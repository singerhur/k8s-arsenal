"""攻击剧本模板

预置的攻击链模板，覆盖从低权限 SA 到集群控制、云平台跨账户等场景。
"""

from k8s_arsenal.models import AttackVector, AttackPath, AttackPhase, RiskLevel


# 剧本 A: 低权限 SA → 集群控制
PLAYBOOK_A_LOW_SA_TO_CLUSTER_ADMIN = AttackPath(
    id="PB-A",
    name="低权限 SA → 全集群控制",
    description=(
        "起始条件：仅有一个低权限 ServiceAccount Token。"
        "通过信息收集、权限提升、横向移动逐步获取 cluster-admin。"
    ),
    difficulty=RiskLevel.HIGH,
    estimated_time="2-4 小时",
    vectors=[
        AttackVector(
            id="PB-A-1", name="环境侦查",
            phase=AttackPhase.DISCOVERY, risk=RiskLevel.LOW,
            description="枚举可访问的 API 资源、已挂载卷、环境变量",
        ),
        AttackVector(
            id="PB-A-2", name="利用 pods/exec 跳板",
            phase=AttackPhase.EXECUTION, risk=RiskLevel.MEDIUM,
            description="exec 进入有 hostPath 挂载或高权限 SA 的 Pod",
        ),
        AttackVector(
            id="PB-A-3", name="符号链接攻击窃取凭证",
            phase=AttackPhase.CREDENTIAL_ACCESS, risk=RiskLevel.HIGH,
            description="利用 /var/log hostPath 挂载创建指向 /etc/kubernetes/pki/ca.key 的符号链接",
        ),
        AttackVector(
            id="PB-A-4", name="自签 cluster-admin 证书",
            phase=AttackPhase.PRIVILEGE_ESCALATION, risk=RiskLevel.CRITICAL,
            description="用 CA 私钥签发 CN=system:admin, O=system:masters 证书",
        ),
        AttackVector(
            id="PB-A-5", name="持久化后门部署",
            phase=AttackPhase.PERSISTENCE, risk=RiskLevel.HIGH,
            description="部署 MutatingWebhook + 超长有效期 Token",
        ),
    ],
)


# 剧本 B: DNS 劫持 → 全集群供应链污染
PLAYBOOK_B_DNS_TO_SUPPLY_CHAIN = AttackPath(
    id="PB-B",
    name="DNS 劫持 → 全集群供应链污染",
    description=(
        "起始条件：已有修改 CoreDNS ConfigMap 的权限。"
        "通过 DNS 劫持将镜像拉取重定向，实现全集群供应链投毒。"
    ),
    difficulty=RiskLevel.CRITICAL,
    estimated_time="30-60 分钟",
    vectors=[
        AttackVector(
            id="PB-B-1", name="修改 CoreDNS ConfigMap",
            phase=AttackPhase.INITIAL_ACCESS, risk=RiskLevel.CRITICAL,
            description="插入 rewrite 规则将镜像仓库域名解析到攻击者 IP",
        ),
        AttackVector(
            id="PB-B-2", name="部署镜像代理仓库",
            phase=AttackPhase.EXECUTION, risk=RiskLevel.HIGH,
            description="搭建真实镜像仓库，对部分镜像进行投毒后再转发正常请求",
        ),
        AttackVector(
            id="PB-B-3", name="等待 Pod 重启/滚动更新",
            phase=AttackPhase.PERSISTENCE, risk=RiskLevel.HIGH,
            description="imagePullPolicy: Always 的 Pod 会在重启时自动拉取投毒镜像",
        ),
        AttackVector(
            id="PB-B-4", name="横向移动至节点",
            phase=AttackPhase.LATERAL_MOVEMENT, risk=RiskLevel.CRITICAL,
            description="从受感染 Pod 通过特权容器逃逸至节点",
        ),
        AttackVector(
            id="PB-B-5", name="抹除 DNS 劫持痕迹",
            phase=AttackPhase.DEFENSE_EVASION, risk=RiskLevel.MEDIUM,
            description="恢复 CoreDNS ConfigMap 原始配置，镜像后门已持久化",
        ),
    ],
)


# 剧本 C: 跨集群云平台扩散
PLAYBOOK_C_CROSS_CLUSTER_CLOUD = AttackPath(
    id="PB-C",
    name="跨集群云平台扩散",
    description=(
        "起始条件：EKS Pod 挂载了 IRSA 角色。"
        "通过 IRSA 获取 AWS 凭证，发现并控制同一 AWS 账户下的其他 EKS 集群。"
    ),
    difficulty=RiskLevel.HIGH,
    estimated_time="3-6 小时",
    vectors=[
        AttackVector(
            id="PB-C-1", name="IRSA Token → AWS STS 凭证",
            phase=AttackPhase.CREDENTIAL_ACCESS, risk=RiskLevel.HIGH,
            description="通过 AssumeRoleWithWebIdentity 获取 AWS 临时凭证",
        ),
        AttackVector(
            id="PB-C-2", name="ec2:DescribeInstances 枚举节点",
            phase=AttackPhase.DISCOVERY, risk=RiskLevel.MEDIUM,
            description="枚举所有 EC2 实例，识别 Worker Node",
        ),
        AttackVector(
            id="PB-C-3", name="UserData Bootstrap 脚本窃取",
            phase=AttackPhase.CREDENTIAL_ACCESS, risk=RiskLevel.CRITICAL,
            description="读取节点的 UserData，提取集群 bootstrap 凭证（CA/API URL/kubelet 证书）",
        ),
        AttackVector(
            id="PB-C-4", name="多集群 kubeconfig 发现",
            phase=AttackPhase.DISCOVERY, risk=RiskLevel.HIGH,
            description="在节点上搜索 /etc/kubernetes/、~/.kube/config 等路径",
        ),
        AttackVector(
            id="PB-C-5", name="跨集群后门部署",
            phase=AttackPhase.PERSISTENCE, risk=RiskLevel.CRITICAL,
            description="用获取的 cluster-admin kubeconfig 连接其他集群并部署后门",
        ),
    ],
)


# 剧本 D: Kubelet 证书 → 全节点控制
PLAYBOOK_D_KUBELET_TO_NODES = AttackPath(
    id="PB-D",
    name="Kubelet 证书 → 全节点控制",
    description=(
        "起始条件：已逃逸到单节点。"
        "利用节点上的 Kubelet 客户端证书和 nodes/proxy 接口控制所有节点。"
    ),
    difficulty=RiskLevel.CRITICAL,
    estimated_time="1-2 小时",
    vectors=[
        AttackVector(
            id="PB-D-1", name="读取 Kubelet 客户端证书",
            phase=AttackPhase.CREDENTIAL_ACCESS, risk=RiskLevel.CRITICAL,
            description="/var/lib/kubelet/pki/kubelet-client-current.pem",
        ),
        AttackVector(
            id="PB-D-2", name="通过 nodes/proxy 访问 API",
            phase=AttackPhase.LATERAL_MOVEMENT, risk=RiskLevel.CRITICAL,
            description="使用 Kubelet 证书做客户端证书认证访问 nodes/proxy",
        ),
        AttackVector(
            id="PB-D-3", name="在所有节点执行命令",
            phase=AttackPhase.EXECUTION, risk=RiskLevel.CRITICAL,
            description="遍历所有节点，通过 /run 接口远程执行命令",
        ),
        AttackVector(
            id="PB-D-4", name="收集 kube-proxy Token",
            phase=AttackPhase.CREDENTIAL_ACCESS, risk=RiskLevel.CRITICAL,
            description="读取宿主机上 kube-proxy Pod 的 SA Token（通常 cluster-admin）",
        ),
        AttackVector(
            id="PB-D-5", name="创建 Shadow Admin 绑定",
            phase=AttackPhase.PERSISTENCE, risk=RiskLevel.CRITICAL,
            description="用 kube-proxy 的 Token 创建新的 cluster-admin ClusterRoleBinding",
        ),
    ],
)


# 剧本 E: GitOps 供应链污染
PLAYBOOK_E_GITOPS_POISON = AttackPath(
    id="PB-E",
    name="GitOps 供应链污染链",
    description=(
        "起始条件：已有 ArgoCD/Flux 的 Git 仓库写入权限。"
        "通过 GitOps 自动同步机制实现全集群静默后门注入。"
    ),
    difficulty=RiskLevel.HIGH,
    estimated_time="1-3 小时",
    vectors=[
        AttackVector(
            id="PB-E-1", name="修改 Git 仓库中的 Kustomize/Helm",
            phase=AttackPhase.INITIAL_ACCESS, risk=RiskLevel.CRITICAL,
            description="在 base/ 或 overlays/ 中静默注入 Sidecar 容器定义",
        ),
        AttackVector(
            id="PB-E-2", name="GitOps 自动 Sync",
            phase=AttackPhase.EXECUTION, risk=RiskLevel.HIGH,
            description="ArgoCD 3分钟 / Flux 1分钟 自动检测变更",
        ),
        AttackVector(
            id="PB-E-3", name="Sidecar 横向扩散",
            phase=AttackPhase.LATERAL_MOVEMENT, risk=RiskLevel.HIGH,
            description="Sidecar 容器的后门模块扫描并渗透相邻服务",
        ),
        AttackVector(
            id="PB-E-4", name="劫持 ArgoCD SA",
            phase=AttackPhase.PRIVILEGE_ESCALATION, risk=RiskLevel.CRITICAL,
            description="从受感染 Pod 窃取 ArgoCD SA Token（通常 cluster-admin）",
        ),
        AttackVector(
            id="PB-E-5", name="扩散至其他 GitOps 仓库",
            phase=AttackPhase.PERSISTENCE, risk=RiskLevel.CRITICAL,
            description="用 ArgoCD SA 修改其他 Application → 扩散到其他命名空间/集群",
        ),
    ],
)


# 剧本 F: 影子管理员（寄生成合法身份）
PLAYBOOK_F_SHADOW_ADMIN = AttackPath(
    id="PB-F",
    name="影子管理员 - 劫持合法身份",
    description=(
        "不创建新身份，劫持现有合法管理员的凭证和流量。"
        "所有操作混入正常运维行为，审计日志完全合法。"
    ),
    difficulty=RiskLevel.HIGH,
    estimated_time="持久性渗透（数天到数周）",
    vectors=[
        AttackVector(
            id="PB-F-1", name="DNS/IP 劫持 API Server",
            phase=AttackPhase.INITIAL_ACCESS, risk=RiskLevel.CRITICAL,
            description="将管理员的 API 请求导向攻击者代理",
        ),
        AttackVector(
            id="PB-F-2", name="记录管理员凭证",
            phase=AttackPhase.CREDENTIAL_ACCESS, risk=RiskLevel.CRITICAL,
            description="代理记录客户端证书和 Token",
        ),
        AttackVector(
            id="PB-F-3", name="寄生 CI/CD SA 流量",
            phase=AttackPhase.DEFENSE_EVASION, risk=RiskLevel.HIGH,
            description="将恶意操作混入 CI/CD 系统正常行为中",
        ),
        AttackVector(
            id="PB-F-4", name="利用证书长生命周期",
            phase=AttackPhase.PERSISTENCE, risk=RiskLevel.CRITICAL,
            description="优先获取客户端证书（比 Token 更难轮换和吊销）",
        ),
    ],
)


# 所有剧本模板
CHAIN_TEMPLATES: list[AttackPath] = [
    PLAYBOOK_A_LOW_SA_TO_CLUSTER_ADMIN,
    PLAYBOOK_B_DNS_TO_SUPPLY_CHAIN,
    PLAYBOOK_C_CROSS_CLUSTER_CLOUD,
    PLAYBOOK_D_KUBELET_TO_NODES,
    PLAYBOOK_E_GITOPS_POISON,
    PLAYBOOK_F_SHADOW_ADMIN,
]


def get_playbook_by_entry(entry: str) -> list[AttackPath]:
    """按入口条件匹配攻击剧本"""
    entry_map = {
        "low-privilege-sa": [PLAYBOOK_A_LOW_SA_TO_CLUSTER_ADMIN],
        "dns-control": [PLAYBOOK_B_DNS_TO_SUPPLY_CHAIN],
        "eks-irsa": [PLAYBOOK_C_CROSS_CLUSTER_CLOUD],
        "node-escape": [PLAYBOOK_D_KUBELET_TO_NODES],
        "gitops": [PLAYBOOK_E_GITOPS_POISON],
        "shadow": [PLAYBOOK_F_SHADOW_ADMIN],
    }

    if entry in entry_map:
        return entry_map[entry]

    # 模糊匹配
    results = []
    for name, paths in entry_map.items():
        if entry.lower() in name.lower() or name.lower() in entry.lower():
            results.extend(paths)
    if results:
        return results

    return CHAIN_TEMPLATES
