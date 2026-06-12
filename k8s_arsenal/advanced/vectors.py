"""扩展攻击向量编目

收录最新 CVE 和高级技术，独立于核心编目以便持续更新。
"""

from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel


ADVANCED_VECTORS: list[AttackVector] = [
    # === runc/Docker CVEs ===
    AttackVector(
        id="ADV-001",
        name="runc CVE-2024-21626 — WORKDIR 容器逃逸",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.CRITICAL,
        cve="CVE-2024-21626",
        description=(
            "runc 1.1.11 之前版本，WORKDIR 指令未正确处理文件描述符泄漏。"
            "在构建镜像时，Dockerfile 中的 WORKDIR 可在 runc exec 时泄漏宿主机文件描述符。"
            "攻击者在容器内可访问宿主机文件系统，实现容器逃逸。"
        ),
        prerequisites=["目标使用 runc < 1.1.11", "容器运行环境"],
        steps=[
            "利用 WORKDIR 泄漏的文件描述符访问 /proc/self/fd/<n>",
            "该 fd 可能指向宿主机文件系统路径",
            "通过该 fd 读写宿主机文件",
            "实现容器逃逸",
        ],
        detection_hints=[
            "容器进程访问非预期的 /proc/self/fd",
            "runc 版本检查",
        ],
        references=["GHSA-xr7r-f8xq-vfvv", "CVE-2024-21626"],
    ),
    AttackVector(
        id="ADV-002",
        name="Docker AuthZ Plugin 绕过 — CVE-2024-41110",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.CRITICAL,
        cve="CVE-2024-41110",
        description=(
            "Docker Engine 18.06+ 中 AuthZ 插件可被绕过。"
            "使用 Content-Length: 0 的特殊 API 请求可跳过授权检查。"
            "攻击者可在容器内执行特权操作（如挂载宿主机路径）。"
        ),
        prerequisites=["Docker AuthZ 插件启用", "API 访问"],
        steps=[
            "构造 Content-Length: 0 的 API 请求",
            "绕过 AuthZ 插件的权限检查",
            "执行被禁止的 Docker API 操作",
            "挂载宿主机路径或创建特权容器",
        ],
        detection_hints=[
            "Content-Length: 0 的 Docker API 请求",
            "AuthZ 日志中的异常绕过",
        ],
        references=["CVE-2024-41110", "Moby Security Advisory"],
    ),
    # === eBPF/Tetragon/BCC 绕过 ===
    AttackVector(
        id="ADV-003",
        name="eBPF Map Overflow 导致程序卸载",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.HIGH,
        description=(
            "向 eBPF map 中写入海量数据导致内存压力。"
            "内核 LRU 驱逐机制可能触发程序卸载。"
            "Tetragon/Falco 监控窗口出现短暂空窗期。"
        ),
        prerequisites=["可访问 eBPF map", "eBPF 程序运行中"],
        steps=[
            "识别安全工具的 eBPF map ID",
            "大量写入无效数据(map_update 循环)",
            "等待 LRU 驱逐或 map 满溢",
            "在监控空窗期执行恶意操作",
        ],
        detection_hints=[
            "eBPF map 大小异常增长",
            "监控程序的 map 写入事件",
        ],
    ),
    AttackVector(
        id="ADV-004",
        name="Tetragon Namespaced Policy 绕过",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.MEDIUM,
        description=(
            "Tetragon TracingPolicy 支持 namespaceSelector。"
            "在不受监控的命名空间（如 kube-public）创建 Pod，"
            "通过 hostNetwork 与目标 Pod 共享网络，实现侧信道攻击。"
        ),
        prerequisites=["可创建 Pod", "Tetragon namespaceSelector 有盲区"],
        steps=[
            "kubectl get tracingpolicies -oyaml  分析监控范围",
            "在监控盲区命名空间创建 Pod",
            "使用 hostNetwork 模式与目标 Pod 共享网络",
            "实施侧信道攻击或流量嗅探",
        ],
        detection_hints=[
            "监控盲区的异常 Pod 创建",
            "hostNetwork Pod 在非系统命名空间",
        ],
    ),
    # === OPA/Gatekeeper/Kyverno 绕过 ===
    AttackVector(
        id="ADV-005",
        name="OPA Gatekeeper 子资源绕过",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.HIGH,
        description=(
            "Gatekeeper 常仅检查 CREATE/UPDATE 操作。"
            "通过 pods/exec, pods/ephemeralcontainers 等子资源端点，"
            "在不触发 ConstraintTemplate 检查的情况下修改运行时配置。"
            "ephemeralContainers 可直接注入容器而不触发 Rego 规则。"
        ),
        prerequisites=["pods/ephemeralcontainers 权限", "Gatekeeper/OPA 环境"],
        steps=[
            "分析 Gatekeeper Constraint 覆盖范围",
            "使用 kubectl debug 或 ephemeralContainers API",
            "注入恶意 debug 容器到目标 Pod",
            "绕过 deployment/pod 级别的 admission 检查",
        ],
        detection_hints=[
            "ephemeralContainers API 调用",
            "debug 容器的异常镜像",
        ],
        references=["K8s Ephemeral Containers", "OPA Gatekeeper"],
    ),
    AttackVector(
        id="ADV-006",
        name="Kyverno Background Scan 延迟利用",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.MEDIUM,
        description=(
            "Kyverno 有 generate/validate/mutate 三种规则。"
            "Validate 规则在 admission 时同步执行，但 Background Scan 每 1 小时才检查一次已有资源。"
            "利用 validationFailureAction: Audit 的宽松模式创建违规资源。"
        ),
        prerequisites=["Kyverno 环境", "validationFailureAction: Audit"],
        steps=[
            "kubectl get policies -A  识别 Audit 模式的规则",
            "创建违反 Audit 模式规则的资源",
            "在 Background Scan 间隔内（最长 1 小时）操作",
            "在后续扫描前消除或利用违规资源",
        ],
        detection_hints=[
            "Background Scan 发现的违规资源",
            "Audit 模式下大量违规创建",
        ],
        references=["Kyverno Background Scan"],
    ),
    # === Seccomp/AppArmor 绕过 ===
    AttackVector(
        id="ADV-007",
        name="Seccomp Profile 降级攻击",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.HIGH,
        description=(
            "修改 Pod SecurityContext 的 seccompProfile.type 从 RuntimeDefault 改为 Unconfined。"
            "需要 Pod 重建，但 admission webhook 对 seccomp 字段的校验经常不完整。"
            "New Pod 释放所有系统调用限制。"
        ),
        prerequisites=["可修改 Pod/Deployment spec", "Admission 不严格校验 seccomp"],
        steps=[
            "kubectl edit deployment target  或 patch",
            "修改 seccompProfile.type 为 Unconfined",
            "等待 Pod 重建",
            "在新 Pod 中使用受限系统调用（如 ptrace, mount）",
        ],
        detection_hints=[
            "Pod seccompProfile 从 RuntimeDefault 变为 Unconfined",
            "非标准的本地 Seccomp Profile 路径",
        ],
    ),
    AttackVector(
        id="ADV-008",
        name="AppArmor Profile 删除攻击",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.MEDIUM,
        description=(
            "在节点上删除已加载的 AppArmor Profile（aa-remove），"
            "或修改 Pod annotation 将 profile 设为 unconfined。"
            "新容器不受 AppArmor 限制。"
        ),
        prerequisites=["节点 root 权限", "AppArmor 启用"],
        steps=[
            "逃逸至宿主机",
            "aa-status  枚举已加载的 Profile",
            "apparmor_parser -R /etc/apparmor.d/<profile>",
            "或修改 Pod annotation container.apparmor.security.beta.kubernetes.io/<c>=unconfined",
        ],
        detection_hints=[
            "AppArmor profile 卸载事件",
            "Pod annotation 变更",
        ],
    ),
    # === ImagePullPolicy 利用 ===
    AttackVector(
        id="ADV-009",
        name="ImagePullPolicy 时间窗劫持",
        phase=AttackPhase.PERSISTENCE,
        risk=RiskLevel.HIGH,
        description=(
            "利用 IfNotPresent 拉取策略：节点已有镜像时不再重新拉取。"
            "攻击者先推送正常镜像填满节点缓存，后续同 tag 镜像不再向 registry 验证 digest。"
            "配合镜像缓存篡改 (ADV-010) 实现全节点感染。"
        ),
        prerequisites=["节点镜像缓存可写", "目标使用 IfNotPresent"],
        steps=[
            "确认目标 Pod 的 imagePullPolicy: IfNotPresent",
            "修改节点缓存的镜像层",
            "Pod 重启时使用被污染的缓存镜像",
            "registry Digest 校验不会触发",
        ],
        detection_hints=[
            "节点镜像层不匹配 registry Digest",
            "Pod 行为与预期镜像不一致",
        ],
    ),
    AttackVector(
        id="ADV-010",
        name="Cosign/Sigstore 签名绕过 — 策略降级",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.HIGH,
        description=(
            "Sigstore Policy Controller 支持 warn/block 两种模式。"
            "当策略模式为 warn 时，触发 ClusterImagePolicy 违反不会拒绝部署。"
            "admission 仅记录一条 warning 事件，镜像正常被部署。"
        ),
        prerequisites=["Sigstore Policy Controller", "策略为 warn 模式"],
        steps=[
            "kubectl get clusterimagepolicy 检查策略模式",
            "识别 warn 模式的策略",
            "部署未签名或签名不匹配的镜像",
            "镜像被接受，仅记录 warning",
        ],
        detection_hints=[
            "ClusterImagePolicy violation warnings",
            "未签名镜像的部署事件",
        ],
        references=["Sigstore Policy Controller"],
    ),
    # === K8s 版本特定 CVE ===
    AttackVector(
        id="ADV-011",
        name="K8s CVE-2023-5528 — HostPath 卷递归权限提升",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.CRITICAL,
        cve="CVE-2023-5528",
        description=(
            "Kubernetes 1.27 之前，hostPath 卷在 Pod 创建时以递归方式修改宿主机路径权限。"
            "创建使用 hostPath 的 Pod 可间接修改关键系统目录（如 /etc/kubernetes/pki）的所有权，"
            "使其他 Pod 获得非预期的访问权限。"
        ),
        prerequisites=["可创建使用 hostPath 的 Pod", "K8s < 1.27.8 / < 1.28.4"],
        steps=[
            "创建挂载 /etc/kubernetes/pki 的 hostPath Pod",
            "利用递归权限变更影响同级目录",
            "后续 Pod 获得对关键证书的非预期访问",
        ],
        detection_hints=[
            "hostPath 卷权限变更",
            "关键目录所有权变更",
        ],
        references=["CVE-2023-5528", "K8s Security Advisory"],
    ),
    AttackVector(
        id="ADV-012",
        name="K8s CVE-2023-3676 — Windows 节点命令注入",
        phase=AttackPhase.EXECUTION,
        risk=RiskLevel.HIGH,
        cve="CVE-2023-3676",
        description=(
            "Windows 节点上，创建 subPath 的恶意卷名，触发 kubelet 命令注入。"
            "在 subPath 中使用 && 等 shell 元字符可让 kubelet 执行任意命令。"
        ),
        prerequisites=["Windows worker node", "可创建使用 subPath 的 Pod"],
        steps=[
            "创建包含注入命令的 subPath Pod（如 ..\..\bin\cmd.exe /c ...）",
            "kubelet 处理 subPath 时执行注入命令",
            "在 kubelet 上下文（SYSTEM 权限）执行代码",
        ],
        detection_hints=[
            "异常 Windows subPath 字符串",
            "kubelet 进程的子进程异常",
        ],
        references=["CVE-2023-3676"],
    ),
    # === Service Mesh 高级利用 ===
    AttackVector(
        id="ADV-013",
        name="Istio AuthorizationPolicy 伪造 Claim 绕过",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.CRITICAL,
        description=(
            "Istio AuthorizationPolicy 基于 JWT Claim 做准入时，"
            "如果 Istio 未配置 jwksUri 或使用宽松验证，"
            "攻击者可自签 JWT 携带伪造的 admin claim 通过 Istio sidecar 检查。"
        ),
        prerequisites=["Istio AuthorizationPolicy 使用 JWT", "jwksUri 未配置或可达"],
        steps=[
            "分析 AuthorizationPolicy 的 JWT 规则",
            "如果 outputClaimToHeaders 有高权限 claim",
            "自签 JWT 携带伪造的 claim",
            "通过 Istio sidecar 访问保护服务",
        ],
        detection_hints=[
            "异常 JWT issuer",
            "未注册的 JWT 签名",
        ],
        references=["Istio AuthorizationPolicy JWT"],
    ),
    AttackVector(
        id="ADV-014",
        name="Linkerd ProxyInit 绕过 — 直连目标服务",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.MEDIUM,
        description=(
            "Linkerd 使用 iptables 将流量重定向到 linkerd-proxy。"
            "在 Pod 内将 iptables OUTPUT 链恢复到默认 ACCEPT 前插入规则，"
            "使特定端口/目标的流量绕过 linkerd-proxy 直连，脱离 mTLS 和 AuthorizationPolicy。"
        ),
        prerequisites=["Pod 拥有 NET_ADMIN 能力", "Linkerd mesh"],
        steps=[
            "iptables -t nat -I OUTPUT -p tcp --dport <target> -j ACCEPT",
            "放在 linkerd-proxy REDIRECT 规则之前",
            "Bypass mTLS 加密和策略检查",
            "直接连接目标服务",
        ],
        detection_hints=[
            "linkerd-proxy 流量异常减少",
            "未加密的 Service 间通信",
        ],
    ),
    # === Sidecar 注入与反转 ===
    AttackVector(
        id="ADV-015",
        name="Istio Sidecar Injection 污染",
        phase=AttackPhase.PERSISTENCE,
        risk=RiskLevel.CRITICAL,
        description=(
            "Istio 通过 MutatingWebhook 自动注入 Sidecar。"
            "修改 istiod ConfigMap 的 injection template，"
            "所有新 Sidecar 将携带恶意环境变量、卷挂载或额外容器。"
            "影响面涵盖所有启用自动注入的命名空间。"
        ),
        prerequisites=["可修改 istiod ConfigMap", "Istio 环境"],
        steps=[
            "kubectl edit configmap istio-sidecar-injector -n istio-system",
            "在 injection template 中添加恶意环境变量",
            "或添加 hostPath 卷挂载",
            "所有新创建或重启的 Pod 自动继承恶意配置",
        ],
        detection_hints=[
            "istio-sidecar-injector ConfigMap 变更",
            "Sidecar 容器中的异常 extraneous 环境变量",
        ],
    ),
    AttackVector(
        id="ADV-016",
        name="ContainerD Shim 劫持",
        phase=AttackPhase.PERSISTENCE,
        risk=RiskLevel.CRITICAL,
        description=(
            "containerd 启动容器时调用 containerd-shim，shim 进程在容器 exit 后仍存活。"
            "替换 shim 二进制或修改配置文件 /etc/containerd/config.toml，"
            "可拦截所有容器的创建/销毁生命周期。全局级 Rootkit。"
        ),
        prerequisites=["宿主机 root 权限", "containerd 运行中"],
        steps=[
            "修改 /etc/containerd/config.toml 指向恶意 shim",
            "或替换 /usr/bin/containerd-shim-runc-v2",
            "重启 containerd 或等待 shim 重载",
            "所有新容器创建均经过恶意 shim",
        ],
        detection_hints=[
            "containerd-shim 二进制哈希不匹配",
            "containerd config 变更",
        ],
    ),
    # === Cloud 扩展 ===
    AttackVector(
        id="ADV-017",
        name="IMDSv2 Hop-Limit 绕过",
        phase=AttackPhase.CREDENTIAL_ACCESS,
        risk=RiskLevel.HIGH,
        description=(
            "AWS IMDSv2 通过 TTL 跳数限制防御 SSRF 访问。"
            "默认 hop-limit=2 允许容器通过主机访问 IMDS。"
            "在嵌套容器（Docker-in-Docker）场景中，第二层容器 TTL=3 可能超出限制。"
            "利用主机网络代理或直接设置 TTL=1 绕过限制。"
        ),
        prerequisites=["AWS EC2/EKS", "IMDSv2 hop-limit <= 2"],
        steps=[
            "检测当前 hop-limit (默认2或3)",
            "通过主机网络代理（如iptables REDIRECT）访问 IMDS",
            "代理将 TTL 降低",
            "获取 EC2 Instance Profile 凭证",
        ],
        detection_hints=[
            "IMDS 访问的异常源 IP",
            "IPTables REDIRECT 规则",
        ],
        references=["AWS IMDSv2"],
    ),
    AttackVector(
        id="ADV-018",
        name="GCP KMS 信封加密密钥提取",
        phase=AttackPhase.CREDENTIAL_ACCESS,
        risk=RiskLevel.CRITICAL,
        description=(
            "GKE 使用 GCP KMS 做应用层信封加密（EncryptionConfiguration）。"
            "获取 KMS 加密的 DEK 和 GCP SA Token 后，可调用 KMS API 解密的 DEK。"
            "用 DEK 解密 etcd 中所有加密的 Secret。"
        ),
        prerequisites=["GKE Application-layer Secret Encryption", "GCP SA Token"],
        steps=[
            "从 EncryptionConfiguration 获取 KMS key URI",
            "从 etcd 提取加密的 Secret（base64 的密文）",
            "使用 GCP SA Token 调用 KMS Decrypt API",
            "获取明文 Secret",
        ],
        detection_hints=[
            "KMS Decrypt API 异常调用",
            "加密 Secret 的大规模解密",
        ],
        references=["GKE Secrets Encryption at Rest"],
    ),
]


def merge_with_core():
    """将高级向量合并到核心编目中

    Returns:
        包含核心+高级向量的完整列表
    """
    from k8s_arsenal.escape.vectors import ESCAPE_VECTORS
    from k8s_arsenal.persistence.catalog import PERSISTENCE_VECTORS
    from k8s_arsenal.lateral.movement import LATERAL_VECTORS
    from k8s_arsenal.network.attacks import NETWORK_VECTORS
    from k8s_arsenal.supply_chain.catalog import SUPPLY_CHAIN_VECTORS
    from k8s_arsenal.evasion.catalog import EVASION_VECTORS

    return (
        list(ESCAPE_VECTORS)
        + list(PERSISTENCE_VECTORS)
        + list(LATERAL_VECTORS)
        + list(NETWORK_VECTORS)
        + list(SUPPLY_CHAIN_VECTORS)
        + list(EVASION_VECTORS)
        + list(ADVANCED_VECTORS)
    )
