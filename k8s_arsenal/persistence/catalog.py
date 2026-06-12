"""持久化技术编目

收录 K8s 集群持久化后门技术，涵盖 Token、Webhook、CronJob、内核级。
"""

from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel


PERSISTENCE_VECTORS: list[AttackVector] = [
    AttackVector(
        id="PER-001",
        name="TokenRequest 超长有效期 Token",
        phase=AttackPhase.PERSISTENCE,
        risk=RiskLevel.HIGH,
        description=(
            "使用 TokenRequest API 生成有效期长达 100 年的 ServiceAccount Token。"
            "绕过 Secret Controller，不创建可被发现的 Secret 对象，"
            "Token 只存在于请求者的内存中。"
        ),
        prerequisites=["已有 API Server 访问权限", "可创建 TokenRequest"],
        steps=[
            "创建 TokenRequest 对象，设置 expirationSeconds=3153600000 (100年)",
            "提取返回的 token 值",
            "将 token 存储到安全位置",
            "使用该 token 进行后续 API 访问",
        ],
        detection_hints=[
            "审计日志中的 TokenRequest 创建记录",
            "异常长的 expirationSeconds 值",
            "非系统组件的 TokenRequest 调用",
        ],
        references=["K8s TokenRequest API", "KEP-1205"],
    ),
    AttackVector(
        id="PER-002",
        name="MutatingAdmissionWebhook 后门注入",
        phase=AttackPhase.PERSISTENCE,
        risk=RiskLevel.CRITICAL,
        description=(
            "创建 MutatingWebhookConfiguration，将 Webhook 指向攻击者控制的 HTTPS 服务。"
            "所有新创建的 Pod 都会经过此 Webhook，可注入恶意 Sidecar、挂载敏感卷、"
            "替换镜像、修改环境变量。完全被动触发，极难被发现。"
        ),
        prerequisites=["cluster-admin 权限", "可部署外部或集群内 Webhook 服务"],
        steps=[
            "部署 Webhook HTTPS 服务（可用自签名证书）",
            "创建 MutatingWebhookConfiguration",
            "配置 namespaceSelector 限定目标命名空间以减少暴露",
            "在新 Pod 中注入恶意 Sidecar 或挂载 hostPath",
            "Webhook 被动等待新 Pod 创建",
        ],
        detection_hints=[
            "新增的 MutatingWebhookConfiguration 对象",
            "Webhook 服务指向非标准地址",
            "Pod 中出现的异常 Sidecar 容器",
        ],
        references=["K8s Dynamic Admission Control"],
    ),
    AttackVector(
        id="PER-003",
        name="寄生式 DaemonSet 后门",
        phase=AttackPhase.PERSISTENCE,
        risk=RiskLevel.HIGH,
        description=(
            "部署 DaemonSet，用 nodeSelector 精准落在控制平面节点或特定 worker 节点上。"
            "使用看似无害的镜像（如 busybox sleep infinity），混在系统 Pod 中间。"
            "需要时通过 kubectl exec 激活。"
        ),
        prerequisites=["可创建 DaemonSet 的权限"],
        steps=[
            "创建 DaemonSet YAML，指定 nodeSelector: node-role.kubernetes.io/control-plane",
            "使用 image: busybox:latest, command: ['sleep', 'infinity']",
            "等待 Pod 调度到目标节点",
            "通过 kubectl exec 在需要时激活后门功能",
        ],
        detection_hints=[
            "异常 DaemonSet 对象",
            "控制平面节点上的非系统 Pod",
            "sleep infinity 进程",
        ],
    ),
    AttackVector(
        id="PER-004",
        name="伪装 CronJob 心跳后门",
        phase=AttackPhase.PERSISTENCE,
        risk=RiskLevel.MEDIUM,
        description=(
            "创建高频 CronJob（如每分钟），表面执行健康检查，实际作为命令下发通道。"
            "配置 ttlSecondsAfterFinished: 0 使得 Job Pod 完成后立即删除，"
            "kubectl get pods 看不到历史记录。"
        ),
        prerequisites=["可创建 CronJob 的权限"],
        steps=[
            "创建 CronJob, schedule: '*/1 * * * *'",
            "command 设为 fetch + execute 模式",
            "设置 ttlSecondsAfterFinished: 0",
            "定期轮询 C2 或配置文件获取命令",
        ],
        detection_hints=[
            "异常高频 CronJob",
            "CronJob 的网络外联行为",
            "Job Pod 生命周期异常短",
        ],
    ),
    AttackVector(
        id="PER-005",
        name="ValidatingWebhook 反删除保护",
        phase=AttackPhase.PERSISTENCE,
        risk=RiskLevel.CRITICAL,
        description=(
            "创建 ValidatingWebhookConfiguration 拦截所有 DELETE 操作。"
            "检查目标对象是否有攻击者的特定 label，拒绝删除操作。"
            "确保后门资源永远不会被运维清理。"
        ),
        prerequisites=["cluster-admin 或 webhook 创建权限"],
        steps=[
            "部署 ValidatingWebhook 服务",
            "在所有后门资源上打上特定 label (如 'persist: true')",
            "Webhook 拦截 DELETE 操作，检查 label",
            "若有 label 则返回拒绝",
        ],
        detection_hints=[
            "异常的 ValidatingWebhookConfiguration",
            "特定 label 的自动保护",
        ],
    ),
    AttackVector(
        id="PER-006",
        name="Static Pod Manifest 持久化",
        phase=AttackPhase.PERSISTENCE,
        risk=RiskLevel.CRITICAL,
        description=(
            "逃逸至宿主机后，修改 /etc/kubernetes/manifests/ 下的 Static Pod 定义。"
            "Kubelet 自动检测变更并重启，每次重启都加载恶意 Pod。"
            "Static Pod 不受 API Server 删除影响。"
        ),
        prerequisites=["宿主机 root 权限", "逃逸成功"],
        steps=[
            "逃逸至宿主机",
            "定位 /etc/kubernetes/manifests/ 路径",
            "创建或修改 manifest YAML 插入后门容器",
            "等待 kubelet 自动检测并重启 Pod",
        ],
        detection_hints=[
            "Static Pod manifest 文件变更",
            "控制平面组件行为异常",
        ],
    ),
    AttackVector(
        id="PER-007",
        name="kube-system 命名空间休眠 Pod",
        phase=AttackPhase.PERSISTENCE,
        risk=RiskLevel.MEDIUM,
        description=(
            "在 kube-system 命名空间创建休眠 Pod（sleep infinity），"
            "混在 coredns、kube-proxy 等系统 Pod 中间。"
            "运维人员查看 Pod 列表时极易忽略。"
        ),
        prerequisites=["kube-system 命名空间创建 Pod 权限"],
        steps=[
            "创建 Pod 在 kube-system 命名空间",
            "设置 pod-name 模拟系统 Pod 命名风格",
            "image: busybox, command: ['sleep', 'infinity']",
            "需要时 exec 进入激活",
        ],
        detection_hints=[
            "kube-system 中的非系统 Pod",
            "busybox 镜像异常使用",
        ],
    ),
    AttackVector(
        id="PER-008",
        name="Shadow API Server (kubelet 代理)",
        phase=AttackPhase.PERSISTENCE,
        risk=RiskLevel.CRITICAL,
        description=(
            "利用 kubelet 的 nodes/proxy 接口作为 Shadow API Server。"
            "即使主 API Server 不可达，仍可通过 kubelet 代理 API 请求。"
            "配合从节点窃取的客户端证书完全控制集群。"
        ),
        prerequisites=["Kubelet 客户端证书", "节点 IP:10250 可达"],
        steps=[
            "获取 kubelet-client-current.pem",
            "通过 nodes/proxy 接口发送 API 请求",
            "绕过主 API Server 的审计和准入控制",
        ],
        detection_hints=[
            "nodes/proxy 接口异常调用",
            "绕过 API Server 的审计空窗期",
        ],
    ),
]


def get_persistence_by_risk(min_risk: RiskLevel = RiskLevel.MEDIUM) -> list[AttackVector]:
    """按最低风险等级筛选持久化技术"""
    risk_order = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 3,
        RiskLevel.INFO: 4,
    }
    return [v for v in PERSISTENCE_VECTORS
            if risk_order[v.risk] <= risk_order[min_risk]]
