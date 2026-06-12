"""权限提升技术编目

收录 K8s 集群权限提升技术，涵盖 RBAC 滥用、特权容器创建、节点逃逸。
"""

from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel


PRIVILEGE_ESCALATION_VECTORS: list[AttackVector] = [
    AttackVector(
        id="PRI-001",
        name="创建特权 Pod 提升权限",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.CRITICAL,
        description=(
            "利用 create pods 权限创建一个 privileged: true 的 Pod。"
            "特权 Pod 拥有宿主机所有 Linux Capabilities，可访问所有设备。"
            "通过 hostPID/hostNetwork/hostIPC 可进一步控制宿主机进程。"
            "挂载宿主机根目录实现完全逃逸。"
        ),
        prerequisites=["create pods 权限"],
        steps=[
            "创建 privileged: true 的 Pod (securityContext.privileged)",
            "挂载 hostPath: / -> /host",
            "exec 进入 pod: nsenter --mount=/host/proc/1/ns/mnt -- bash",
            "获得宿主机 root shell",
        ],
        detection_hints=[
            "新创建的 privileged Pod",
            "挂载 hostPath / 或其他敏感路径",
            "Pod 运行在非系统命名空间",
        ],
        references=["K8s Pod Security Standards"],
    ),
    AttackVector(
        id="PRI-002",
        name="ClusterRoleBinding 提权到 Cluster-Admin",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.CRITICAL,
        description=(
            "利用 create clusterrolebindings 权限，将自己绑到 cluster-admin。"
            "一条命令即可获得集群完全控制权。"
            "可同时创建多个 ClusterRoleBinding 分散注意。"
        ),
        prerequisites=["create clusterrolebindings 权限"],
        steps=[
            "kubectl create clusterrolebinding <name> --clusterrole=cluster-admin --serviceaccount=<ns>:<sa>",
            "验证权限: kubectl auth can-i '*' '*' --all-namespaces",
            "创建 secondary ClusterRoleBinding 做冗余后门",
        ],
        detection_hints=[
            "新 ClusterRoleBinding 关联 cluster-admin",
            "非管理员创建的 ClusterRoleBinding",
        ],
        references=["K8s RBAC"],
    ),
    AttackVector(
        id="PRI-003",
        name="hostPath 挂载逃逸提权",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.CRITICAL,
        description=(
            "利用 create pods 权限创建挂载敏感 hostPath 的 Pod。"
            "挂载主机根目录 (/)、/var/log、/proc 等。"
            "通过 chroot 或 nsenter 切换至宿主机命名空间。"
            "无需 privileged 即可利用特定挂载路径实现提权。"
        ),
        prerequisites=["create pods 权限", "挂载 hostPath 未被 admission webhook 拦截"],
        steps=[
            "创建 Pod 挂载 hostPath / -> /host",
            "exec 进入容器后 chroot /host",
            "或挂载 /proc: nsenter --mount=/host/proc/1/ns/mnt -- bash",
            "在宿主机读写任意文件",
        ],
        detection_hints=[
            "挂载 / 或 /proc 的 hostPath Pod",
            "Pod 中执行 chroot/nsenter",
            "非控制平面组件的 hostPath 挂载",
        ],
    ),
    AttackVector(
        id="PRI-004",
        name="RBAC 动词组合提权",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.HIGH,
        description=(
            "利用多个受限权限组合实现提权。"
            "经典组合: list secrets + create pods（提取 secret -> 注入特权 Pod）。"
            "create tokenreviews + impersonate -> 模拟高权限用户。"
            "update deployments + patch pods -> 修改已有 Deployment 注入后门。"
        ),
        prerequisites=["至少两个看似无害的权限组合"],
        steps=[
            "枚举可用权限: kubectl auth can-i --list",
            "list secrets -> 提取 SA Token",
            "create pods -> 使用提取的 Token 创建特权 Pod",
            "patch deployments -> 在现有 Deployment 中注入恶意 Sidecar",
        ],
        detection_hints=[
            "权限组合使用的非典型模式",
            "短时间内跨资源的权限链式使用",
        ],
    ),
    AttackVector(
        id="PRI-005",
        name="Bootstrap Token 利用",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.CRITICAL,
        description=(
            "Bootstrap Token 用于集群初始化，默认具有创建 ClusterRoleBinding 的权限。"
            "若获取到有效的 Bootstrap Token（格式: 6位字符.16位字符），"
            "可使用 system:bootstrappers 组的默认权限绑定 cluster-admin。"
        ),
        prerequisites=["有效的 Bootstrap Token", "cluster-info configmap 读取权限"],
        steps=[
            "获取 Bootstrap Token: kubectl get secrets -n kube-system | grep bootstrap",
            "或通过 cluster-info configmap 读取 Token",
            "kubectl --token=<bootstrap-token> create clusterrolebinding <name> --clusterrole=cluster-admin --user=<user>",
        ],
        detection_hints=[
            "Bootstrap Token 的非节点来源使用",
            "system:bootstrappers 组的权限变更",
        ],
        references=["K8s Bootstrap Tokens", "KEP-1152"],
    ),
]


def get_privilege_escalation_by_method(method: str) -> list[AttackVector]:
    """按提权方法筛选"""
    method_map = {
        "pod": ["Pod", "privileged", "hostPath"],
        "rbac": ["RBAC", "ClusterRoleBinding"],
        "token": ["Token", "Bootstrap"],
        "chain": ["组合"],
    }
    if method in method_map:
        keywords = method_map[method]
        return [
            v for v in PRIVILEGE_ESCALATION_VECTORS
            if any(kw.lower() in v.description.lower() for kw in keywords)
        ]
    return PRIVILEGE_ESCALATION_VECTORS
