"""影响技术编目

收录 K8s 集群破坏性攻击技术，涵盖数据销毁、资源劫持、服务中断。
"""

from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel


IMPACT_VECTORS: list[AttackVector] = [
    AttackVector(
        id="IMP-001",
        name="大规模 Pod 删除与工作负载破坏",
        phase=AttackPhase.IMPACT,
        risk=RiskLevel.CRITICAL,
        description=(
            "通过批量删除 Deployment、StatefulSet、DaemonSet 等资源，"
            "或直接删除 Pod 对象造成大规模服务中断。"
            "配合删除 ReplicaSet 阻止自动恢复，或删除 PVC 造成持久化数据丢失。"
        ),
        prerequisites=["delete pods/deployments 权限"],
        steps=[
            "kubectl delete deployment --all -n <target>",
            "kubectl delete statefulset --all -n <target>",
            "kubectl delete pvc --all -n <target>",
            "删除 ReplicaSet 阻止新 Pod 创建",
        ],
        detection_hints=[
            "短时间内大量 DELETE 操作",
            "未知来源的批量删除操作",
            "跨命名空间的并发删除",
        ],
    ),
    AttackVector(
        id="IMP-002",
        name="数据加密勒索（Ransomware）",
        phase=AttackPhase.IMPACT,
        risk=RiskLevel.CRITICAL,
        description=(
            "通过 exec 进入 Pod，对 PVC 挂载的持久化数据进行加密。"
            "加密后删除原始数据并留下赎金说明。"
            "配合 Secret 删除和 etcd 破坏使恢复更加困难。"
        ),
        prerequisites=["exec 权限", "目标 Pod 挂载 PVC"],
        steps=[
            "kubectl exec -it <target-pod> -- /bin/sh",
            "遍历 /data 或挂载卷路径",
            "openssl enc -aes-256-cbc 加密所有数据文件",
            "删除原始文件，留下恢复说明",
            "删除相关 Secret 增加恢复难度",
        ],
        detection_hints=[
            "异常的 exec 操作",
            "PVC 数据大规模变更",
            "非业务时间的大量 exec",
        ],
    ),
    AttackVector(
        id="IMP-003",
        name="资源劫持（Cryptojacking）",
        phase=AttackPhase.IMPACT,
        risk=RiskLevel.HIGH,
        description=(
            "在集群中部署加密货币挖矿工作负载。"
            "利用 HPA 自动扩展挖矿 Pod 最大化资源占用。"
            "使用未被使用的 Namespace 或伪装成系统组件隐藏。"
        ),
        prerequisites=["create deployments 权限", "有可用资源配额"],
        steps=[
            "部署挖矿 Deployment，使用 cronjob 在低峰时段运行",
            "配置 HPA 自动扩展，使用所有可用资源",
            "设置 request/limit 低于节点资源避免被驱逐",
            "伪装容器名为系统组件（如 kube-dns、metrics）",
        ],
        detection_hints=[
            "异常高的 CPU 使用率",
            "非预期的新 Deployment",
            "连接已知矿池 IP 地址",
        ],
    ),
    AttackVector(
        id="IMP-004",
        name="拒绝服务 - 资源耗尽",
        phase=AttackPhase.IMPACT,
        risk=RiskLevel.HIGH,
        description=(
            "通过创建大量资源耗尽节点内存、CPU 和磁盘。"
            "利用 DaemonSet 在每个节点部署资源消耗 Pod。"
            "配合 HugePages 和 Init Container 先于正常 Pod 抢资源。"
        ),
        prerequisites=["create daemonsets/deployments 权限"],
        steps=[
            "部署 DaemonSet 抢占所有节点资源",
            "每个 Pod 配置内存 request 接近节点容量",
            "使用 Init Container 长时间占用资源",
            "创建大量 PVC 耗尽存储配额",
        ],
        detection_hints=[
            "资源使用率突增",
            "大量 Pending Pod",
            "节点 NotReady 状态",
        ],
    ),
    AttackVector(
        id="IMP-005",
        name="etcd 数据破坏",
        phase=AttackPhase.IMPACT,
        risk=RiskLevel.CRITICAL,
        description=(
            "直接或通过 API Server 破坏 etcd 中的数据。"
            "删除关键资源（CRD、自定义资源）导致扩展组件不可用。"
            "删除 ClusterRoleBinding 使所有用户失去权限。"
        ),
        prerequisites=["etcd 访问或 cluster-admin 权限"],
        steps=[
            "若可访问 etcd: etcdctl del /registry/ --prefix",
            "若通过 API: 删除所有 CRD、ClusterRoleBinding",
            "删除 admission webhook 配置使攻击绕过准入控制",
            "删除 CNI 相关资源触发网络全断",
        ],
        detection_hints=[
            "etcd 直接操作",
            "大规模集群资源删除",
            "CRD 和关键配置集体消失",
        ],
    ),
    AttackVector(
        id="IMP-006",
        name="节点污点化与工作负载驱逐",
        phase=AttackPhase.IMPACT,
        risk=RiskLevel.MEDIUM,
        description=(
            "通过给节点打上 NoExecute 污点，触发大规模 Pod 驱逐。"
            "配合删除其他节点的污点标志（如 control-plane 污点），"
            "迫使 Pod 迁移到不适当节点或全部 Pending。"
        ),
        prerequisites=["patch nodes 权限"],
        steps=[
            "kubectl taint nodes <node> key=value:NoExecute",
            "对所有 worker 节点添加 NoExecute 污点",
            "删除 control-plane 节点的 NoSchedule 污点造成混乱",
            "Pod 大规模进入 Evicted/Pending 状态",
        ],
        detection_hints=[
            "节点污点批量变更",
            "大规模 Pod 驱逐事件",
        ],
    ),
]


def get_impact_by_severity(min_risk: RiskLevel = RiskLevel.HIGH) -> list[AttackVector]:
    """按最低风险等级筛选"""
    risk_order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3, RiskLevel.INFO: 4}
    return [v for v in IMPACT_VECTORS if risk_order[v.risk] <= risk_order[min_risk]]
