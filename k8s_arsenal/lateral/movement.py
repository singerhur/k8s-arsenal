"""横向移动技术编目

收录 K8s 集群内横向移动技术，包括 Kubelet 证书利用、Token 窃取、节点代理等。
"""

from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel


LATERAL_VECTORS: list[AttackVector] = [
    AttackVector(
        id="LAT-001",
        name="Kubelet 客户端证书横向移动",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.CRITICAL,
        description=(
            "利用节点上的 kubelet-client-current.pem 证书作为客户端凭证，"
            "通过 API Server 的 nodes/proxy 接口在其他节点上执行命令。"
            "kubelet 证书拥有对节点的完全控制权。"
        ),
        prerequisites=["节点 root 权限", "kubelet-client-current.pem 可读"],
        steps=[
            "读取 /var/lib/kubelet/pki/kubelet-client-current.pem",
            "使用该证书作为 curl/kubectl 的客户端证书",
            "调用 /api/v1/nodes/<node>/proxy/pods 枚举 Pod",
            "通过 nodes/<node>/proxy/run 在新节点执行命令",
        ],
        detection_hints=[
            "nodes/proxy 接口调用",
            "非 kubelet 进程使用 kubelet 证书",
        ],
        references=["Kubelet API (10250)"],
    ),
    AttackVector(
        id="LAT-002",
        name="ServiceAccount Token 窃取横向移动",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.HIGH,
        description=(
            "在已控制的 Pod 内读取挂载的 ServiceAccount Token，"
            "使用该 Token 访问 API Server。如果 Token 有跨命名空间权限，"
            "可以横向移动到其他命名空间。"
        ),
        prerequisites=["Pod exec 权限", "目标 Pod 挂载有权限的 SA Token"],
        steps=[
            "kubectl exec 进入 Pod",
            "读取 /var/run/secrets/kubernetes.io/serviceaccount/token",
            "读取 ca.crt 和 namespace",
            "用 Token 认证访问 API Server",
            "在不同命名空间部署资源",
        ],
        detection_hints=[
            "同一 SA Token 被不同 IP/UserAgent 使用",
            "命名空间间异常资源创建",
        ],
    ),
    AttackVector(
        id="LAT-003",
        name="容器运行时 Socket 横向移动",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.CRITICAL,
        description=(
            "通过挂载的 Docker/containerd Socket，在宿主机上创建新容器 "
            "或 exec 进入现有容器（包括 kube-system 中的特权容器）。"
            "可直接挂载宿主机根文件系统获取完全控制。"
        ),
        prerequisites=["容器运行时 Socket 挂载", "docker/containerd 客户端"],
        steps=[
            "安装 docker/crictl 客户端工具",
            "docker exec 进入 kube-system 中的系统容器",
            "或 docker run --privileged --pid=host 创建新特权容器",
            "在新容器中进一步渗透",
        ],
        detection_hints=[
            "容器运行时 Socket 的异常调用",
            "非编排系统创建的容器",
        ],
    ),
    AttackVector(
        id="LAT-004",
        name="Impersonate-User 身份伪装横向移动",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.HIGH,
        description=(
            "使用已获取的高权限 SA Token，结合 Impersonate-User HTTP 头 "
            "伪装成其他用户（如 system:admin）。"
            "审计日志将显示被伪装用户的操作记录。"
        ),
        prerequisites=["有 impersonate 权限的 SA Token", "API Server 访问"],
        steps=[
            "获取有 impersonate 权限的 SA Token",
            "在 API 请求中添加 Impersonate-User: system:admin",
            "或添加 Impersonate-Group: system:masters",
            "执行需要管理员权限的操作",
            "审计日志混淆真实攻击者身份",
        ],
        detection_hints=[
            "Impersonate 行为审计日志",
            "同一用户同时从多个 IP 操作",
        ],
    ),
    AttackVector(
        id="LAT-005",
        name="Pod 内 curl/proxy 代理中继",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.MEDIUM,
        description=(
            "在已控制的 Pod 内启动纯 Python/Go HTTP 代理，转发 API 请求时自动注入 "
            "当前 SA Token。跳过 TLS 证书校验解决自签名环境问题。"
            "作为横向移动跳板，隐藏攻击者的真实来源。"
        ),
        prerequisites=["Pod exec 权限", "Pod 内可运行 HTTP 代理"],
        steps=[
            "部署内存代理（Python http.server 或 Go net/http）",
            "读取 SA Token 并注入到转发的请求中",
            "跳过 SSL 证书验证",
            "从攻击者机器通过代理访问集群内服务",
        ],
        detection_hints=[
            "Pod 内异常监听端口",
            "不明来源的 HTTP 代理流量",
        ],
    ),
    AttackVector(
        id="LAT-006",
        name="ConfigMap/Secret 信息收集横向扩散",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.MEDIUM,
        description=(
            "在已控制的命名空间内读取所有 ConfigMap 和 Secret，"
            "从中提取其他系统的凭证、API Key、数据库连接串等。"
            "利用这些凭证访问集群外系统或跨命名空间。"
        ),
        prerequisites=["get secrets 权限", "get configmaps 权限"],
        steps=[
            "kubectl get secrets --all-namespaces (若有权限)",
            "kubectl get configmaps -n <target>",
            "解码 Secret 中的 base64 数据",
            "使用提取的凭证访问目标系统",
        ],
        detection_hints=[
            "大规模 Secret/ConfigMap 读取",
            "异常命名空间的 Secret 访问",
        ],
    ),
    AttackVector(
        id="LAT-007",
        name="kube-proxy iptables 流量重定向",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.HIGH,
        description=(
            "逃逸至宿主机后，插入 iptables DNAT 规则将目标 Service ClusterIP "
            "流量重定向到攻击者控制的 Pod。"
            "不影响 Service 原有功能，只是复制或选择性篡改流量。"
        ),
        prerequisites=["宿主机 root 权限", "iptables 可用"],
        steps=[
            "逃逸至宿主机",
            "iptables -t nat -I PREROUTING -d <ClusterIP> -j DNAT --to <攻击者PodIP>",
            "在攻击者 Pod 内部署流量嗅探/篡改服务",
            "选择性转发或篡改后返回原目标",
        ],
        detection_hints=[
            "异常 iptables 规则",
            "Service 流量异常路由",
        ],
    ),
    AttackVector(
        id="LAT-008",
        name="etcd 客户端证书直连",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.CRITICAL,
        description=(
            "获取 etcd 客户端证书后，直接连接 etcd 集群写入或读取数据。"
            "完全绕过 API Server 的审计、RBAC、准入控制器。"
            "可直接注入 ServiceAccount、ClusterRoleBinding 等对象。"
        ),
        prerequisites=["etcd 客户端证书", "etcd 端点可达"],
        steps=[
            "获取 etcd 客户端证书（通常从 API Server Pod 或 /etc/kubernetes/pki）",
            "使用 etcdctl 或 gRPC 直连 etcd",
            "按 K8s protobuf 编码写入资源对象",
            "对象凭空出现在集群中",
        ],
        detection_hints=[
            "etcd 直连连接",
            "绕过 API Server 的对象变更",
        ],
    ),
]


def get_lateral_by_entry_point(entry: str) -> list[AttackVector]:
    """按入口点筛选横向移动技术"""
    keyword_map = {
        "node": ["节点", "kubelet", "Socket", "宿主机"],
        "pod": ["Pod", "exec", "Token", "代理"],
        "sa": ["ServiceAccount", "Token", "Impersonate"],
        "etcd": ["etcd"],
    }
    if entry in keyword_map:
        keywords = keyword_map[entry]
        return [
            v for v in LATERAL_VECTORS
            if any(kw in v.description for kw in keywords)
        ]
    return LATERAL_VECTORS
