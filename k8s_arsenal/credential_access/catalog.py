"""凭证访问技术编目

收录 K8s 集群凭证窃取技术，涵盖 Secret 读取、Token 提取、云凭证盗取。
"""

from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel


CREDENTIAL_ACCESS_VECTORS: list[AttackVector] = [
    AttackVector(
        id="CRD-001",
        name="全命名空间 Secret 枚举",
        phase=AttackPhase.CREDENTIAL_ACCESS,
        risk=RiskLevel.CRITICAL,
        description=(
            "通过 list secrets 在所有命名空间中枚举 Secret 对象。"
            "Secret 中常包含数据库密码、API Key、TLS 证书和云平台凭证。"
            "配合 jq/yq 解析 Secret data 字段可直接获取明文凭证。"
        ),
        prerequisites=["list secrets 权限（至少在一个命名空间）"],
        steps=[
            "kubectl get secrets --all-namespaces -o json",
            "解析 Secret data 字段（base64 解码）",
            "提取高价值凭证：云平台 Key、数据库密码、TLS 私钥",
        ],
        detection_hints=[
            "异常的跨命名空间 Secret list 操作",
            "短时间内大量 Secret 读取",
            "非运维时间的大量 Secret 访问",
        ],
        references=["K8s Secret API", "MITRE T1552"],
    ),
    AttackVector(
        id="CRD-002",
        name="挂载卷 SA Token 提取",
        phase=AttackPhase.CREDENTIAL_ACCESS,
        risk=RiskLevel.HIGH,
        description=(
            "从容器内挂载的 ServiceAccount Token 文件读取 JWT Token。"
            "Token 挂载路径: /var/run/secrets/kubernetes.io/serviceaccount/token。"
            "配合 RBAC 扩张可实现横向提权。"
        ),
        prerequisites=["容器内文件读取能力"],
        steps=[
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
            "解码 JWT 负载获取 SA 信息和过期时间",
            "使用 token 进行 API 认证",
        ],
        detection_hints=[
            "SA Token 用于非 Pod 来源的 API 调用",
            "审计日志中 token audience 字段异常",
        ],
    ),
    AttackVector(
        id="CRD-003",
        name="云元数据服务凭证窃取",
        phase=AttackPhase.CREDENTIAL_ACCESS,
        risk=RiskLevel.CRITICAL,
        description=(
            "通过云平台元数据服务（169.254.169.254）窃取 IAM 临时凭证。"
            "AWS IMDSv1 无需 Token 即可访问，IMDSv2 需 PUT 获取 Token。"
            "GCP/Azure 同样提供元数据端点，可获取 managed identity 凭证。"
        ),
        prerequisites=["容器可访问 169.254.169.254", "非 hostNetwork 模式需 NAT 可达"],
        steps=[
            "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "提取 AccessKeyId、SecretAccessKey、Token",
            "使用窃取的凭证访问云资源（S3、RDS、Lambda 等）",
        ],
        detection_hints=[
            "Pod 网络流量指向 169.254.169.254",
            "非系统组件访问云元数据端点",
        ],
        references=["AWS IMDS", "GCP Metadata Server", "Azure IMDS"],
    ),
    AttackVector(
        id="CRD-004",
        name="etcd 直接凭证窃取",
        phase=AttackPhase.CREDENTIAL_ACCESS,
        risk=RiskLevel.CRITICAL,
        description=(
            "etcd 存储所有 K8s 资源对象（包括 Secret）的明文数据。"
            "若能访问 etcd（端口 2379），使用 etcdctl 可直接读取 Secret。"
            "即使 API Server 有审计，etcd 直连操作不产生审计日志。"
        ),
        prerequisites=["etcd 端点可达", "etcd 客户端证书或绕过 auth"],
        steps=[
            "ETCDCTL_API=3 etcdctl --endpoints=<etcd-ip>:2379 get / --prefix --keys-only",
            "定位 Secret key: /registry/secrets/<ns>/<name>",
            "ETCDCTL_API=3 etcdctl get <secret-key>",
            "解析 protobuf 编码的 Secret 对象",
        ],
        detection_hints=[
            "etcd 端口的异常连接",
            "etcd 直接查询而非通过 API Server",
        ],
        references=["etcd Encryption at Rest", "MITRE T1552.001"],
    ),
    AttackVector(
        id="CRD-005",
        name="节点 kubeconfig 文件窃取",
        phase=AttackPhase.CREDENTIAL_ACCESS,
        risk=RiskLevel.CRITICAL,
        description=(
            "通过 hostPath 挂载或容器逃逸获取节点上的 kubeconfig 文件。"
            "节点 kubeconfig 通常包含 kubelet 客户端证书或 bootstrap token。"
            "路径: /etc/kubernetes/kubelet.conf 或 /var/lib/kubelet/kubeconfig。"
        ),
        prerequisites=["节点文件系统访问（hostPath/逃逸）"],
        steps=[
            "定位 kubeconfig 文件: find / -name '*.conf' -path '*/kubernetes/*'",
            "提取 client-certificate-data 和 client-key-data",
            "使用 kubelet 证书认证 API Server",
        ],
        detection_hints=[
            "kubelet 证书用于非 kubelet 来源的请求",
            "文件完整性监控告警",
        ],
        references=["K8s Node Authorization"],
    ),
]


def get_credential_access_by_target(target: str) -> list[AttackVector]:
    """按目标凭证类型筛选"""
    target_map = {
        "secret": ["Secret", "secret"],
        "token": ["Token", "token", "SA Token"],
        "cloud": ["Cloud", "Metadata", "IMDS"],
        "etcd": ["etcd"],
        "kubeconfig": ["kubeconfig", "kubelet"],
    }
    if target in target_map:
        keywords = target_map[target]
        return [
            v for v in CREDENTIAL_ACCESS_VECTORS
            if any(kw.lower() in v.description.lower() for kw in keywords)
        ]
    return CREDENTIAL_ACCESS_VECTORS
