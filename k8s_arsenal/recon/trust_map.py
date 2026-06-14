"""信任拓扑映射

构建 K8s 集群内各组件间的信任关系图。
"""

from typing import Optional

from k8s_arsenal.models import TrustEdge, EnvironmentProfile, RiskLevel


def build_trust_topology(
    profile: EnvironmentProfile,
    kubeconfig: Optional[str] = None
) -> list[TrustEdge]:
    """构建集群信任拓扑

    分析组件间信任关系:
    - API Server ↔ kubelet (客户端证书)
    - kubelet → Pod (挂载 SA Token)
    - Pod → API Server (SA Token)
    - kubelet → 容器运行时 (Unix Socket)
    - API Server → etcd (客户端证书)
    - CoreDNS → API Server (SKIP 验证)

    返回信任边列表，每边标注凭证类型和轮换频率。
    """
    edges = []

    # API Server → kubelet (双向信任)
    edges.append(TrustEdge(
        source="kube-apiserver",
        target="kubelet",
        relationship="客户端证书认证",
        credential_type="kubelet-client-current.pem",
        auto_rotated=True,
        risk=RiskLevel.HIGH,
        metadata={"edge_type": "ClientCertAuth"},
    ))

    # kubelet → Pod (SA Token 挂载)
    edges.append(TrustEdge(
        source="kubelet",
        target="pod",
        relationship="挂载 ServiceAccount Token",
        credential_type="ServiceAccount Token (JWT)",
        auto_rotated=True,  # K8s 1.22+ 自动轮换
        risk=RiskLevel.HIGH,
        metadata={"edge_type": "ServiceAccountToken"},
    ))

    # Pod → API Server (SA Token 使用)
    edges.append(TrustEdge(
        source="pod",
        target="kube-apiserver",
        relationship="Bearer Token 认证",
        credential_type="ServiceAccount Token",
        auto_rotated=True,
        risk=RiskLevel.MEDIUM,
        metadata={"edge_type": "BearerTokenAuth"},
    ))

    # API Server → etcd
    edges.append(TrustEdge(
        source="kube-apiserver",
        target="etcd",
        relationship="客户端证书认证",
        credential_type="etcd-client.crt",
        auto_rotated=True,
        risk=RiskLevel.CRITICAL,
        metadata={"edge_type": "ClientCertAuth"},
    ))

    # kubelet → 容器运行时
    edges.append(TrustEdge(
        source="kubelet",
        target="container-runtime",
        relationship="Unix Socket (CRI)",
        credential_type="Unix Domain Socket",
        auto_rotated=False,
        risk=RiskLevel.HIGH,
        metadata={"edge_type": "UnixSocket"},
    ))

    # CoreDNS → API Server
    edges.append(TrustEdge(
        source="coredns",
        target="kube-apiserver",
        relationship="跳过 TLS 验证 (默认)",
        credential_type="CoreDNS ServiceAccount",
        auto_rotated=True,
        risk=RiskLevel.MEDIUM,
        metadata={"edge_type": "SkipTLSVerify"},
    ))

    # kube-proxy → API Server
    edges.append(TrustEdge(
        source="kube-proxy",
        target="kube-apiserver",
        relationship="ServiceAccount 认证",
        credential_type="kube-proxy ServiceAccount (cluster-admin?)",
        auto_rotated=True,
        risk=RiskLevel.CRITICAL,
        metadata={"edge_type": "ServiceAccount"},
    ))

    # 如果当前环境在 Pod 内，添加具体边
    if profile.is_kubernetes and profile.service_account:
        edges.append(TrustEdge(
            source=f"pod/{profile.service_account}",
            target="kube-apiserver",
            relationship="当前 Pod 信任关系",
            credential_type=profile.service_account,
            auto_rotated=True,
            risk=RiskLevel.MEDIUM,
            metadata={"edge_type": "PodTrust"},
        ))

    # 容器运行时 Socket 分析
    if profile.mounted_docker_sock:
        edges.append(TrustEdge(
            source="current-container",
            target="docker-daemon",
            relationship="挂载 Docker Socket",
            credential_type="Unix Domain Socket (/var/run/docker.sock)",
            auto_rotated=False,
            risk=RiskLevel.CRITICAL,
            metadata={"edge_type": "DockerSocket"},
        ))

    return edges


def find_attackable_edges(edges: list[TrustEdge]) -> list[TrustEdge]:
    """筛选可被利用的信任边

    条件:
    - 自动轮换为 False 的（证书/Socket 不变）
    - 风险等级 HIGH 或 CRITICAL
    """
    attackable = []
    for edge in edges:
        if not edge.auto_rotated and edge.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            attackable.append(edge)
    return attackable


def render_trust_map_ascii(edges: list[TrustEdge]) -> str:
    """生成 ASCII 信任拓扑图"""
    lines = ["K8s 集群信任拓扑:", "=" * 40]
    for edge in edges:
        risk_icon = "[!]" if edge.risk == RiskLevel.CRITICAL else \
                    "[X]" if edge.risk == RiskLevel.HIGH else \
                    "[~]" if edge.risk == RiskLevel.MEDIUM else "[-]"
        rotate = "[R]" if edge.auto_rotated else "[L]"
        lines.append(
            f"  {risk_icon} [{edge.source}] --{edge.credential_type or edge.relationship}--> "
            f"[{edge.target}] {rotate}"
        )
    return "\n".join(lines)
