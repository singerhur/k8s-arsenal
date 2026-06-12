"""侦察模块

K8s 环境探测、RBAC 权限分析、信任拓扑映射。
"""

from k8s_arsenal.recon.k8s_enum import enumerate_environment
from k8s_arsenal.recon.sa_analysis import (
    CLUSTER_ADMIN_RESOURCES,
    CLUSTER_ADMIN_VERBS,
    HIGH_RISK_PERMISSIONS,
    analyze_current_sa,
    assess_permission_risk,
)
from k8s_arsenal.recon.trust_map import (
    build_trust_topology,
    find_attackable_edges,
    render_trust_map_ascii,
)

__all__ = [
    "enumerate_environment",
    "CLUSTER_ADMIN_RESOURCES",
    "CLUSTER_ADMIN_VERBS",
    "HIGH_RISK_PERMISSIONS",
    "analyze_current_sa",
    "assess_permission_risk",
    "build_trust_topology",
    "find_attackable_edges",
    "render_trust_map_ascii",
]
