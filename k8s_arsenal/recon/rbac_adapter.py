"""
Live RBAC Adapter — build trust edges from real Kubernetes RBAC queries.

Replaces the hardcoded static topology with live cluster discovery.
Queries ClusterRoles, RoleBindings, ClusterRoleBindings, and ServiceAccounts
to build TrustEdge objects with OBSERVATION-level evidence.

Edge types detected:
  TokenAccess   — SA can read secrets in another SA's namespace (token theft)
  Impersonate   — SA can impersonate users/groups/serviceaccounts
  NodeAccess    — SA has verbs on nodes (node compromise path)
  RbacEdge      — SA can bind/escalate roles/clusterroles
  PodTrust      — SA can create/exec pods (deploy privileged workloads)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from k8s_arsenal.models import (
    TrustEdge, EdgeSource, RiskLevel, EnvironmentProfile,
)

logger = logging.getLogger(__name__)

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    HAS_K8S_CLIENT = True
except ImportError:
    HAS_K8S_CLIENT = False
    ApiException = Exception


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _get_k8s_clients(
    kubeconfig: Optional[str] = None,
) -> tuple[object, object, object]:
    """Return (CoreV1Api, RbacAuthorizationV1Api, AppsV1Api) or raise."""
    if not HAS_K8S_CLIENT:
        raise RuntimeError(
            "kubernetes client not installed. Run: pip install kubernetes>=27.0.0"
        )
    if kubeconfig:
        config.load_kube_config(config_file=kubeconfig)
    else:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
    return (
        client.CoreV1Api(),
        client.RbacAuthorizationV1Api(),
        client.AppsV1Api(),
    )


def _safe_api_call(fn, *args, **kwargs):
    """Wrap ApiException into logger warning; return [] on failure."""
    try:
        return fn(*args, **kwargs)
    except ApiException as exc:
        logger.warning("K8s API call failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# SA + RBAC discovery
# ---------------------------------------------------------------------------

@dataclass
class SARbacInfo:
    """Resolved RBAC information for one ServiceAccount."""
    name: str
    namespace: str
    role_rules: list[dict] = field(default_factory=list)
    cluster_role_rules: list[dict] = field(default_factory=list)
    # role_rules / cluster_role_rules are raw rule dicts:
    #   {"apiGroups": [...], "resources": [...], "verbs": [...]}
    role_names: list[str] = field(default_factory=list)
    cluster_role_names: list[str] = field(default_factory=list)


def list_service_accounts(
    namespace: Optional[str] = None,
    kubeconfig: Optional[str] = None,
) -> dict[tuple[str, str], SARbacInfo]:
    """Discover all ServiceAccounts and their RBAC rules.

    Returns dict keyed by (namespace, name) -> SARbacInfo.
    If namespace is None, scans all namespaces.
    """
    core, rbac, _ = _get_k8s_clients(kubeconfig)
    result: dict[tuple[str, str], SARbacInfo] = {}

    # list namespaces
    if namespace:
        nss = [namespace]
    else:
        ns_list = _safe_api_call(core.list_namespace)
        nss = [ns.metadata.name for ns in (ns_list.items if ns_list else [])]

    if not nss:
        logger.warning("No namespaces found — are you connected to a cluster?")
        return result

    # collect SAs per namespace
    for ns in nss:
        sa_list = _safe_api_call(core.list_namespaced_service_account, ns)
        if not sa_list:
            continue
        for sa in sa_list.items:
            sa_name = sa.metadata.name
            info = SARbacInfo(name=sa_name, namespace=ns)

            # --- RoleBindings ---
            rbs = _safe_api_call(rbac.list_namespaced_role_binding, ns)
            for rb in (rbs.items if rbs else []):
                for subj in rb.subjects or []:
                    if (
                        subj.kind == "ServiceAccount"
                        and subj.name == sa_name
                        and (subj.namespace or ns) == ns
                    ):
                        info.role_names.append(rb.role_ref.name)
                        rules = _resolve_role_rules(
                            rbac, rb.role_ref.name, ns
                        )
                        info.role_rules.extend(rules)

            # --- ClusterRoleBindings ---
            crbs = _safe_api_call(rbac.list_cluster_role_binding)
            for crb in (crbs.items if crbs else []):
                for subj in crb.subjects or []:
                    if (
                        subj.kind == "ServiceAccount"
                        and subj.name == sa_name
                        and (subj.namespace or ns) == ns
                    ):
                        info.cluster_role_names.append(crb.role_ref.name)
                        rules = _resolve_cluster_role_rules(
                            rbac, crb.role_ref.name
                        )
                        info.cluster_role_rules.extend(rules)

            result[(ns, sa_name)] = info

    logger.info(
        "Discovered %d ServiceAccount(s) across %d namespace(s)",
        len(result), len(nss),
    )
    return result


def _resolve_role_rules(
    rbac, role_name: str, namespace: str
) -> list[dict]:
    """Resolve a namespaced Role to its rule list."""
    role = _safe_api_call(rbac.read_namespaced_role, role_name, namespace)
    if not role:
        return []
    return [
        {
            "apiGroups": r.api_groups or [""],
            "resources": r.resources or [],
            "verbs": r.verbs or [],
        }
        for r in (role.rules or [])
    ]


def _resolve_cluster_role_rules(rbac, cr_name: str) -> list[dict]:
    """Resolve a ClusterRole to its rule list."""
    cr = _safe_api_call(rbac.read_cluster_role, cr_name)
    if not cr:
        return []
    return [
        {
            "apiGroups": r.api_groups or [""],
            "resources": r.resources or [],
            "verbs": r.verbs or [],
        }
        for r in (cr.rules or [])
    ]


# ---------------------------------------------------------------------------
# rule → capability inference
# ---------------------------------------------------------------------------

# Known dangerous verb-resource patterns and their capability names.
_DANGEROUS_PATTERNS: list[tuple[set[str], set[str], str]] = [
    # (verbs, resources, capability_name)
    ({"impersonate"}, {"users", "groups", "serviceaccounts"}, "impersonate"),
    ({"*", "get", "list", "watch"}, {"secrets"}, "read_secrets"),
    ({"create", "update", "patch", "*"}, {"secrets"}, "write_secrets"),
    ({"*", "create", "update", "patch", "delete"}, {"pods"}, "create_pod"),
    ({"*", "get", "list"}, {"pods/exec", "pods/log"}, "exec_pod"),
    ({"bind", "escalate", "*"}, {"roles", "clusterroles"}, "escalate_rbac"),
    ({"*", "get", "list", "proxy"}, {"nodes"}, "node_access"),
    ({"*", "create", "update", "patch", "delete"}, {"deployments", "daemonsets", "statefulsets"}, "create_workload"),
    ({"*", "create", "update"}, {"validatingwebhookconfigurations", "mutatingwebhookconfigurations"}, "control_admission"),
    ({"*"}, {"*"}, "cluster_admin"),
]


def _infer_capabilities(rules: list[dict]) -> set[str]:
    """Infer capability names from a list of RBAC rules."""
    caps: set[str] = set()
    for rule in rules:
        rule_verbs = set(rule.get("verbs", []))
        rule_resources = set(rule.get("resources", []))
        for patt_verbs, patt_resources, cap_name in _DANGEROUS_PATTERNS:
            if rule_verbs & patt_verbs and rule_resources & patt_resources:
                caps.add(cap_name)
    return caps


def _infer_edge_type_from_caps(capabilities: set[str]) -> str:
    """Map capability set to a primary edge_type string."""
    if "cluster_admin" in capabilities:
        return "Impersonate"  # full compromise edges treated as identity transitions
    if "impersonate" in capabilities:
        return "Impersonate"
    if "node_access" in capabilities:
        return "NodeAccess"
    if "read_secrets" in capabilities or "write_secrets" in capabilities:
        return "TokenAccess"
    if "escalate_rbac" in capabilities:
        return "RbacEdge"
    if "create_pod" in capabilities or "exec_pod" in capabilities:
        return "PodTrust"
    return "ObservationEdge"


def _infer_risk_level(capabilities: set[str]) -> RiskLevel:
    """Map capability set to a risk level."""
    if "cluster_admin" in capabilities:
        return RiskLevel.CRITICAL
    if "impersonate" in capabilities or "escalate_rbac" in capabilities:
        return RiskLevel.CRITICAL
    if "node_access" in capabilities:
        return RiskLevel.HIGH
    if "read_secrets" in capabilities or "write_secrets" in capabilities:
        return RiskLevel.HIGH
    if "create_workload" in capabilities:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


# ---------------------------------------------------------------------------
# TrustEdge generation from live RBAC
# ---------------------------------------------------------------------------

def build_live_rbac_edges(
    namespace: Optional[str] = None,
    kubeconfig: Optional[str] = None,
    include_infrastructure: bool = True,
    entry_namespace: Optional[str] = None,
) -> list[TrustEdge]:
    """Build TrustEdge list from live cluster RBAC queries.

    Returns edges of two kinds:

    1. **RBAC edges** (EdgeSource.OBSERVATION):
       Discovered from live RoleBinding/ClusterRoleBinding data.
       Each edge represents a SA-to-SA relationship where one SA's
       permissions enable attacking another SA or cluster resource.

    2. **Infrastructure edges** (EdgeSource.DEFAULT):
       Standard K8s component trust relationships (API Server↔etcd,
       kubelet↔CRI, etc.), same as the existing build_trust_topology().

    Parameters
    ----------
    namespace : str | None
        Scope the scan to a single namespace. None = all namespaces.
    kubeconfig : str | None
        Path to kubeconfig file. None uses in-cluster or default config.
    include_infrastructure : bool
        Include standard K8s component edges (default: True).
    entry_namespace : str | None
        If set, mark SAs in this namespace as entry points.
        Used to scope the attack graph to a specific namespace.

    Returns
    -------
    list[TrustEdge]
    """
    edges: list[TrustEdge] = []

    # 1. Discover all SAs and their RBAC rules
    sa_map = list_service_accounts(namespace=namespace, kubeconfig=kubeconfig)
    if not sa_map:
        logger.warning("No ServiceAccounts discovered — returning empty edge list")
        if include_infrastructure:
            edges.extend(_build_infrastructure_edges())
        return edges

    # 2. Build SA→SA edges based on RBAC capabilities
    sa_list = list(sa_map.values())

    for sa_a in sa_list:
        ns_a, name_a = sa_a.namespace, sa_a.name
        all_rules = sa_a.role_rules + sa_a.cluster_role_rules
        caps_a = _infer_capabilities(all_rules)

        if not caps_a:
            continue  # No dangerous capabilities, skip

        edge_type_a = _infer_edge_type_from_caps(caps_a)
        risk_a = _infer_risk_level(caps_a)
        evidence = {
            "role_names": sa_a.role_names,
            "cluster_role_names": sa_a.cluster_role_names,
        }

        # Cross-namespace TokenAccess: SA-A can read secrets in SA-B's namespace
        if "read_secrets" in caps_a or "write_secrets" in caps_a:
            for sa_b in sa_list:
                ns_b, name_b = sa_b.namespace, sa_b.name
                if (ns_a, name_a) == (ns_b, name_b):
                    continue
                # ClusterRole rules grant access across all namespaces
                if any(
                    r.get("resources") and
                    "secrets" in r["resources"]
                    for r in sa_a.cluster_role_rules
                ):
                    edges.append(TrustEdge(
                        source=f"{ns_a}/{name_a}",
                        target=f"{ns_b}/{name_b}",
                        relationship="TokenAccess",
                        risk=risk_a,
                        metadata={
                            "edge_type": "TokenAccess",
                            "source": EdgeSource.OBSERVATION.value,
                            "capability": _rule_summary(all_rules),
                            "evidence": evidence,
                        },
                    ))
                # Namespace-scoped Role: can only access secrets in own ns
                elif sa_a.role_rules:
                    for sa_b_in_ns_a in sa_list:
                        if (
                            sa_b_in_ns_a.namespace == ns_a
                            and sa_b_in_ns_a.name != name_a
                        ):
                            edges.append(TrustEdge(
                                source=f"{ns_a}/{name_a}",
                                target=f"{ns_a}/{sa_b_in_ns_a.name}",
                                relationship="TokenAccess",
                                risk=risk_a,
                                metadata={
                                    "edge_type": "TokenAccess",
                                    "source": EdgeSource.OBSERVATION.value,
                                    "capability": _rule_summary(all_rules),
                                    "evidence": evidence,
                                    "scope": "namespace",
                                },
                            ))
                            break  # At most one edge per source SA per ns pair

        # Impersonate: SA can become another SA
        if "impersonate" in caps_a:
            for sa_b in sa_list:
                if (sa_a.namespace, sa_a.name) == (sa_b.namespace, sa_b.name):
                    continue
                # Impersonate via ClusterRole can reach any SA
                if any(
                    r.get("resources") and
                    set(r["resources"]) & {"users", "groups", "serviceaccounts"}
                    and set(r.get("verbs", [])) & {"impersonate", "*"}
                    for r in sa_a.cluster_role_rules
                ):
                    edges.append(TrustEdge(
                        source=f"{sa_a.namespace}/{sa_a.name}",
                        target=f"{sa_b.namespace}/{sa_b.name}",
                        relationship="Impersonate",
                        risk=risk_a,
                        metadata={
                            "edge_type": "Impersonate",
                            "source": EdgeSource.OBSERVATION.value,
                            "capability": _rule_summary(all_rules),
                            "evidence": evidence,
                        },
                    ))
                # Namespace-scoped impersonate
                elif any(
                    r.get("resources") and
                    set(r["resources"]) & {"users", "groups", "serviceaccounts"}
                    and set(r.get("verbs", [])) & {"impersonate", "*"}
                    for r in sa_a.role_rules
                ):
                    if sa_b.namespace == sa_a.namespace:
                        edges.append(TrustEdge(
                            source=f"{sa_a.namespace}/{sa_a.name}",
                            target=f"{sa_b.namespace}/{sa_b.name}",
                            relationship="Impersonate",
                            risk=risk_a,
                            metadata={
                                "edge_type": "Impersonate",
                                "source": EdgeSource.OBSERVATION.value,
                                "capability": _rule_summary(all_rules),
                                "evidence": evidence,
                                "scope": "namespace",
                            },
                        ))

        # NodeAccess: SA has node-level permissions
        if "node_access" in caps_a:
            edges.append(TrustEdge(
                source=f"{ns_a}/{name_a}",
                target="kubelet-node",
                relationship="NodeAccess",
                risk=risk_a,
                metadata={
                    "edge_type": "NodeAccess",
                    "source": EdgeSource.OBSERVATION.value,
                    "capability": _rule_summary(all_rules),
                    "evidence": evidence,
                },
            ))

        # RbacEdge: can escalate/bind roles
        if "escalate_rbac" in caps_a:
            # Edge to cluster-admin (control-plane node)
            edges.append(TrustEdge(
                source=f"{ns_a}/{name_a}",
                target="cluster-admin",
                relationship="RbacEdge",
                risk=risk_a,
                metadata={
                    "edge_type": "RbacEdge",
                    "source": EdgeSource.OBSERVATION.value,
                    "capability": _rule_summary(all_rules),
                    "evidence": evidence,
                },
            ))

        # PodTrust: can create/exec pods — can deploy privileged containers
        # to any reachable node
        if "create_pod" in caps_a or "exec_pod" in caps_a or "create_workload" in caps_a:
            edges.append(TrustEdge(
                source=f"{ns_a}/{name_a}",
                target="kubelet-node",
                relationship="PodTrust",
                risk=risk_a,
                metadata={
                    "edge_type": "PodTrust",
                    "source": EdgeSource.OBSERVATION.value,
                    "capability": _rule_summary(all_rules),
                    "evidence": evidence,
                },
            ))

    # 3. Infrastructure edges (static K8s component topology)
    if include_infrastructure:
        edges.extend(_build_infrastructure_edges())

    logger.info(
        "Built %d TrustEdge(s): %d RBAC + %d infrastructure",
        len(edges),
        len(edges) - (9 if include_infrastructure else 0),
        9 if include_infrastructure else 0,
    )
    return edges


def _rule_summary(rules: list[dict]) -> dict:
    """Summarize RBAC rules into a compact capability dict.

    Returns {"verbs": ["get","list",...], "resources": ["secrets","pods",...]}
    """
    verbs: set[str] = set()
    resources: set[str] = set()
    for r in rules:
        verbs.update(r.get("verbs", []))
        resources.update(r.get("resources", []))
    return {"verbs": sorted(verbs), "resources": sorted(resources)}


# ---------------------------------------------------------------------------
# infrastructure edges (re-use existing trust_map patterns)
# ---------------------------------------------------------------------------

_INFRA_EDGES: list[dict] = [
    {"s": "kube-apiserver", "t": "kubelet", "r": "ClientCertAuth", "risk": RiskLevel.HIGH, "rot": True},
    {"s": "kubelet", "t": "pod", "r": "ServiceAccountToken", "risk": RiskLevel.HIGH, "rot": True},
    {"s": "pod", "t": "kube-apiserver", "r": "BearerTokenAuth", "risk": RiskLevel.MEDIUM, "rot": True},
    {"s": "kube-apiserver", "t": "etcd", "r": "ClientCertAuth", "risk": RiskLevel.CRITICAL, "rot": True},
    {"s": "kubelet", "t": "container-runtime", "r": "UnixSocket", "risk": RiskLevel.HIGH, "rot": False},
    {"s": "coredns", "t": "kube-apiserver", "r": "SkipTLSVerify", "risk": RiskLevel.MEDIUM, "rot": True},
    {"s": "kube-proxy", "t": "kube-apiserver", "r": "ServiceAccount", "risk": RiskLevel.CRITICAL, "rot": True},
]


def _build_infrastructure_edges() -> list[TrustEdge]:
    """Build static K8s component trust topology edges."""
    edges: list[TrustEdge] = []
    for e in _INFRA_EDGES:
        edges.append(TrustEdge(
            source=e["s"],
            target=e["t"],
            relationship=e["r"],
            risk=e["risk"],
            auto_rotated=e["rot"],
            metadata={
                "edge_type": e["r"],
                "source": EdgeSource.DEFAULT.value,
            },
        ))
    return edges


# ---------------------------------------------------------------------------
# drop-in replacement for build_trust_topology()
# ---------------------------------------------------------------------------

def build_live_topology(
    profile: Optional[EnvironmentProfile] = None,
    kubeconfig: Optional[str] = None,
    namespace: Optional[str] = None,
) -> list[TrustEdge]:
    """Drop-in replacement for trust_map.build_trust_topology().

    Uses live RBAC queries instead of hardcoded topology.
    Falls back to static infrastructure edges if K8s client is unavailable.

    Parameters
    ----------
    profile : EnvironmentProfile | None
        Environment profile with container/K8s metadata.
    kubeconfig : str | None
        Path to kubeconfig file.
    namespace : str | None
        Scope to a specific namespace: if None, scans all namespaces.

    Returns
    -------
    list[TrustEdge]
    """
    edges: list[TrustEdge] = []

    # 1. RBAC edges from live cluster
    if HAS_K8S_CLIENT:
        rbac_edges = build_live_rbac_edges(
            namespace=namespace,
            kubeconfig=kubeconfig,
            include_infrastructure=True,
        )
        edges.extend(rbac_edges)
    else:
        logger.warning(
            "kubernetes client not available; falling back to static topology only"
        )
        edges.extend(_build_infrastructure_edges())

    # 2. Docker socket edge (environment-specific, from profile)
    if profile and profile.is_kubernetes and profile.mounted_docker_sock:
        edges.append(TrustEdge(
            source="current-container",
            target="docker-daemon",
            relationship="DockerSocket",
            risk=RiskLevel.CRITICAL,
            metadata={
                "edge_type": "DockerSocket",
                "source": EdgeSource.OBSERVATION.value,
            },
        ))

    # 3. Current Pod trust (from profile)
    if profile and profile.is_kubernetes and profile.service_account:
        edges.append(TrustEdge(
            source=f"pod/{profile.service_account}",
            target="kube-apiserver",
            relationship="PodTrust",
            risk=RiskLevel.MEDIUM,
            metadata={
                "edge_type": "PodTrust",
                "source": EdgeSource.DEFAULT.value,
            },
        ))

    return edges