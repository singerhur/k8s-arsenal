"""Capability set algebra — answers "what can the attacker do cumulatively."

Capabilities are NOT per-edge properties; they accumulate across the path.
This layer converts Role rule fragments into capability tokens and tracks
the growing set: individual edges reveal individual capabilities, but the
COMBINATION defines the true attack surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from k8s_arsenal.models import TrustEdge


# Map: (resource, verb) key-pattern → capability token.
# Handles both "resource/verb" and "verb resource" forms from metadata.
_CAPABILITY_MAP: dict[str, str] = {
    # Core attack primitives
    "pods/create": "create_pod",
    "pods/exec": "exec_pod",
    "pods/attach": "exec_pod",
    "pods/patch": "modify_pod",
    "pods/update": "modify_pod",
    "deployments/create": "create_pod",
    "deployments/patch": "modify_workload",
    "deployments/update": "modify_workload",
    "jobs/create": "create_pod",
    "cronjobs/create": "create_pod",
    "daemonsets/create": "create_pod",
    "statefulsets/create": "create_pod",
    "replicasets/create": "create_pod",
    # Token / identity theft
    "secrets/get": "read_secret",
    "secrets/list": "read_secret",
    "secrets/watch": "read_secret",
    "serviceaccounts/token": "steal_token",
    "serviceaccounts/get": "steal_token",
    # Impersonation
    "users/impersonate": "impersonate",
    "groups/impersonate": "impersonate",
    "serviceaccounts/impersonate": "impersonate",
    # Host access
    "nodes/proxy": "node_access",
    # RBAC manipulation
    "rolebindings/create": "grant_rbac",
    "clusterrolebindings/create": "grant_rbac",
    "roles/create": "grant_rbac",
    "clusterroles/create": "grant_rbac",
    "clusterroles/escalate": "escalate_rbac",
    "roles/escalate": "escalate_rbac",
}


@dataclass
class CapabilityState:
    """Cumulative capabilities accumulated along an attack path."""

    capabilities: set[str] = field(default_factory=set)

    def has(self, capability: str) -> bool:
        return capability in self.capabilities


# ── relationship hint capabilities (fallback for unannotated trust_map edges) ────
# When trust_map edges lack metadata (neither explicit capability nor role_rules),
# this mapping provides conservative capability hints based on well-known
# trust relationship semantics. Docker Socket implies container breakout;
# TokenAccess implies identity transition capability (used by identity_flow).
_RELATIONSHIP_HINT_CAPABILITIES: dict[str, set[str]] = {
    # Production trust_map.py strings
    "挂载 Docker Socket": {"node_access"},
    # Test fixture / English aliases
    "Docker Socket": {"node_access"},
    "Docker Socket 挂载": {"node_access"},
    "Host PID": {"node_access"},
    "特权容器": {"node_access", "create_pod", "exec_pod"},
}


def _capability_from_rules(rules: list[dict]) -> set[str]:
    """Extract capability tokens from Role/ClusterRole rule list.

    Each rule: {"verbs": ["create", "get"], "resources": ["pods", "secrets"]}
    Returns a set of capability tokens like {"create_pod", "read_secret"}.
    """
    caps: set[str] = set()
    for rule in rules:
        verbs = rule.get("verbs", [])
        resources = rule.get("resources", [])
        for resource in resources:
            for verb in verbs:
                key = f"{resource}/{verb}"
                cap = _CAPABILITY_MAP.get(key)
                if cap:
                    caps.add(cap)
    return caps


def update_capability(state: CapabilityState, edge: TrustEdge) -> CapabilityState:
    """Accumulate capabilities from a trust edge.

    Capabilities are extracted from two metadata sources:
    1. metadata.capability — explicit capability annotation on inference edges
    2. metadata.role_rules — raw Role/ClusterRole rules on observation edges
    """
    meta = edge.metadata

    # Source 1: explicit capability annotation (inference edges)
    cap_meta = meta.get("capability", {})
    if cap_meta:
        rules = cap_meta if isinstance(cap_meta, list) else [cap_meta]
        new_caps = _capability_from_rules(rules)
        state.capabilities.update(new_caps)

    # Source 2: raw Role/ClusterRole rules (observation edges)
    role_rules = meta.get("role_rules", [])
    if role_rules:
        new_caps = _capability_from_rules(role_rules)
        state.capabilities.update(new_caps)

    # Source 3: relationship hint fallback (trust_map edges with no metadata)
    # Only active when both explicit sources are empty — uses conservative
    # heuristics for well-known trust relationship types.
    if not cap_meta and not role_rules:
        hint = _RELATIONSHIP_HINT_CAPABILITIES.get(edge.relationship, None)
        if hint:
            state.capabilities.update(hint)

    return state


def is_compromised(state: CapabilityState, threshold: str = "standard") -> bool:
    """[DEPRECATED] Check if cumulative capabilities imply cluster compromise.

    Use `evaluate_terminal_state()` in `runtime/terminal_state.py` instead,
    which supports the full T(S) with graph-aware PARTIAL detection.

    Kept for backward compatibility. Delegates to hard-compromise check only.

    Thresholds:
    - "standard": create_pod + exec_pod + read_secret  (privileged pod route)
    - "host": add node_access to the above  (direct node compromise)
    - "rbac_escalation": create_pod + grant_rbac  (deploy + escalate)
    """
    import warnings
    warnings.warn(
        "capability_set.is_compromised() is deprecated. "
        "Use evaluate_terminal_state() for graph-aware T(S) evaluation.",
        DeprecationWarning,
        stacklevel=2,
    )
    caps = state.capabilities

    thresholds: dict[str, list[str]] = {
        "standard": ["create_pod", "exec_pod", "read_secret"],
        "host": ["create_pod", "exec_pod", "read_secret", "node_access"],
        "rbac_escalation": ["create_pod", "grant_rbac"],
        "any_host": ["node_access"],
        "any_impersonate": ["impersonate"],
    }

    required = thresholds.get(threshold, thresholds["standard"])
    return all(c in caps for c in required)
