"""Terminal State Function — unified attack outcome classification.

T(S, G, p) → {SAFE, PARTIAL, COMPROMISED}

The semantic closure of v0.5's state-evolution model. Not a rules engine,
but three computable predicates that define the attack terminal space:

  COMPROMISED: Attacker has already achieved cluster-admin or kubelet
               impersonation — the kill shot has landed.

  PARTIAL:     Attacker has not yet achieved compromise, but the current
               identity can still reach a critical asset in the graph.
               They are "on a trajectory" toward terminal state.

  SAFE:        Attacker neither has compromise capability nor has a
               reachable path to any critical asset. Trajectory is benign.

This is the single exit function that all downstream analysis
(counterfactual, cut-set, what-if) will evaluate against.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from k8s_arsenal.models import AttackGraph
    from k8s_arsenal.runtime.identity_flow import IdentityState

from k8s_arsenal.models import AttackTerminalState


# ── unified terminal state function ──────────────────────────────────────


def evaluate_terminal_state(
    identity: "IdentityState",
    capabilities: frozenset[str] | set[str],
    graph: "AttackGraph",
    threshold: str = "standard",
) -> AttackTerminalState:
    """T(S, G, p) → {SAFE, PARTIAL, COMPROMISED}

    Args:
        identity: Current identity state (node + identity_chain).
        capabilities: Accumulated capability set.
        graph: The full AttackGraph (for reachability queries).
        threshold: Compromise threshold name for backward compatibility.

    Returns:
        AttackTerminalState classification.
    """
    caps = frozenset(capabilities) if not isinstance(capabilities, frozenset) else capabilities

    # Empty capabilities → SAFE, regardless of position.
    # Being at a critical asset with zero dangerous capabilities
    # is not "on a trajectory" — you can do nothing.
    if not caps:
        return AttackTerminalState.SAFE

    # ── Rule 1: Hard Compromise ──────────────────────────────────────
    if _is_hard_compromise(caps, threshold):
        return AttackTerminalState.COMPROMISED

    # ── Rule 2: Partial Compromise ──────────────────────────────────
    # At this point caps is non-empty but not hard-compromised.
    # If we're at or can reach a critical asset, we're on a trajectory.
    if _is_partial(identity, graph):
        return AttackTerminalState.PARTIAL

    # ── Rule 3: Safe ────────────────────────────────────────────────
    # Non-empty caps but no connectivity to critical assets → SAFE
    # (benign capabilities only — e.g., list_pods from isolated SA).
    return AttackTerminalState.SAFE


# ── internal predicates ────────────────────────────────────────────────────


def _is_hard_compromise(caps: frozenset[str], threshold: str) -> bool:
    """Check if capabilities already constitute cluster compromise.

    Universal hard signals (any threshold): escalate_rbac, impersonate.
    Threshold-specific: create_pod+exec_pod+read_secret (standard),
    host_access (host/any_host).
    """
    if not caps:
        return False

    # Universal hard-compromise signals.
    _hard_signals: frozenset[str] = frozenset({"escalate_rbac", "impersonate"})
    if caps & _hard_signals:
        return True

    # Threshold-specific checks.
    _thresholds: dict[str, frozenset[str]] = {
        "standard": frozenset({"create_pod", "exec_pod", "read_secret"}),
        "host": frozenset({"host_access"}),
        "rbac_escalation": frozenset({"escalate_rbac"}),
        "any_host": frozenset({"host_access"}),
        "any_impersonate": frozenset({"impersonate"}),
    }

    threshold_set = _thresholds.get(threshold, _thresholds["standard"])
    return threshold_set.issubset(caps)


def _is_partial(identity: "IdentityState", graph: "AttackGraph") -> bool:
    """Check if current identity is on a trajectory toward compromise.

    PARTIAL means: compromise hasn't happened yet, but the attacker is
    either AT a critical asset (one capability-gated step away from
    compromise) or has a reachable path to one.
    """
    from k8s_arsenal.playbook.chains import reachable

    current_node = identity.node

    critical_assets: list[str] = getattr(graph, "critical_assets", None) or []

    if not critical_assets:
        critical_assets = _derive_terminal_nodes(graph)

    if not critical_assets:
        return False

    # At the critical asset itself → launch point (PARTIAL).
    # The capability-gated step is outside the graph model (e.g.,
    # "deploy privileged pod" is a capability action, not a graph edge),
    # so being AT the target with relevant capabilities IS "on a trajectory."
    if current_node in critical_assets:
        return True

    for target in critical_assets:
        if reachable(graph, current_node, target):
            return True

    return False


def _derive_terminal_nodes(graph: "AttackGraph") -> list[str]:
    """Derive terminal nodes from graph topology (sinks: in-edges, no out-edges)."""
    if not hasattr(graph, "edges") or not graph.edges:
        return []

    sources: set[str] = set()
    targets: set[str] = set()
    for edge in graph.edges:
        sources.add(getattr(edge, "source", ""))
        targets.add(getattr(edge, "target", ""))

    terminal = targets - sources
    return sorted(terminal)


# ── backward compatibility ─────────────────────────────────────────────────


def is_compromised(
    capabilities: frozenset[str],
    threshold: str = "standard",
    *,
    _identity: "IdentityState | None" = None,
    _graph: "AttackGraph | None" = None,
) -> bool:
    """Backward-compatible boolean check.

    With _identity+_graph provided: uses full T(S) with graph-aware PARTIAL.
    Without: falls back to capability-only hard-compromise check (v0.5.0).
    """
    if _identity is not None and _graph is not None:
        return (
            evaluate_terminal_state(_identity, capabilities, _graph, threshold)
            == AttackTerminalState.COMPROMISED
        )
    return _is_hard_compromise(capabilities, threshold)
