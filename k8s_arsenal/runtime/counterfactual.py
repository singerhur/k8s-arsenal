"""Counterfactual kernel — delta-T(S) causality analysis.

v0.6: remove edge → recompute T(S) → delta explanation.

AttackGraph = differentiable security system over discrete graph space:
  delta : G x e → delta_T
"""

from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from k8s_arsenal.models import AttackGraph, AttackTerminalState, TrustEdge

from k8s_arsenal.models import AttackTerminalState
from k8s_arsenal.playbook.chains import shortest_path
from k8s_arsenal.runtime.evaluator import evaluate_path


def counterfactual(
    graph: "AttackGraph",
    edge_to_remove: "TrustEdge",
    start_node: str,
    target_node: str,
    threshold: str = "standard",
) -> dict:
    """delta-T(S): causal impact of removing a trust edge.

    delta-T = T(S, G') - T(S, G)  where  G' = G / {edge_to_remove}

    Returns dict with baseline/counterfactual paths + terminal states
    + delta semantics (became_safe, became_compromised, explanation).
    """
    # 1 — baseline
    path0 = shortest_path(graph, start_node, target_node)
    if path0 is None:
        raise ValueError(f"No path from {start_node} to {target_node}")

    result0 = evaluate_path(graph, path0, compromise_threshold=threshold)
    T0 = result0["terminal_state"]

    # 2 — counterfactual world: deep copy + edge removal
    G_cf = deepcopy(graph)
    G_cf.edges = [
        e
        for e in G_cf.edges
        if not (
            e.source == edge_to_remove.source
            and e.target == edge_to_remove.target
            and e.relationship == edge_to_remove.relationship
        )
    ]

    # 3 — re-evaluate under modified graph
    path1 = shortest_path(G_cf, start_node, target_node)
    if path1 is None:
        # Edge removal broke all paths — critical dependency.
        return _result(edge_to_remove, path0, T0, None, AttackTerminalState.SAFE)

    result1 = evaluate_path(G_cf, path1, compromise_threshold=threshold)
    T1 = result1["terminal_state"]

    # 4 — delta semantics
    return _result(edge_to_remove, path0, T0, path1, T1)


def _result(
    edge: "TrustEdge",
    path0: list[str],
    T0: "AttackTerminalState",
    path1: list[str] | None,
    T1: "AttackTerminalState",
) -> dict:
    became_safe = (T0, T1) == (AttackTerminalState.COMPROMISED, AttackTerminalState.SAFE)
    became_compromised = (T0, T1) == (AttackTerminalState.SAFE, AttackTerminalState.COMPROMISED)

    if T0 == T1:
        explain = (
            f"Non-critical: {edge.source}→{edge.target} removal "
            f"preserves {T0.value} state — alternative path exists"
        )
    elif path1 is None:
        explain = (
            f"Critical: {edge.source}→{edge.target} removal breaks "
            f"all paths to target — {T0.value} → SAFE"
        )
    elif T0 == AttackTerminalState.COMPROMISED and T1 != AttackTerminalState.COMPROMISED:
        explain = (
            f"Mitigation: {edge.source}→{edge.target} degrades "
            f"COMPROMISED → {T1.value} — one risk vector neutralized"
        )
    elif T1 == AttackTerminalState.COMPROMISED:
        explain = (
            f"Paradox: {edge.source}→{edge.target} removal surfaces "
            f"new COMPROMISED path — edge was a false-positive dependency"
        )
    else:
        explain = f"Shift: {T0.value} → {T1.value}"

    return {
        "edge": (edge.source, edge.target, edge.relationship),
        "baseline_path": path0,
        "baseline_state": T0,
        "counterfactual_path": path1,
        "counterfactual_state": T1,
        "delta": {
            "became_safe": became_safe,
            "became_compromised": became_compromised,
            "state_change": (T0, T1),
            "explanation": explain,
        },
    }
