"""Minimal Cut Set — combinatorial causality analysis.

v0.7: find minimal E' ⊂ E s.t. T(S(G - E')) != COMPROMISED.

Extends v0.6 from single-edge counterfactual to set-level causality
by solving a hitting-set problem over compromised witness paths.
"""

from __future__ import annotations

from itertools import combinations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from k8s_arsenal.models import AttackGraph

from k8s_arsenal.models import AttackTerminalState
from k8s_arsenal.runtime.evaluator import evaluate_path


# ═══════════════════════════════════════════════════════════════════════
# internal: enumerate all COMPROMISED simple paths from start → target
# ═══════════════════════════════════════════════════════════════════════


def _all_compromised_paths(
    graph: "AttackGraph",
    start: str,
    target: str,
    threshold: str,
    max_paths: int = 1000,
) -> list[tuple[list[str], list[tuple[str, str, str]]]]:
    """DFS-enumerate simple paths; keep those with T(S) == COMPROMISED.

    Returns list of (node_path, edge_path) where edge_path is
    (source, target, relationship) tuples.
    """
    adj: dict[str, list[tuple[str, object]]] = {}
    for e in graph.edges:
        adj.setdefault(e.source, []).append((e.target, e))

    results: list[tuple[list[str], list[tuple[str, str, str]]]] = []

    def dfs(nodes: list[str], edge_sig: list[tuple[str, str, str]]):
        if len(results) >= max_paths:
            return
        current = nodes[-1]
        if current == target:
            result = evaluate_path(graph, list(nodes), compromise_threshold=threshold)
            if result["terminal_state"] == AttackTerminalState.COMPROMISED:
                results.append((list(nodes), list(edge_sig)))
            return
        for nxt, edge in adj.get(current, []):
            if nxt not in nodes:
                sig = (edge.source, edge.target, edge.relationship)
                nodes.append(nxt)
                edge_sig.append(sig)
                dfs(nodes, edge_sig)
                nodes.pop()
                edge_sig.pop()

    dfs([start], [])
    return results


# ═══════════════════════════════════════════════════════════════════════
# internal: edge-path incidence helper
# ═══════════════════════════════════════════════════════════════════════


def _incidence(paths: list[list[tuple[str, str, str]]]) -> dict[
    tuple[str, str, str], set[int]
]:
    """Build edge → {path indices} incidence map."""
    inc: dict[tuple[str, str, str], set[int]] = {}
    for i, edge_path in enumerate(paths):
        for sig in edge_path:
            inc.setdefault(sig, set()).add(i)
    return inc


# ═══════════════════════════════════════════════════════════════════════
# Greedy MCS (baseline, ~40 lines)
# ═══════════════════════════════════════════════════════════════════════


def greedy_minimal_cut(
    graph: "AttackGraph",
    start: str,
    target: str,
    threshold: str = "standard",
) -> dict:
    """Greedy hitting-set over COMPROMISED paths.

    Iteratively removes the edge covering the most remaining
    compromised paths until T(S) != COMPROMISED.
    """
    paths_comp = _all_compromised_paths(graph, start, target, threshold)
    if not paths_comp:
        return {
            "strategy": "greedy",
            "cut_edges": [],
            "size": 0,
            "baseline_paths": [],
            "explanation": "No COMPROMISED paths exist; cut set is empty.",
        }

    edge_paths = _incidence([ep for _, ep in paths_comp])
    uncovered: set[int] = set(range(len(paths_comp)))
    cut: list[tuple[str, str, str]] = []

    while uncovered:
        best_edge = max(
            edge_paths.items(),
            key=lambda kv: len(kv[1] & uncovered),
        )
        hit = best_edge[1] & uncovered
        if not hit:
            break
        cut.append(best_edge[0])
        uncovered -= hit

    node_paths = [np for np, _ in paths_comp]
    return {
        "strategy": "greedy",
        "cut_edges": cut,
        "size": len(cut),
        "paths_cut": len(node_paths) - len(uncovered),
        "total_compromised_paths": len(node_paths),
        "baseline_paths": node_paths,
        "explanation": (
            f"Greedy cut of {len(cut)} edge(s) neutralizes "
            f"{len(node_paths) - len(uncovered)}/{len(node_paths)} COMPROMISED paths"
        ),
    }


# ═══════════════════════════════════════════════════════════════════════
# Exact MCS (subset search, pruned by greedy bound)
# ═══════════════════════════════════════════════════════════════════════


def minimal_cut_set(
    graph: "AttackGraph",
    start: str,
    target: str,
    threshold: str = "standard",
    max_brute_force_edges: int = 28,
) -> dict:
    """Exact minimum cardinality hitting set via subset enumeration.

    Uses greedy result as upper bound for pruning. Falls back to
    greedy-only for graphs with too many candidate edges.
    """
    paths_comp = _all_compromised_paths(graph, start, target, threshold)
    if not paths_comp:
        return {
            "strategy": "exact",
            "cut_edges": [],
            "size": 0,
            "baseline_paths": [],
            "explanation": "No COMPROMISED paths exist.",
        }

    edge_paths = _incidence([ep for _, ep in paths_comp])
    candidate_edges = list(edge_paths.keys())
    node_paths = [np for np, _ in paths_comp]

    # greedy gives upper bound
    greedy = greedy_minimal_cut(graph, start, target, threshold)

    if len(candidate_edges) > max_brute_force_edges:
        return {
            **greedy,
            "strategy": "greedy (exact infeasible)",
            "note": f"Edge count ({len(candidate_edges)}) exceeds brute-force limit ({max_brute_force_edges}).",
        }

    upper_bound = greedy["size"]
    if upper_bound <= 1:
        return {**greedy, "strategy": "exact", "note": "Trivial — greedy already optimal."}

    # enumerate subsets from size 1 to upper_bound - 1
    n_paths = len(paths_comp)
    for k in range(1, upper_bound):
        for subset in combinations(range(len(candidate_edges)), k):
            # check: does this subset hit every compromised path?
            covered: set[int] = set()
            for idx in subset:
                covered |= edge_paths[candidate_edges[idx]]
            if len(covered) == n_paths:
                cut = [candidate_edges[i] for i in subset]
                return {
                    "strategy": "exact",
                    "cut_edges": cut,
                    "size": len(cut),
                    "baseline_paths": node_paths,
                    "total_compromised_paths": n_paths,
                    "greedy_upper_bound": upper_bound,
                    "explanation": (
                        f"Exact minimal cut: {len(cut)} edge(s). "
                        f"Greedy used {upper_bound} edge(s) (bound applied)."
                    ),
                }

    # no subset smaller than greedy found → greedy IS optimal
    return {
        **greedy,
        "strategy": "exact",
        "note": "Greedy solution is provably optimal (exhaustive verified).",
    }


# ═══════════════════════════════════════════════════════════════════════
# MCS Counterfactual Verification Gate (v0.9.2)
# ═══════════════════════════════════════════════════════════════════════


def verify_cut_set(
    graph: "AttackGraph",
    cut_edges: list[tuple[str, str, str]],
    start: str,
    target: str,
    threshold: str = "standard",
) -> tuple[bool, str]:
    """Verify that removing all cut edges neutralizes all COMPROMISED paths.

    This is the counterfactual gate for MCS: if MCS says "these edges are the
    minimal cut," we verify by actually removing them and re-checking T(S).
    A passing verification means the cut set is sufficient (though not
    necessarily minimal — that's proven by the subset enumeration in
    minimal_cut_set).

    Args:
        graph: The original AttackGraph.
        cut_edges: Cut set as (source, target, relationship) tuples.
        start: Start/entry node.
        target: Target/critical asset node.
        threshold: Compromise threshold.

    Returns:
        (verified: bool, note: str). verified=True means zero COMPROMISED
        paths remain after removing all cut edges.
    """
    from copy import deepcopy
    from k8s_arsenal.playbook.chains import shortest_path
    from k8s_arsenal.runtime.evaluator import evaluate_path
    from k8s_arsenal.models import AttackTerminalState

    if not cut_edges:
        return True, "Empty cut set — nothing to verify."

    # Build counterfactual graph with all cut edges removed.
    G_cf = deepcopy(graph)
    cut_set = set(cut_edges)
    G_cf.edges = [
        e for e in G_cf.edges
        if (e.source, e.target, e.relationship) not in cut_set
    ]

    # Enumerate all simple paths in the cut graph and check T(S).
    compromised_found = 0
    paths_checked = 0

    # Use DFS enumeration (same pattern as _all_compromised_paths).
    adj: dict[str, list[tuple[str, object]]] = {}
    for e in G_cf.edges:
        adj.setdefault(e.source, []).append((e.target, e))

    def dfs(nodes: list[str]):
        nonlocal compromised_found, paths_checked
        if compromised_found >= 3:  # Early exit after finding a few failures.
            return
        current = nodes[-1]
        if current == target:
            paths_checked += 1
            result = evaluate_path(G_cf, list(nodes), compromise_threshold=threshold)
            if result["terminal_state"] == AttackTerminalState.COMPROMISED:
                compromised_found += 1
            return
        for nxt, _ in adj.get(current, []):
            if nxt not in nodes:
                nodes.append(nxt)
                dfs(nodes)
                nodes.pop()

    dfs([start])

    if compromised_found > 0:
        return False, (
            f"MCS verification FAILED: {compromised_found} COMPROMISED path(s) "
            f"remain after removing {len(cut_edges)} edge(s). "
            f"({paths_checked} paths checked). Cut set is INCOMPLETE."
        )

    return True, (
        f"MCS verified: removing {len(cut_edges)} edge(s) neutralizes "
        f"all COMPROMISED paths ({paths_checked} checked, 0 compromised). "
        f"Cut set is sufficient."
    )
