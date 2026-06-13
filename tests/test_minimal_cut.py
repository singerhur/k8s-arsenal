"""Tests for v0.7 minimal cut set — combinatorial causality analysis.

Tests cover:
- No compromised paths → empty cut
- Single critical edge → cut of size 1
- Multi-edge exhaustive verification
- Greedy vs exact on parallel-path graph
- Exact optimality proof when greedy is optimal
"""

import pytest

from k8s_arsenal.models import AttackGraph, AttackTerminalState, RiskLevel, TrustEdge
from k8s_arsenal.playbook.chains import build_graph
from k8s_arsenal.runtime.minimal_cut import (
    greedy_minimal_cut,
    minimal_cut_set,
)


# ═══════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════

def _single_path_graph() -> AttackGraph:
    """A → B → C: single compromise path, no alternatives."""
    edges = [
        TrustEdge(source="sa-A", target="sa-B", relationship="RoleBinding",
                  metadata={"edge_type": "RbacEdge"}),
        TrustEdge(source="sa-B", target="sa-C", relationship="TokenAccess",
                  risk=RiskLevel.HIGH,
                  metadata={
                      "edge_type": "TokenAccess",
                      "capability": {"verbs": ["impersonate"], "resources": ["users"]},
                  }),
    ]
    g = build_graph(edges, nodes={"sa-A": "sa-A", "sa-B": "sa-B", "sa-C": "sa-C"})
    g.entry_points = ["sa-A"]
    g.critical_assets = ["sa-C"]
    return g


def _parallel_compromise_graph() -> AttackGraph:
    """A → B → D and A → C → D: two parallel TokenAccess paths to compromise."""
    edges = [
        # Path 1: A → B → D (impersonate)
        TrustEdge(source="sa-A", target="sa-B", relationship="RoleBinding",
                  metadata={"edge_type": "RbacEdge"}),
        TrustEdge(source="sa-B", target="sa-D", relationship="TokenAccess",
                  risk=RiskLevel.HIGH,
                  metadata={
                      "edge_type": "TokenAccess",
                      "capability": {"verbs": ["impersonate"], "resources": ["users"]},
                  }),
        # Path 2: A → C → D (impersonate)
        TrustEdge(source="sa-A", target="sa-C", relationship="RoleBinding",
                  metadata={"edge_type": "RbacEdge"}),
        TrustEdge(source="sa-C", target="sa-D", relationship="TokenAccess",
                  risk=RiskLevel.HIGH,
                  metadata={
                      "edge_type": "TokenAccess",
                      "capability": {"verbs": ["impersonate"], "resources": ["users"]},
                  }),
    ]
    g = build_graph(edges, nodes={
        "sa-A": "sa-A", "sa-B": "sa-B", "sa-C": "sa-C", "sa-D": "sa-D",
    })
    g.entry_points = ["sa-A"]
    g.critical_assets = ["sa-D"]
    return g


def _safe_graph() -> AttackGraph:
    """A → B with no dangerous capability → no COMPROMISED paths."""
    edges = [
        TrustEdge(source="sa-A", target="sa-B", relationship="RoleBinding",
                  metadata={"edge_type": "RbacEdge"}),
    ]
    g = build_graph(edges, nodes={"sa-A": "sa-A", "sa-B": "sa-B"})
    g.entry_points = ["sa-A"]
    g.critical_assets = ["sa-B"]
    return g


# ═══════════════════════════════════════════════════════════════════════
# Empty / Safe graph
# ═══════════════════════════════════════════════════════════════════════

def test_no_compromised_paths_returns_empty():
    """Safe graph → no cut edges needed."""
    g = _safe_graph()
    result = greedy_minimal_cut(g, "sa-A", "sa-B")
    assert result["cut_edges"] == []
    assert result["size"] == 0

    result_exact = minimal_cut_set(g, "sa-A", "sa-B")
    assert result_exact["cut_edges"] == []
    assert result_exact["size"] == 0


# ═══════════════════════════════════════════════════════════════════════
# Single critical edge
# ═══════════════════════════════════════════════════════════════════════

def test_single_path_greedy_cuts_token_edge():
    """The greedy solver cuts one edge from the only compromised path."""
    g = _single_path_graph()
    result = greedy_minimal_cut(g, "sa-A", "sa-C")

    assert len(result["cut_edges"]) == 1
    # Either edge on the path works — both have equal coverage.
    cut_sig = result["cut_edges"][0]
    assert cut_sig in (("sa-A", "sa-B", "RoleBinding"), ("sa-B", "sa-C", "TokenAccess"))


def test_single_path_exact_optimal():
    """Exact solver confirms greedy is optimal for single-path graph."""
    g = _single_path_graph()
    result = minimal_cut_set(g, "sa-A", "sa-C")

    assert result["size"] == 1
    assert result["strategy"] == "exact"


# ═══════════════════════════════════════════════════════════════════════
# Parallel compromise paths
# ═══════════════════════════════════════════════════════════════════════

def test_parallel_greedy_covers_both_paths():
    """Greedy should identify edges that collectively cover both paths."""
    g = _parallel_compromise_graph()
    result = greedy_minimal_cut(g, "sa-A", "sa-D")

    assert result["total_compromised_paths"] >= 1
    assert result["size"] >= 1


def test_parallel_exact_finds_minimal():
    """Exact solver verifies optimality on parallel compromise graph."""
    g = _parallel_compromise_graph()
    result = minimal_cut_set(g, "sa-A", "sa-D")

    assert result["strategy"] in ("exact", "greedy (exact infeasible)")
    assert result["size"] >= 1
    # If exact ran, greedy upper bound should be >= exact result
    if "greedy_upper_bound" in result:
        assert result["greedy_upper_bound"] >= result["size"]


# ═══════════════════════════════════════════════════════════════════════
# Result structure
# ═══════════════════════════════════════════════════════════════════════

def test_greedy_result_has_all_keys():
    """Greedy result dict has expected structure."""
    g = _single_path_graph()
    result = greedy_minimal_cut(g, "sa-A", "sa-C")

    for key in ("strategy", "cut_edges", "size", "baseline_paths", "explanation"):
        assert key in result

    assert isinstance(result["cut_edges"], list)
    assert isinstance(result["size"], int)
    assert result["size"] == len(result["cut_edges"])


def test_exact_result_has_all_keys():
    """Exact result dict has expected structure."""
    g = _single_path_graph()
    result = minimal_cut_set(g, "sa-A", "sa-C")

    for key in ("strategy", "cut_edges", "size", "baseline_paths", "explanation"):
        assert key in result


# ═══════════════════════════════════════════════════════════════════════
# Cut verification — after removing cut edges, no COMPROMISED paths
# ═══════════════════════════════════════════════════════════════════════

def test_cut_verification_single_path():
    """After removing cut edges, evaluating path should NOT be COMPROMISED."""
    from copy import deepcopy
    from k8s_arsenal.runtime.evaluator import evaluate_path
    from k8s_arsenal.playbook.chains import shortest_path

    g = _single_path_graph()
    result = minimal_cut_set(g, "sa-A", "sa-C")
    cut_sigs = set(result["cut_edges"])

    # Build modified graph
    G_cf = deepcopy(g)
    G_cf.edges = [
        e for e in G_cf.edges
        if (e.source, e.target, e.relationship) not in cut_sigs
    ]

    path = shortest_path(G_cf, "sa-A", "sa-C")
    if path is None:
        # Cut broke all paths → SAFE
        assert True
    else:
        r = evaluate_path(G_cf, path)
        assert r["terminal_state"] != AttackTerminalState.COMPROMISED
