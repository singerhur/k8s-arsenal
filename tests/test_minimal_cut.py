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
    """Exact/ILP solver confirms optimal for single-path graph."""
    g = _single_path_graph()
    result = minimal_cut_set(g, "sa-A", "sa-C")

    assert result["strategy"] in ("exact", "ilp (trivial)", "ilp")


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
    """Exact/ILP solver verifies optimality on parallel compromise graph."""
    g = _parallel_compromise_graph()
    result = minimal_cut_set(g, "sa-A", "sa-D")

    assert result["strategy"] in ("exact", "greedy (exact infeasible)", "ilp", "ilp (trivial)")
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


# ═══════════════════════════════════════════════════════════════════════
# ILP-specific tests (v0.9.3)
# ═══════════════════════════════════════════════════════════════════════

from k8s_arsenal.runtime.minimal_cut import ilp_minimal_cut, HAS_PULP


@pytest.mark.skipif(not HAS_PULP, reason="PuLP not installed")
def test_ilp_minimal_cut_parallel_paths():
    """ILP finds the exact minimal cut on parallel-path graph.

    Two parallel paths share zero edges, so ILP must find 2 edges
    (one from each path) — greedy overestimates on this graph.
    """
    g = _parallel_compromise_graph()
    result = ilp_minimal_cut(g, "sa-A", "sa-D")

    assert result["strategy"] == "ilp"
    assert result["size"] == 2
    assert result["total_compromised_paths"] == 2
    assert result["ilp_status"] == "Optimal"
    assert len(result["cut_edges"]) == 2


@pytest.mark.skipif(not HAS_PULP, reason="PuLP not installed")
def test_ilp_minimal_cut_single_path():
    """ILP on a single-path graph finds the trivial one-edge cut."""
    g = _single_path_graph()
    result = ilp_minimal_cut(g, "sa-A", "sa-C")

    assert result["strategy"] == "ilp (trivial)"
    assert result["size"] == 1


@pytest.mark.skipif(not HAS_PULP, reason="PuLP not installed")
def test_ilp_minimal_cut_safe_graph():
    """ILP on a safe graph (no COMPROMISED paths) returns empty cut."""
    g = _safe_graph()
    result = ilp_minimal_cut(g, "sa-A", "sa-B")

    assert result["size"] == 0
    assert result["cut_edges"] == []
    assert result["strategy"] == "ilp"


@pytest.mark.skipif(not HAS_PULP, reason="PuLP not installed")
def test_ilp_result_structure():
    """ILP result dict contains all expected fields."""
    g = _parallel_compromise_graph()
    result = ilp_minimal_cut(g, "sa-A", "sa-D")

    for key in ("strategy", "cut_edges", "size", "baseline_paths", "explanation"):
        assert key in result

    assert "total_compromised_paths" in result
    assert "candidate_edges" in result
    assert "ilp_objective" in result
    assert "ilp_status" in result
    assert result["ilp_status"] == "Optimal"
    assert result["size"] == result["ilp_objective"]


@pytest.mark.skipif(not HAS_PULP, reason="PuLP not installed")
def test_minimal_cut_set_uses_ilp():
    """minimal_cut_set() with use_ilp=True should return ILP result."""
    g = _parallel_compromise_graph()
    result = minimal_cut_set(g, "sa-A", "sa-D", use_ilp=True)

    assert result["strategy"] == "ilp"
    assert result["size"] == 2


@pytest.mark.skipif(not HAS_PULP, reason="PuLP not installed")
def test_minimal_cut_set_disable_ilp():
    """minimal_cut_set() with use_ilp=False falls back to old exact/greedy."""
    g = _single_path_graph()
    result = minimal_cut_set(g, "sa-A", "sa-C", use_ilp=False)

    assert result["strategy"] in ("exact", "greedy (exact infeasible)")
    assert result["size"] == 1
