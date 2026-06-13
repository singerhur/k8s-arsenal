"""Tests for v0.9 architectural invariants.

CI gate:  pytest -m invariants
"""

import pytest

pytestmark = pytest.mark.invariants

from copy import deepcopy

from k8s_arsenal.models import (
    AttackGraph,
    AttackTerminalState,
    EdgeSource,
    RiskLevel,
    TrustEdge,
)
from k8s_arsenal.playbook.chains import build_graph, shortest_path, reachable
from k8s_arsenal.runtime.evaluator import evaluate_path
from k8s_arsenal.runtime.classifier import AttackLabel, classify, infer_tactic
from k8s_arsenal.runtime.invariants import (
    # v0.5.1 terminal-state
    assert_terminal_state_valid,
    # v0.8 classifier
    assert_tactic_label_valid,
    assert_attack_label_dimensions_separated,
    assert_classify_produces_valid_label,
    assert_confidence_in_range,
    # v0.5 identity
    assert_identity_chain_non_empty,
    assert_identity_only_changes_on_defined_edges,
    assert_identity_chain_grows_monotonically,
    # v0.5 capabilities
    assert_capability_set_monotonic,
    assert_capability_is_atomic,
    # v0.5 evaluator
    assert_evaluate_path_result_structure,
    # v0.4 graph
    assert_shortest_path_valid,
    assert_reachable_returns_bool,
    # v0.6 counterfactual
    assert_counterfactual_result_structure,
    assert_counterfactual_no_mutation,
    # v0.7 MCS
    assert_mcs_result_structure,
    assert_mcs_exact_not_larger_than_greedy,
    # global
    validate_trace_result,
)


# ═══════════════════════════════════════════════════════════════════════
# helpers
# ═══════════════════════════════════════════════════════════════════════

def _simple_graph() -> AttackGraph:
    """sa-A → sa-B (TokenAccess) → sa-C (RoleBinding, escalate_rbac)."""
    edges = [
        TrustEdge(
            source="sa-A",
            target="sa-B",
            relationship="TokenAccess",
            risk=RiskLevel.HIGH,
            metadata={"edge_type": "TokenAccess", "source": "inference"},
        ),
        TrustEdge(
            source="sa-B",
            target="sa-C",
            relationship="RoleBinding",
            risk=RiskLevel.CRITICAL,
            metadata={
                "edge_type": "RbacEdge",
                "source": "observation",
                "role_rules": [
                    {"verbs": ["escalate"], "resources": ["clusterroles"], "apiGroups": ["rbac.authorization.k8s.io"]}
                ],
            },
        ),
    ]
    g = build_graph(edges, nodes={"sa-A": "sa-A", "sa-B": "sa-B", "sa-C": "sa-C"})
    g.entry_points = ["sa-A"]
    g.critical_assets = ["sa-C"]
    return g


# ═══════════════════════════════════════════════════════════════════════
# v0.5.1 — terminal state
# ═══════════════════════════════════════════════════════════════════════

def test_valid_terminal_states_pass():
    for state in AttackTerminalState:
        assert_terminal_state_valid(state)  # no raise


def test_invalid_terminal_state_caught(monkeypatch):
    class FakeState:
        value = "unknown"
    fake = FakeState()
    with pytest.raises(AssertionError, match="unknown"):
        assert_terminal_state_valid(fake)  # type: ignore[arg-type]


# ═══════════════════════════════════════════════════════════════════════
# v0.8 — classifier
# ═══════════════════════════════════════════════════════════════════════

def test_valid_tactics_pass():
    for t in ["PRIVILEGE_ESCALATION", "PERSISTENCE", "CREDENTIAL_ACCESS",
              "LATERAL_MOVEMENT", "EXECUTION", "UNKNOWN"]:
        assert_tactic_label_valid(t)


def test_forbidden_tactic_rejected():
    for bad in ["CLUSTER_TAKEOVER", "safe", "partial", "compromised", "BANANA"]:
        with pytest.raises(AssertionError):
            assert_tactic_label_valid(bad)


def test_attack_label_dimensions_ok():
    label = AttackLabel(tactic="PRIVILEGE_ESCALATION", outcome=AttackTerminalState.COMPROMISED)
    assert_attack_label_dimensions_separated(label)


def test_attack_label_outcome_not_a_terminal_state_rejected():
    label = AttackLabel(tactic="PRIVILEGE_ESCALATION", outcome="safe")  # type: ignore[arg-type]
    with pytest.raises(AssertionError, match="AttackTerminalState"):
        assert_attack_label_dimensions_separated(label)


def test_attack_label_tactic_is_terminal_rejected():
    label = AttackLabel(tactic="safe", outcome=AttackTerminalState.COMPROMISED)
    with pytest.raises(AssertionError, match="terminal-state"):
        assert_attack_label_dimensions_separated(label)


def test_classify_produces_valid_label():
    g = _simple_graph()
    tr = evaluate_path(g, ["sa-A", "sa-B", "sa-C"])
    assert_classify_produces_valid_label(tr)


def test_confidence_out_of_range_rejected():
    with pytest.raises(AssertionError):
        assert_confidence_in_range(1.5)
    with pytest.raises(AssertionError):
        assert_confidence_in_range(-0.1)
    assert_confidence_in_range(0.0)  # ok
    assert_confidence_in_range(1.0)  # ok


# ═══════════════════════════════════════════════════════════════════════
# v0.5 — identity flow
# ═══════════════════════════════════════════════════════════════════════

def test_identity_chain_non_empty():
    assert_identity_chain_non_empty(["sa-A"])
    with pytest.raises(AssertionError, match="empty"):
        assert_identity_chain_non_empty([])


def test_identity_chain_grows_monotonically_ok():
    assert_identity_chain_grows_monotonically(["sa-A", "sa-B", "sa-C"])


def test_identity_chain_duplicate_adjacent_rejected():
    with pytest.raises(AssertionError):
        assert_identity_chain_grows_monotonically(["sa-A", "sa-A", "sa-B"])


def test_identity_only_changes_on_defined_edges():
    g = _simple_graph()
    tr = evaluate_path(g, ["sa-A", "sa-B", "sa-C"])
    assert_identity_only_changes_on_defined_edges(tr["trace"], tr["identity_chain"])


def test_identity_change_on_wrong_edge_rejected():
    """Trace where non-transition edge causes identity change → violation."""
    bad_trace = [
        {"identity": "sa-A", "edge_type": "RbacEdge", "capabilities": []},
        {"identity": "sa-B", "edge_type": "RbacEdge", "capabilities": []},  # changed but NOT TokenAccess/Impersonate
    ]
    with pytest.raises(AssertionError, match="TokenAccess"):
        assert_identity_only_changes_on_defined_edges(bad_trace, ["sa-A", "sa-B"])


# ═══════════════════════════════════════════════════════════════════════
# v0.5 — capabilities
# ═══════════════════════════════════════════════════════════════════════

def test_capability_set_monotonic():
    trace = [
        {"capabilities": ["create_pod"]},
        {"capabilities": ["create_pod", "exec_pod"]},
    ]
    assert_capability_set_monotonic(trace)


def test_capability_regression_rejected():
    trace = [
        {"capabilities": ["create_pod", "exec_pod"]},
        {"capabilities": ["create_pod"]},
    ]
    with pytest.raises(AssertionError, match="regression"):
        assert_capability_set_monotonic(trace)


def test_capability_is_atomic():
    assert_capability_is_atomic({"create_pod", "exec_pod"})


def test_capability_composite_rejected():
    with pytest.raises(AssertionError, match="CLUSTER_TAKEOVER"):
        assert_capability_is_atomic({"create_pod", "CLUSTER_TAKEOVER"})


# ═══════════════════════════════════════════════════════════════════════
# v0.5 — evaluator
# ═══════════════════════════════════════════════════════════════════════

def test_evaluate_path_result_structure():
    g = _simple_graph()
    tr = evaluate_path(g, ["sa-A", "sa-B", "sa-C"])
    assert_evaluate_path_result_structure(tr)


def test_evaluate_path_missing_key_rejected():
    bad = {"final_identity": "sa-A"}  # missing identity_chain, capabilities, etc.
    with pytest.raises(AssertionError, match="missing"):
        assert_evaluate_path_result_structure(bad)


# ═══════════════════════════════════════════════════════════════════════
# v0.4 — graph
# ═══════════════════════════════════════════════════════════════════════

def test_shortest_path_valid():
    g = _simple_graph()
    sp = shortest_path(g, "sa-A", "sa-C")
    assert_shortest_path_valid(sp)


def test_shortest_path_accepts_none():
    assert_shortest_path_valid(None)  # unreachable = valid


def test_shortest_path_rejects_non_list():
    with pytest.raises(AssertionError):
        assert_shortest_path_valid("not-a-list")


def test_reachable_returns_bool():
    g = _simple_graph()
    r = reachable(g, "sa-A", "sa-C")
    assert_reachable_returns_bool(r)


def test_reachable_rejects_non_bool():
    with pytest.raises(AssertionError):
        assert_reachable_returns_bool(42)


# ═══════════════════════════════════════════════════════════════════════
# v0.6 — counterfactual
# ═══════════════════════════════════════════════════════════════════════

def test_counterfactual_result_structure():
    g = _simple_graph()
    from k8s_arsenal.runtime.counterfactual import counterfactual
    edge = g.edges[0]
    result = counterfactual(g, edge, "sa-A", "sa-C")
    assert_counterfactual_result_structure(result)


def test_counterfactual_no_mutation():
    g = _simple_graph()
    edge = g.edges[0]
    assert_counterfactual_no_mutation(g, edge)
    # verify: graph still untouched
    assert len(g.edges) == 2


# ═══════════════════════════════════════════════════════════════════════
# v0.7 — MCS
# ═══════════════════════════════════════════════════════════════════════

def test_mcs_result_structure():
    g = _simple_graph()
    from k8s_arsenal.runtime.minimal_cut import greedy_minimal_cut
    result = greedy_minimal_cut(g, "sa-A", "sa-C")
    assert_mcs_result_structure(result)


def test_mcs_exact_not_larger_than_greedy_ok():
    assert_mcs_exact_not_larger_than_greedy(3, 2)


def test_mcs_exact_larger_than_greedy_rejected():
    with pytest.raises(AssertionError, match="upper bound"):
        assert_mcs_exact_not_larger_than_greedy(2, 3)


# ═══════════════════════════════════════════════════════════════════════
# global runner
# ═══════════════════════════════════════════════════════════════════════

def test_validate_trace_result_all_pass():
    g = _simple_graph()
    tr = evaluate_path(g, ["sa-A", "sa-B", "sa-C"])
    violations = validate_trace_result(tr)
    assert violations == [], f"Unexpected violations: {violations}"


def test_validate_trace_result_detects_broken():
    bad_tr = {
        "final_identity": "sa-A",
        # missing identity_chain etc.
    }
    violations = validate_trace_result(bad_tr)
    # should catch missing keys
    assert len(violations) > 0
