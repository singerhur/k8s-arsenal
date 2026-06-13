"""Tests for v0.8 Attack Semantics Classifier.

Tests cover:
- All 5 tactic classifications (PRIVILEGE_ESCALATION, PERSISTENCE,
  CREDENTIAL_ACCESS, LATERAL_MOVEMENT, EXECUTION)
- UNKNOWN classification (no matching signals)
- Outcome dimension preserved (does NOT classify CLUSTER_TAKEOVER)
- Evidence extraction correctness
- Confidence scoring
- Edge cases: empty trace, single-node path
"""

import pytest

from k8s_arsenal.models import AttackGraph, AttackTerminalState, RiskLevel, TrustEdge
from k8s_arsenal.playbook.chains import build_graph
from k8s_arsenal.runtime.evaluator import evaluate_path
from k8s_arsenal.runtime.classifier import (
    AttackLabel,
    classify,
    infer_tactic,
)


# ============================================================================
# Graph Fixtures
# ============================================================================


def _escalation_graph() -> AttackGraph:
    """SA with escalate_rbac capability → COMPROMISED."""
    edges = [
        TrustEdge(
            source="attacker-sa",
            target="cluster-admin-binding",
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
    g = build_graph(edges, nodes={
        "attacker-sa": "attacker-sa",
        "cluster-admin-binding": "cluster-admin-binding",
    })
    g.entry_points = ["attacker-sa"]
    g.critical_assets = ["cluster-admin-binding"]
    return g


def _lateral_graph() -> AttackGraph:
    """Identity shift without escalation: SA-A → SA-B via TokenAccess."""
    edges = [
        TrustEdge(
            source="sa-A",
            target="sa-B",
            relationship="TokenAccess",
            risk=RiskLevel.HIGH,
            metadata={
                "edge_type": "TokenAccess",
                "source": "inference",
            },
        ),
        TrustEdge(
            source="sa-B",
            target="sa-C",
            relationship="RoleBinding",
            metadata={
                "edge_type": "RbacEdge",
                "source": "observation",
                "role_rules": [{"verbs": ["get", "list"], "resources": ["pods"], "apiGroups": [""]}],
            },
        ),
    ]
    g = build_graph(edges, nodes={
        "sa-A": "sa-A", "sa-B": "sa-B", "sa-C": "sa-C",
    })
    g.entry_points = ["sa-A"]
    g.critical_assets = ["sa-C"]
    return g


def _credential_graph() -> AttackGraph:
    """Read secrets / steal tokens without escalation."""
    edges = [
        TrustEdge(
            source="attacker-sa",
            target="secret-store",
            relationship="RoleBinding",
            risk=RiskLevel.HIGH,
            metadata={
                "edge_type": "RbacEdge",
                "source": "observation",
                "role_rules": [{"verbs": ["get", "list"], "resources": ["secrets"], "apiGroups": [""]}],
            },
        ),
    ]
    g = build_graph(edges, nodes={
        "attacker-sa": "attacker-sa",
        "secret-store": "secret-store",
    })
    g.entry_points = ["attacker-sa"]
    g.critical_assets = ["secret-store"]
    return g


def _persistence_graph() -> AttackGraph:
    """grant_rbac (create RoleBinding/ClusterRoleBinding)."""
    edges = [
        TrustEdge(
            source="attacker-sa",
            target="rbac-mutator",
            relationship="RoleBinding",
            risk=RiskLevel.HIGH,
            metadata={
                "edge_type": "RbacEdge",
                "source": "observation",
                "role_rules": [
                    {"verbs": ["create"], "resources": ["rolebindings", "clusterrolebindings"], "apiGroups": ["rbac.authorization.k8s.io"]},
                ],
            },
        ),
    ]
    g = build_graph(edges, nodes={
        "attacker-sa": "attacker-sa",
        "rbac-mutator": "rbac-mutator",
    })
    g.entry_points = ["attacker-sa"]
    g.critical_assets = []
    return g


def _execution_graph() -> AttackGraph:
    """create_pod / exec_pod without escalation."""
    edges = [
        TrustEdge(
            source="attacker-sa",
            target="pod-exec",
            relationship="RoleBinding",
            metadata={
                "edge_type": "RbacEdge",
                "source": "observation",
                "role_rules": [{"verbs": ["create", "exec"], "resources": ["pods"], "apiGroups": [""]}],
            },
        ),
    ]
    g = build_graph(edges, nodes={
        "attacker-sa": "attacker-sa",
        "pod-exec": "pod-exec",
    })
    g.entry_points = ["attacker-sa"]
    g.critical_assets = []
    return g


def _empty_graph() -> AttackGraph:
    """No capabilities, identity fixed."""
    edges = [
        TrustEdge(
            source="sa-A",
            target="sa-B",
            relationship="RoleBinding",
            metadata={
                "edge_type": "RbacEdge",
                "source": "observation",
                "role_rules": [{"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}],
            },
        ),
    ]
    g = build_graph(edges, nodes={"sa-A": "sa-A", "sa-B": "sa-B"})
    g.entry_points = ["sa-A"]
    g.critical_assets = []
    return g


# ============================================================================
# PRIVILEGE_ESCALATION
# ============================================================================


def test_privilege_escalation_hard_signal():
    """escalate_rbac capability → PRIVILEGE_ESCALATION, confidence 1.0"""
    g = _escalation_graph()
    trace = evaluate_path(g, ["attacker-sa", "cluster-admin-binding"])
    assert "escalate_rbac" in trace["capabilities"]

    tactic = infer_tactic(trace)
    assert tactic == "PRIVILEGE_ESCALATION"

    label = classify(trace)
    assert label.tactic == "PRIVILEGE_ESCALATION"
    assert label.confidence == 1.0
    assert label.outcome != AttackTerminalState.SAFE


def test_privilege_escalation_with_grant_rbac():
    """grant_rbac + cap growth + PARTIAL → PRIVILEGE_ESCALATION"""
    edges = [
        TrustEdge(
            source="sa-A",
            target="sa-B",
            relationship="RoleBinding",
            metadata={
                "edge_type": "RbacEdge",
                "source": "observation",
                "role_rules": [
                    {"verbs": ["create"], "resources": ["rolebindings", "clusterrolebindings"],
                     "apiGroups": ["rbac.authorization.k8s.io"]},
                ],
            },
        ),
        TrustEdge(
            source="sa-B",
            target="admin-role",
            relationship="RoleBinding",
            risk=RiskLevel.HIGH,
            metadata={
                "edge_type": "RbacEdge",
                "source": "observation",
                "role_rules": [{"verbs": ["impersonate"], "resources": ["users"], "apiGroups": [""]}],
            },
        ),
    ]
    g = build_graph(edges, nodes={"sa-A": "sa-A", "sa-B": "sa-B", "admin-role": "admin-role"})
    g.entry_points = ["sa-A"]
    g.critical_assets = ["admin-role"]

    trace = evaluate_path(g, ["sa-A", "sa-B", "admin-role"])
    # grant_rbac from first edge, impersonate from second → hard escalation
    label = classify(trace)
    assert label.tactic == "PRIVILEGE_ESCALATION"


# ============================================================================
# PERSISTENCE
# ============================================================================


def test_persistence():
    """grant_rbac without escalation → PERSISTENCE"""
    g = _persistence_graph()
    trace = evaluate_path(g, ["attacker-sa", "rbac-mutator"])
    assert "grant_rbac" in trace["capabilities"]

    tactic = infer_tactic(trace)
    assert tactic == "PERSISTENCE"

    label = classify(trace)
    assert label.tactic == "PERSISTENCE"
    assert label.confidence == 0.85
    assert any("grant_rbac" in e for e in label.evidence)


# ============================================================================
# CREDENTIAL_ACCESS
# ============================================================================


def test_credential_access_read_secret():
    """read_secret capability → CREDENTIAL_ACCESS"""
    g = _credential_graph()
    trace = evaluate_path(g, ["attacker-sa", "secret-store"])
    assert "read_secret" in trace["capabilities"]

    tactic = infer_tactic(trace)
    assert tactic == "CREDENTIAL_ACCESS"

    label = classify(trace)
    assert label.tactic == "CREDENTIAL_ACCESS"
    assert label.confidence == 0.9
    assert any("read_secret" in e for e in label.evidence)


def test_credential_access_token_access_edge():
    """TokenAccess edge + read_secret → CREDENTIAL_ACCESS"""
    edges = [
        TrustEdge(
            source="sa-A",
            target="sa-B",
            relationship="TokenAccess",
            risk=RiskLevel.HIGH,
            metadata={
                "edge_type": "TokenAccess",
                "source": "inference",
                "capability": {"verbs": ["get"], "resources": ["secrets"]},
            },
        ),
    ]
    g = build_graph(edges, nodes={"sa-A": "sa-A", "sa-B": "sa-B"})
    g.entry_points = ["sa-A"]
    g.critical_assets = []

    trace = evaluate_path(g, ["sa-A", "sa-B"])
    assert "read_secret" in trace["capabilities"]
    tactic = infer_tactic(trace)
    assert tactic == "CREDENTIAL_ACCESS"

    label = classify(trace)
    assert "token_steal_edge" in " ".join(label.evidence)


# ============================================================================
# LATERAL_MOVEMENT
# ============================================================================


def test_lateral_movement():
    """Identity shift without escalation → LATERAL_MOVEMENT"""
    g = _lateral_graph()
    trace = evaluate_path(g, ["sa-A", "sa-B", "sa-C"])
    assert len(trace["identity_chain"]) > 1

    tactic = infer_tactic(trace)
    assert tactic == "LATERAL_MOVEMENT"

    label = classify(trace)
    assert label.tactic == "LATERAL_MOVEMENT"
    assert label.confidence > 0.5
    assert any("identity_shift" in e for e in label.evidence)


# ============================================================================
# EXECUTION
# ============================================================================


def test_execution():
    """create_pod + exec_pod without escalation → EXECUTION"""
    g = _execution_graph()
    trace = evaluate_path(g, ["attacker-sa", "pod-exec"])
    assert "create_pod" in trace["capabilities"] or "exec_pod" in trace["capabilities"]

    tactic = infer_tactic(trace)
    assert tactic == "EXECUTION"

    label = classify(trace)
    assert label.tactic == "EXECUTION"
    assert label.confidence == 0.7
    assert any("execution_cap" in e for e in label.evidence)


# ============================================================================
# UNKNOWN
# ============================================================================


def test_unknown_no_signals():
    """No recognizable capabilities → UNKNOWN, confidence 0.0"""
    g = _empty_graph()
    trace = evaluate_path(g, ["sa-A", "sa-B"])

    tactic = infer_tactic(trace)
    assert tactic == "UNKNOWN"

    label = classify(trace)
    assert label.tactic == "UNKNOWN"
    assert label.confidence == 0.0


# ============================================================================
# Outcome Dimension (NOT classified)
# ============================================================================


def test_outcome_is_terminal_state_not_classified():
    """AttackLabel.outcome equals T(S), not a classifier output."""
    g = _escalation_graph()
    trace = evaluate_path(g, ["attacker-sa", "cluster-admin-binding"])

    label = classify(trace)
    assert label.outcome == trace["terminal_state"]
    # CLUSTER_TAKEOVER is NOT a tactic value
    assert label.tactic != "CLUSTER_TAKEOVER"


# ============================================================================
# AttackLabel structure
# ============================================================================


def test_attack_label_has_all_fields():
    """AttackLabel contains tactic, outcome, evidence, confidence."""
    g = _escalation_graph()
    trace = evaluate_path(g, ["attacker-sa", "cluster-admin-binding"])

    label = classify(trace)
    assert isinstance(label, AttackLabel)
    assert isinstance(label.tactic, str)
    assert isinstance(label.outcome, AttackTerminalState)
    assert isinstance(label.evidence, list)
    assert isinstance(label.confidence, float)
    assert 0.0 <= label.confidence <= 1.0


# ============================================================================
# Edge Cases
# ============================================================================


def test_empty_trace_no_crash():
    """classify() handles minimal trace gracefully."""
    # Manually construct minimal trace (edge case: only identity info, no caps)
    minimal = {
        "final_identity": "sa-X",
        "identity_chain": ["sa-X"],
        "capabilities": set(),
        "trace": [],
        "terminal_state": AttackTerminalState.SAFE,
    }
    label = classify(minimal)
    assert label.tactic == "UNKNOWN"
    assert label.outcome == AttackTerminalState.SAFE
    assert label.confidence == 0.0
