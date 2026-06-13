"""Tests for identity_flow — identity transition tracking."""

import pytest

from k8s_arsenal.models import RiskLevel, TrustEdge
from k8s_arsenal.runtime import IdentityState, propagate_identity


# --- Fixtures ---------------------------------------------------------------

def _edge(src: str, dst: str, edge_type: str, **meta) -> TrustEdge:
    return TrustEdge(
        source=src,
        target=dst,
        relationship=edge_type,
        risk=RiskLevel.MEDIUM,
        metadata={"edge_type": edge_type, **meta},
    )


# --- IdentityState ----------------------------------------------------------

def test_identity_state_default():
    s = IdentityState(node="sa-1")
    assert s.node == "sa-1"
    assert s.identity_chain == ["sa-1"]


def test_identity_state_explicit_chain():
    s = IdentityState(node="sa-3", identity_chain=["sa-1", "sa-2", "sa-3"])
    assert s.identity_chain == ["sa-1", "sa-2", "sa-3"]


# --- Identity Transitions ---------------------------------------------------

def test_no_transition_on_regular_edge():
    """Non-transition edges leave identity unchanged."""
    edge = _edge("sa-A", "role-A", "RbacEdge")
    state = IdentityState(node="sa-A")

    result = propagate_identity(edge, state)
    assert result.node == "sa-A"  # Identity unchanged
    # No transition — state returned unchanged, chain does not grow
    assert result.identity_chain == ["sa-A"]


def test_transition_on_token_access():
    """TokenAccess edges trigger identity transition."""
    edge = _edge("sa-A", "sa-B", "TokenAccess")
    state = IdentityState(node="sa-A")

    result = propagate_identity(edge, state)
    assert result.node == "sa-B"
    assert result.identity_chain == ["sa-A", "sa-B"]


def test_transition_on_impersonate():
    """Impersonate edges trigger identity transition."""
    edge = _edge("sa-A", "kubelet", "Impersonate")
    state = IdentityState(node="sa-A")

    result = propagate_identity(edge, state)
    assert result.node == "kubelet"
    assert result.identity_chain == ["sa-A", "kubelet"]


# --- Multi-step Identity Chain ----------------------------------------------

def test_multi_step_identity_chain():
    """Scenario C style: SA → SA → SA → kubelet via TokenAccess + Impersonate."""
    edges = [
        _edge("ci-pipeline-sa", "prod-app-sa", "TokenAccess"),
        _edge("prod-app-sa", "monitoring-operator-sa", "TokenAccess"),
        _edge("monitoring-operator-sa", "kubelet", "Impersonate"),
    ]

    state = IdentityState(node="ci-pipeline-sa")
    for edge in edges:
        state = propagate_identity(edge, state)

    assert state.node == "kubelet"
    assert state.identity_chain == [
        "ci-pipeline-sa",
        "prod-app-sa",
        "monitoring-operator-sa",
        "kubelet",
    ]


def test_all_non_transition_edges_preserve_identity():
    """All edges that are not TokenAccess/Impersonate preserve identity."""
    non_transition_types = [
        "RbacEdge",
        "SemanticBridge",
        "DefaultEdge",
        "ClientCert",
        "",
        "SomeCustomType",
    ]

    for edge_type in non_transition_types:
        edge = _edge("sa-A", f"node-{edge_type}", edge_type)
        state = IdentityState(node="sa-A")
        result = propagate_identity(edge, state)
        # Non-transition edges: identity stays at "sa-A"
        assert result.node == "sa-A"
        assert result.identity_chain == ["sa-A"]


# --- Edge Cases -------------------------------------------------------------

def test_identity_preserved_on_empty_metadata():
    """Edge with no metadata (no edge_type) does not trigger transition."""
    edge = TrustEdge(
        source="sa-A",
        target="role-X",
        relationship="RbacEdge",
        metadata={},
    )
    state = IdentityState(node="sa-A")
    result = propagate_identity(edge, state)
    assert result.node == "sa-A"  # Identity unchanged
    assert result.identity_chain == ["sa-A"]


def test_identity_chain_always_grows():
    """Every step adds one entry to the chain — no shrinking."""
    edges = [
        _edge("A", "B", "TokenAccess"),
        _edge("B", "C", "RbacEdge"),
        _edge("C", "D", "TokenAccess"),
    ]
    state = IdentityState(node="A")
    assert len(state.identity_chain) == 1
    for edge in edges:
        state = propagate_identity(edge, state)
    assert len(state.identity_chain) == 3  # 1 initial + 2 transitions (non-transitions don't grow)
