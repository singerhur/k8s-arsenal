"""Tests for capability_set — capability accumulation and composition check."""

import pytest

from k8s_arsenal.models import RiskLevel, TrustEdge
from k8s_arsenal.runtime import (
    CapabilityState,
    update_capability,
)


# --- Fixtures ---------------------------------------------------------------

def _edge(meta: dict) -> TrustEdge:
    return TrustEdge(
        source="sa-A",
        target="sa-B",
        relationship="SemanticBridge",
        risk=RiskLevel.MEDIUM,
        metadata=meta,
    )


# --- CapabilityState --------------------------------------------------------

def test_capability_state_empty():
    s = CapabilityState()
    assert s.capabilities == set()
    assert s.has("create_pod") is False


def test_capability_state_has():
    s = CapabilityState(capabilities={"create_pod", "read_secret"})
    assert s.has("create_pod") is True
    assert s.has("read_secret") is True
    assert s.has("impersonate") is False


# --- Capability Extraction --------------------------------------------------

def test_extract_from_capability_metadata():
    """Inference edge with explicit capability annotation."""
    edge = _edge({"capability": {"verbs": ["create"], "resources": ["pods"]}})
    state = CapabilityState()
    state = update_capability(state, edge)
    assert state.capabilities == {"create_pod"}


def test_extract_from_role_rules():
    """Observation edge with raw Role rules."""
    edge = _edge({"role_rules": [{"verbs": ["get"], "resources": ["secrets"], "apiGroups": [""]}]})
    state = CapabilityState()
    state = update_capability(state, edge)
    assert state.capabilities == {"read_secret"}


def test_extract_multiple_capabilities():
    """Single rule with multiple (verb, resource) combinations."""
    edge = _edge(
        {
            "capability": {
                "verbs": ["create", "exec"],
                "resources": ["pods"],
            }
        }
    )
    state = CapabilityState()
    state = update_capability(state, edge)
    assert state.capabilities == {"create_pod", "exec_pod"}


def test_extract_multiple_resources():
    """Single verb across multiple resources."""
    edge = _edge(
        {
            "role_rules": [
                {"verbs": ["get"], "resources": ["secrets", "serviceaccounts"]}
            ]
        }
    )
    state = CapabilityState()
    state = update_capability(state, edge)
    assert state.capabilities == {"read_secret", "steal_token"}


def test_unknown_capability_ignored():
    """Capabilities not in CAPABILITY_MAP are silently skipped."""
    edge = _edge({"role_rules": [{"verbs": ["list"], "resources": ["namespaces"]}]})
    state = CapabilityState()
    state = update_capability(state, edge)
    assert state.capabilities == set()


# --- Cumulative Accumulation ------------------------------------------------

def test_cumulative_across_edges():
    """Capabilities accumulate across multiple edges."""
    edges = [
        _edge({"capability": {"verbs": ["create"], "resources": ["pods"]}}),
        _edge({"role_rules": [{"verbs": ["get"], "resources": ["secrets"]}]}),
        _edge({"capability": {"verbs": ["exec"], "resources": ["pods"]}}),
    ]
    state = CapabilityState()
    for edge in edges:
        state = update_capability(state, edge)

    assert state.capabilities == {"create_pod", "read_secret", "exec_pod"}


def test_no_duplicates():
    """Same capability from multiple sources does not duplicate."""
    edges = [
        _edge({"capability": {"verbs": ["get"], "resources": ["secrets"]}}),
        _edge({"role_rules": [{"verbs": ["get"], "resources": ["secrets"]}]}),
    ]
    state = CapabilityState()
    for edge in edges:
        state = update_capability(state, edge)

    assert state.capabilities == {"read_secret"}
    assert len(state.capabilities) == 1


# --- is_compromised ---------------------------------------------------------
# Migrated from the deprecated is_compromised() to an inline helper.
# The old signature is preserved: check if capability set contains all
# threshold-required caps (OLD semantics: all(c in caps for c in required)).

def _is_compromised(caps: set[str], threshold: str = "standard") -> bool:
    _thresholds: dict[str, list[str]] = {
        "standard": ["create_pod", "exec_pod", "read_secret"],
        "host": ["create_pod", "exec_pod", "read_secret", "node_access"],
        "rbac_escalation": ["create_pod", "grant_rbac"],
        "any_host": ["node_access"],
        "any_impersonate": ["impersonate"],
    }
    required = _thresholds.get(threshold, _thresholds["standard"])
    return all(c in caps for c in required)


def test_standard_compromise():
    state = CapabilityState({"create_pod", "exec_pod", "read_secret"})
    assert _is_compromised(state.capabilities) is True


def test_standard_not_compromised_missing_one():
    state = CapabilityState({"create_pod", "exec_pod"})
    assert _is_compromised(state.capabilities) is False


def test_host_compromise():
    state = CapabilityState({"create_pod", "exec_pod", "read_secret", "node_access"})
    assert _is_compromised(state.capabilities, "host") is True


def test_host_compromise_missing_node_access():
    state = CapabilityState({"create_pod", "exec_pod", "read_secret"})
    assert _is_compromised(state.capabilities, "host") is False


def test_any_impersonate():
    state = CapabilityState({"impersonate"})
    assert _is_compromised(state.capabilities, "any_impersonate") is True


def test_empty_capabilities_not_compromised():
    state = CapabilityState()
    assert _is_compromised(state.capabilities) is False


# --- Edge Cases -------------------------------------------------------------

def test_edge_with_no_relevant_metadata():
    """Edge with metadata but no capability or role_rules leaves state unchanged."""
    edge = _edge({"edge_type": "RbacEdge", "evidence": {"type": "RoleBinding"}})
    state = CapabilityState({"create_pod"})
    state = update_capability(state, edge)
    assert state.capabilities == {"create_pod"}


def test_multiple_rules_from_single_edge():
    """An edge can carry multiple role_rules entries."""
    edge = _edge(
        {
            "role_rules": [
                {"verbs": ["create"], "resources": ["pods"]},
                {"verbs": ["get"], "resources": ["secrets"]},
            ]
        }
    )
    state = CapabilityState()
    state = update_capability(state, edge)
    assert state.capabilities == {"create_pod", "read_secret"}


def test_edge_type_preserved_independently():
    """capability_set does not interfere with edge_type metadata."""
    edge = _edge(
        {
            "edge_type": "Impersonate",
            "capability": {"verbs": ["impersonate"], "resources": ["users"]},
        }
    )
    state = CapabilityState()
    state = update_capability(state, edge)
    assert "impersonate" in state.capabilities
    assert edge.metadata["edge_type"] == "Impersonate"
