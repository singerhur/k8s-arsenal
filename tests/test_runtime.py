"""Integration tests for v0.5 runtime layer — path evaluation + Scenario C replay.

Tests cover:
- Path → state evolution trace
- BFS shortest path evaluation (simple identity chain)
- Full multi-hop chain with cumulative capability composition
- Edge cases: empty capabilities, non-transition paths
"""

import pytest

from k8s_arsenal.models import AttackGraph, RiskLevel, TrustEdge
from k8s_arsenal.playbook.chains import build_graph, shortest_path
from k8s_arsenal.runtime import (
    CapabilityState,
    IdentityState,
    evaluate_path,
    is_compromised,
    propagate_identity,
    update_capability,
)


# ============================================================================
# Fixtures
# ============================================================================

def _graph_with_capability():
    """Two-hop graph: SA-A has pods/create → SA-B."""
    edges = [
        TrustEdge(
            source="sa-A",
            target="role-A",
            relationship="RoleBinding",
            metadata={"edge_type": "RbacEdge", "role_rules": [
                {"verbs": ["create"], "resources": ["pods"], "apiGroups": [""]}
            ]},
        ),
        TrustEdge(
            source="role-A",
            target="sa-B",
            relationship="token-access",
            metadata={"edge_type": "TokenAccess", "capability": {
                "verbs": ["create"], "resources": ["pods"]
            }},
        ),
    ]
    return build_graph(edges, nodes={"sa-A": "sa-A", "role-A": "role-A", "sa-B": "sa-B"})


def _set_graph_meta(graph: AttackGraph, entry_points: list[str], critical_assets: list[str]) -> AttackGraph:
    graph.entry_points = entry_points
    graph.critical_assets = critical_assets
    return graph


def _scenario_c_graph():
    """Scenario C graph: 7 nodes, 7 edges, multi-hop identity chain.

    ci-pipeline-sa → ci-deployer → prod-app-sa → monitoring-reader
        → monitoring-operator-sa → kubelet-impersonator → kube-apiserver

    Plus a direct DEFAULT edge: prod-app-sa → kube-apiserver
    """
    edges = [
        # Edge 1: ci-pipeline-sa → ci-deployer (observation: RoleBinding)
        TrustEdge(
            source="ci-pipeline-sa",
            target="ci-deployer",
            relationship="RoleBinding",
            metadata={
                "edge_type": "RbacEdge",
                "source": "observation",
                "role_rules": [
                    {"verbs": ["create"], "resources": ["deployments"], "apiGroups": ["apps"]},
                ],
            },
        ),
        # Edge 4 (bridge): ci-deployer → prod-app-sa (inference: can deploy → identity theft)
        TrustEdge(
            source="ci-deployer",
            target="prod-app-sa",
            relationship="SemanticBridge",
            risk=RiskLevel.HIGH,
            metadata={
                "edge_type": "TokenAccess",
                "source": "inference",
                "derived_from": ["ci-pipeline-sa->ci-deployer"],
                "capability": {"verbs": ["create"], "resources": ["deployments"]},
                "reasoning": "ci-deployer can deploy pods using prod-app-sa",
            },
        ),
        # Edge 2: prod-app-sa → monitoring-reader (observation: RoleBinding)
        TrustEdge(
            source="prod-app-sa",
            target="monitoring-reader",
            relationship="RoleBinding",
            metadata={
                "edge_type": "RbacEdge",
                "source": "observation",
                "role_rules": [
                    {"verbs": ["get", "list"], "resources": ["secrets"], "apiGroups": [""]},
                ],
            },
        ),
        # Edge 5 (bridge): monitoring-reader → monitoring-operator-sa (inference: token theft)
        TrustEdge(
            source="monitoring-reader",
            target="monitoring-operator-sa",
            relationship="SemanticBridge",
            risk=RiskLevel.HIGH,
            metadata={
                "edge_type": "TokenAccess",
                "source": "inference",
                "derived_from": ["prod-app-sa->monitoring-reader"],
                "capability": {"verbs": ["get"], "resources": ["secrets"]},
                "reasoning": "monitoring-reader can read monitoring-operator-sa token",
            },
        ),
        # Edge 3: monitoring-operator-sa → kubelet-impersonator (observation: ClusterRoleBinding)
        TrustEdge(
            source="monitoring-operator-sa",
            target="kubelet-impersonator",
            relationship="ClusterRoleBinding",
            metadata={
                "edge_type": "RbacEdge",
                "source": "observation",
                "role_rules": [
                    {"verbs": ["impersonate"], "resources": ["users"], "apiGroups": [""]},
                ],
            },
        ),
        # Edge 7 (bridge): kubelet-impersonator → kube-apiserver (inference: impersonate→kubelet)
        TrustEdge(
            source="kubelet-impersonator",
            target="kube-apiserver",
            relationship="SemanticBridge",
            risk=RiskLevel.CRITICAL,
            metadata={
                "edge_type": "Impersonate",
                "source": "inference",
                "derived_from": ["monitoring-operator-sa->kubelet-impersonator"],
                "capability": {"verbs": ["impersonate"], "resources": ["users"]},
                "reasoning": "kubelet-impersonator can impersonate system:node:* → kubelet access",
            },
        ),
        # Edge 6: prod-app-sa → kube-apiserver (default: SA Token → API access)
        TrustEdge(
            source="prod-app-sa",
            target="kube-apiserver",
            relationship="DefaultEdge",
            risk=RiskLevel.MEDIUM,
            metadata={
                "edge_type": "DefaultEdge",
                "source": "default",
                "reasoning": "Every SA has JWT token granting API server access",
            },
        ),
    ]

    graph = build_graph(
        edges,
        nodes={
            "ci-pipeline-sa": "ci-pipeline-sa",
            "ci-deployer": "ci-deployer",
            "prod-app-sa": "prod-app-sa",
            "monitoring-reader": "monitoring-reader",
            "monitoring-operator-sa": "monitoring-operator-sa",
            "kubelet-impersonator": "kubelet-impersonator",
            "kube-apiserver": "kube-apiserver",
        },
    )
    return _set_graph_meta(graph, ["ci-pipeline-sa"], ["kube-apiserver"])


# ============================================================================
# Basic Runtime Tests
# ============================================================================

def test_evaluate_simple_path():
    """Basic two-hop path with capability accumulation."""
    graph = _graph_with_capability()
    path = shortest_path(graph, "sa-A", "sa-B")

    result = evaluate_path(graph, path)

    assert result["final_identity"] == "sa-B"
    assert len(result["identity_chain"]) == 2  # sa-A -> sa-B (only transition edges grow chain)
    assert "create_pod" in result["capabilities"]
    # Only create_pod — not enough for compromise
    assert result["is_compromised"] is False


def test_evaluate_path_trace():
    """Trace records each step's identity and capabilities."""
    graph = _graph_with_capability()
    path = shortest_path(graph, "sa-A", "sa-B")

    result = evaluate_path(graph, path)

    trace = result["trace"]
    assert len(trace) == 2  # Two edges
    assert trace[0]["node"] == "role-A"
    assert trace[1]["node"] == "sa-B"

    # First step: identity unchanged (role-A is not TokenAccess)
    assert trace[0]["identity"] == "sa-A"
    # Second step: identity transitions to sa-B
    assert trace[1]["identity"] == "sa-B"


def test_evaluate_path_identity_preserved_on_non_transition():
    """Path with no TokenAccess/Impersonate preserves identity throughout."""
    edges = [
        TrustEdge(
            source="sa-X", target="role-Y", relationship="RoleBinding",
            metadata={"edge_type": "RbacEdge"},
        ),
        TrustEdge(
            source="role-Y", target="sa-Z", relationship="RoleBinding",
            metadata={"edge_type": "RbacEdge"},
        ),
    ]
    graph = build_graph(edges, nodes={"sa-X": "sa-X", "role-Y": "role-Y", "sa-Z": "sa-Z"})
    path = shortest_path(graph, "sa-X", "sa-Z")

    result = evaluate_path(graph, path)

    assert result["final_identity"] == "sa-X"  # Never changed
    assert result["identity_chain"][-1] == "sa-X"
    assert result["capabilities"] == set()
    assert result["is_compromised"] is False


def test_evaluate_path_raises_on_single_node():
    """Single node path raises ValueError."""
    graph = build_graph([])
    with pytest.raises(ValueError, match="≥2 nodes"):
        evaluate_path(graph, ["only-node"])


# ============================================================================
# Scenario C: BFS Shortest Path (3 hops: SA → API via default edge)
# ============================================================================

def test_scenario_c_shortest_path():
    """BFS finds the shortest path: ci-pipeline-sa → ci-deployer → prod-app-sa → kube-apiserver."""
    graph = _scenario_c_graph()

    path = shortest_path(graph, "ci-pipeline-sa", "kube-apiserver")
    assert path is not None
    assert len(path) == 4  # 3 hops + start node
    assert path == [
        "ci-pipeline-sa",
        "ci-deployer",
        "prod-app-sa",
        "kube-apiserver",
    ], f"BFS should find ≤3-hop path, got {path}"


def test_scenario_c_shortest_path_evaluation():
    """Short path: identity transitions from ci-pipeline-sa to prod-app-sa, but not compromised."""
    graph = _scenario_c_graph()
    path = shortest_path(graph, "ci-pipeline-sa", "kube-apiserver")

    result = evaluate_path(graph, path)

    # Identity chain: ci-pipeline-sa → ci-pipeline-sa → prod-app-sa → prod-app-sa
    assert result["final_identity"] == "prod-app-sa"
    assert "prod-app-sa" in result["identity_chain"]

    # Capabilities: create_pod from ci-deployer, nothing else
    assert "create_pod" in result["capabilities"]
    # Only create_pod — no exec/read_secret, not compromised
    assert result["is_compromised"] is False


# ============================================================================
# Scenario C: Full Multi-Hop Chain (7 hops via monitoring route)
# ============================================================================

_SCENE_C_FULL_PATH = [
    "ci-pipeline-sa",
    "ci-deployer",
    "prod-app-sa",
    "monitoring-reader",
    "monitoring-operator-sa",
    "kubelet-impersonator",
    "kube-apiserver",
]


def test_scenario_c_full_identity_chain():
    """Full 7-hop chain: identity drifts across 3 SA + kubelet."""
    graph = _scenario_c_graph()
    result = evaluate_path(graph, _SCENE_C_FULL_PATH)

    assert result["final_identity"] == "kube-apiserver"
    assert result["identity_chain"] == [
        "ci-pipeline-sa",
        "prod-app-sa",            # TokenAccess (ci-deployer -> prod-app-sa)
        "monitoring-operator-sa",  # TokenAccess (monitoring-reader -> monitoring-operator-sa)
        "kube-apiserver",          # Impersonate (kubelet-impersonator -> kube-apiserver)
    ], f"identity_chain mismatch: {result['identity_chain']}"


def test_scenario_c_full_capability_composition():
    """Full chain accumulates create_pod + read_secret + impersonate."""
    graph = _scenario_c_graph()
    result = evaluate_path(graph, _SCENE_C_FULL_PATH)

    caps = result["capabilities"]
    assert "create_pod" in caps, f"Expected create_pod from deployments/create"
    assert "read_secret" in caps, f"Expected read_secret from secrets/get"
    assert "impersonate" in caps, f"Expected impersonate from users/impersonate"


def test_scenario_c_full_is_compromised():
    """Full capability set (create + get + impersonate) → cluster compromised."""
    graph = _scenario_c_graph()
    result = evaluate_path(graph, _SCENE_C_FULL_PATH)

    # Standard threshold needs create + exec + read_secret
    # We have create + read_secret + impersonate (no exec_pod)
    assert result["is_compromised"] is False, (
        "Standard threshold: create_pod+exec_pod+read_secret — missing exec_pod"
    )

    # Impersonate threshold: any impersonate is a compromise
    assert is_compromised(CapabilityState(result["capabilities"]), "any_impersonate") is True


def test_scenario_c_full_trace():
    """Each trace step records the correct identity and cumulative capabilities."""
    graph = _scenario_c_graph()
    result = evaluate_path(graph, _SCENE_C_FULL_PATH)

    trace = result["trace"]
    assert len(trace) == 6  # 6 edges for 7 nodes

    # Step 3 (prod-app-sa → monitoring-reader): identity is prod-app-sa
    assert trace[2]["identity"] == "prod-app-sa"

    # Step 5 (monitoring-operator-sa → kubelet-impersonator): identity is monitoring-operator-sa
    assert trace[4]["identity"] == "monitoring-operator-sa"

    # Last step: identity is kube-apiserver
    assert trace[5]["identity"] == "kube-apiserver"


# ============================================================================
# Edge Cases
# ============================================================================

def test_empty_capability_path():
    """Path with no capability-bearing edges returns empty capabilities."""
    edges = [
        TrustEdge(
            source="A", target="B", relationship="DefaultEdge",
            metadata={"edge_type": "DefaultEdge", "source": "default"},
        ),
    ]
    graph = build_graph(edges, nodes={"A": "A", "B": "B"})
    path = shortest_path(graph, "A", "B")

    result = evaluate_path(graph, path)
    assert result["capabilities"] == set()
    assert result["is_compromised"] is False


def test_custom_threshold():
    """Compromise check can use non-default thresholds."""
    graph = _scenario_c_graph()

    # Use rbac_escalation threshold: needs create_pod + grant_rbac
    result = evaluate_path(graph, _SCENE_C_FULL_PATH, compromise_threshold="rbac_escalation")
    # We have create_pod but not grant_rbac
    assert result["is_compromised"] is False
