"""Integration tests for v0.5.1 runtime layer — path evaluation + Scenario C replay.

Tests cover:
- Path → state evolution trace with terminal state classification
- BFS shortest path evaluation (simple identity chain)
- Full multi-hop chain with cumulative capability composition
- T(S) three-way classification: SAFE / PARTIAL / COMPROMISED
- Edge cases: empty capabilities, non-transition paths, custom thresholds
"""

import pytest

from k8s_arsenal.models import AttackGraph, AttackTerminalState, RiskLevel, TrustEdge
from k8s_arsenal.playbook.chains import build_graph, shortest_path
from k8s_arsenal.runtime import (
    CapabilityState,
    IdentityState,
    evaluate_path,
    evaluate_terminal_state,
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
    """Scenario C graph: 7 nodes, 7 edges, multi-hop identity chain."""
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
        # Edge 4: ci-deployer → prod-app-sa (inference: can deploy → identity theft)
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
        # Edge 5: monitoring-reader → monitoring-operator-sa (inference: token theft)
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
        # Edge 3: monitoring-operator-sa → kubelet-impersonator
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
        # Edge 7: kubelet-impersonator → kube-apiserver
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
                "reasoning": "kubelet-impersonator can impersonate system:node:*",
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
    """Basic two-hop path with capability accumulation → PARTIAL (has dangerous cap)."""
    graph = _graph_with_capability()
    path = shortest_path(graph, "sa-A", "sa-B")

    result = evaluate_path(graph, path)

    assert result["final_identity"] == "sa-B"
    assert len(result["identity_chain"]) == 2  # sa-A -> sa-B (only transition edges grow chain)
    assert "create_pod" in result["capabilities"]
    # create_pod is dangerous + at terminal node sa-B → PARTIAL
    assert result["terminal_state"] == AttackTerminalState.PARTIAL


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
    # Empty capabilities, at terminal node sa-Z → SAFE
    assert result["terminal_state"] == AttackTerminalState.SAFE


def test_evaluate_path_raises_on_single_node():
    """Single node path raises ValueError."""
    graph = build_graph([])
    with pytest.raises(ValueError, match="\u22652 nodes"):
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
    ], f"BFS should find \u22643-hop path, got {path}"


def test_scenario_c_shortest_path_evaluation():
    """Short path: identity → prod-app-sa at kube-apiserver with create_pod → PARTIAL."""
    graph = _scenario_c_graph()
    path = shortest_path(graph, "ci-pipeline-sa", "kube-apiserver")

    result = evaluate_path(graph, path)

    assert result["final_identity"] == "prod-app-sa"
    assert "prod-app-sa" in result["identity_chain"]
    assert "create_pod" in result["capabilities"]
    # At kube-apiserver (critical asset) with create_pod → PARTIAL
    assert result["terminal_state"] == AttackTerminalState.PARTIAL


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
        "monitoring-operator-sa",  # TokenAccess (monitoring-reader -> operator-sa)
        "kube-apiserver",          # Impersonate (kubelet-impersonator -> api)
    ], f"identity_chain mismatch: {result['identity_chain']}"


def test_scenario_c_full_capability_composition():
    """Full chain accumulates create_pod + read_secret + impersonate."""
    graph = _scenario_c_graph()
    result = evaluate_path(graph, _SCENE_C_FULL_PATH)

    caps = result["capabilities"]
    assert "create_pod" in caps, f"Expected create_pod from deployments/create"
    assert "read_secret" in caps, f"Expected read_secret from secrets/get"
    assert "impersonate" in caps, f"Expected impersonate from users/impersonate"


def test_scenario_c_full_terminal_state():
    """Full capability set with impersonate → COMPROMISED (universal hard signal)."""
    graph = _scenario_c_graph()
    result = evaluate_path(graph, _SCENE_C_FULL_PATH)

    # impersonate is a universal hard-compromise signal —
    # can impersonate kubelet → cluster-wide root
    assert result["terminal_state"] == AttackTerminalState.COMPROMISED, (
        f"Expected COMPROMISED (has impersonate), got {result['terminal_state']}"
    )


def test_scenario_c_full_trace():
    """Each trace step records the correct identity and cumulative capabilities."""
    graph = _scenario_c_graph()
    result = evaluate_path(graph, _SCENE_C_FULL_PATH)

    trace = result["trace"]
    assert len(trace) == 6  # 6 edges for 7 nodes

    assert trace[2]["identity"] == "prod-app-sa"
    assert trace[4]["identity"] == "monitoring-operator-sa"
    assert trace[5]["identity"] == "kube-apiserver"


# ============================================================================
# Edge Cases
# ============================================================================

def test_empty_capability_path():
    """Path with no capability-bearing edges → SAFE (no dangerous caps)."""
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
    assert result["terminal_state"] == AttackTerminalState.SAFE


def test_custom_threshold_rbac_escalation():
    """rbac_escalation threshold with create_pod only → PARTIAL (at critical asset)."""
    graph = _scenario_c_graph()

    result = evaluate_path(graph, _SCENE_C_FULL_PATH, compromise_threshold="rbac_escalation")
    # impersonate is a universal hard signal, so this is still COMPROMISED
    # regardless of threshold
    assert result["terminal_state"] == AttackTerminalState.COMPROMISED


def test_custom_threshold_standard_no_exec():
    """Standard threshold without exec_pod: impersonate still triggers COMPROMISED."""
    graph = _scenario_c_graph()
    result = evaluate_path(graph, _SCENE_C_FULL_PATH, compromise_threshold="standard")
    # impersonate is universal hard signal → COMPROMISED
    assert result["terminal_state"] == AttackTerminalState.COMPROMISED


# ============================================================================
# Terminal State Function: Direct Tests
# ============================================================================

def test_terminal_state_safe():
    """Empty capabilities → SAFE."""
    graph = build_graph([], nodes={"x": "x"})
    identity = IdentityState(node="x")
    result = evaluate_terminal_state(identity, frozenset(), graph)
    assert result == AttackTerminalState.SAFE


def test_terminal_state_partial_reachable():
    """Has dangerous cap + reachable to critical asset → PARTIAL."""
    graph = _scenario_c_graph()
    identity = IdentityState(node="ci-pipeline-sa")
    caps = frozenset({"create_pod"})
    result = evaluate_terminal_state(identity, caps, graph)
    assert result == AttackTerminalState.PARTIAL


def test_terminal_state_compromised_impersonate():
    """Impersonate → COMPROMISED (universal hard signal)."""
    graph = build_graph([], nodes={"x": "x"})
    identity = IdentityState(node="x")
    caps = frozenset({"impersonate"})
    result = evaluate_terminal_state(identity, caps, graph)
    assert result == AttackTerminalState.COMPROMISED


def test_terminal_state_compromised_escalate_rbac():
    """escalate_rbac → COMPROMISED (universal hard signal)."""
    graph = build_graph([], nodes={"x": "x"})
    identity = IdentityState(node="x")
    caps = frozenset({"escalate_rbac"})
    result = evaluate_terminal_state(identity, caps, graph)
    assert result == AttackTerminalState.COMPROMISED


def test_terminal_state_compromised_standard():
    """create_pod + exec_pod + read_secret → COMPROMISED (threshold met)."""
    graph = build_graph([], nodes={"x": "x"})
    identity = IdentityState(node="x")
    caps = frozenset({"create_pod", "exec_pod", "read_secret"})
    result = evaluate_terminal_state(identity, caps, graph)
    assert result == AttackTerminalState.COMPROMISED


def test_terminal_state_partial_at_critical():
    """At critical asset with dangerous caps but no full threshold → PARTIAL."""
    graph = build_graph([], nodes={"api": "api"})
    _set_graph_meta(graph, [], ["api"])
    identity = IdentityState(node="api")
    caps = frozenset({"create_pod"})
    result = evaluate_terminal_state(identity, caps, graph)
    assert result == AttackTerminalState.PARTIAL


def test_terminal_state_host_threshold():
    """host_access → COMPROMISED (host threshold)."""
    graph = build_graph([], nodes={"x": "x"})
    identity = IdentityState(node="x")
    caps = frozenset({"host_access"})
    result = evaluate_terminal_state(identity, caps, graph, threshold="host")
    assert result == AttackTerminalState.COMPROMISED


def test_scenario_c_replay_terminal_state():
    """Scenario C full chain: evaluate_path → terminal_state via T(S)."""
    graph = _scenario_c_graph()
    result = evaluate_path(graph, _SCENE_C_FULL_PATH)
    assert result["terminal_state"] == AttackTerminalState.COMPROMISED

    # The T(S) function should agree with evaluate_path.
    identity = IdentityState(node=result["final_identity"])
    identity.identity_chain = result["identity_chain"]
    ts = evaluate_terminal_state(identity, result["capabilities"], graph)
    assert ts == result["terminal_state"]
