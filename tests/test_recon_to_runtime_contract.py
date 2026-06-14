"""Contract tests: recon/trust_map → runtime pipeline end-to-end.

v0.9.2: Verifies the full recon → trust_map → runtime integration.
Ensures the edge semantic contract (metadata.edge_type) flows correctly
from trust_map production through the entire runtime pipeline.

These tests are the structural answer to the P0 "silent degradation" bug
found in v0.9.0: production trust edges had no metadata, causing the
entire runtime pipeline to silently produce SAFE results.

Coverage:
  - trust_map → build_graph → evaluate_path → T(S) classification
  - trust_map → build_graph → counterfactual on Docker Socket edge
  - trust_map → build_graph → classifier on trust topology edges
  - trust_map → AttackGraphEngine.from_trust_map → full pipeline
  - Full contract: edge_type flows through all layers without loss
"""

import pytest

from k8s_arsenal.models import AttackTerminalState, EnvironmentProfile, TrustEdge
from k8s_arsenal.recon.trust_map import build_trust_topology
from k8s_arsenal.playbook.chains import build_graph, shortest_path
from k8s_arsenal.runtime.evaluator import evaluate_path
from k8s_arsenal.runtime.counterfactual import counterfactual
from k8s_arsenal.runtime.classifier import classify
from k8s_arsenal.runtime.engine import AttackGraphEngine


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def trust_edges() -> list[TrustEdge]:
    """Real trust edges from build_trust_topology (non-K8s profile, no pod/docker extras)."""
    profile = EnvironmentProfile(
        is_container=False,
        is_kubernetes=False,
        is_privileged=False,
        host_pid=False,
        host_network=False,
        host_ipc=False,
        capabilities=[],
        mounted_docker_sock=False,
    )
    return build_trust_topology(profile)


@pytest.fixture
def trust_edges_full() -> list[TrustEdge]:
    """Trust edges with pod + docker sock (worst-case scenario)."""
    profile = EnvironmentProfile(
        is_container=True,
        is_kubernetes=True,
        is_privileged=True,
        host_pid=True,
        host_network=True,
        host_ipc=False,
        capabilities=["CAP_SYS_ADMIN"],
        mounted_docker_sock=True,
        service_account="ci-pipeline-sa",
    )
    return build_trust_topology(profile)


# ============================================================================
# Core Contract: metadata.edge_type exists on every production edge
# ============================================================================


def test_all_trust_edges_have_edge_type(trust_edges):
    """Contract: every TrustEdge produced by build_trust_topology MUST have
    metadata.edge_type set. This is the P0 fix from v0.9.1."""
    for i, edge in enumerate(trust_edges):
        edge_type = edge.metadata.get("edge_type", "")
        assert edge_type, (
            f"Edge {i} ({edge.source} → {edge.target}) has no edge_type in metadata. "
            f"relationship={edge.relationship!r}"
        )


def test_trust_edges_exclude_docker_sock_without_mount(trust_edges):
    """Docker Socket edge should NOT appear when mounted_docker_sock=False."""
    for edge in trust_edges:
        assert edge.relationship != "挂载 Docker Socket", (
            "Docker Socket edge should not be generated without mounted_docker_sock"
        )


def test_trust_edges_include_docker_sock_with_mount(trust_edges_full):
    """Docker Socket edge SHOULD appear when mounted_docker_sock=True."""
    docker_edges = [
        e for e in trust_edges_full
        if e.relationship == "挂载 Docker Socket"
    ]
    assert len(docker_edges) == 1
    assert docker_edges[0].metadata["edge_type"] == "DockerSocket"


# ============================================================================
# Integration: trust_map → build_graph → evaluate_path → T(S)
# ============================================================================


def test_trust_map_to_graph_roundtrip(trust_edges):
    """trust_map edges → AttackGraph: all nodes and edges are present."""
    graph = build_graph(trust_edges)

    assert len(graph.edges) == len(trust_edges)
    # Entry points should be auto-detected (sources that aren't targets)
    assert len(graph.entry_points) > 0


def test_trust_map_to_evaluate_path(trust_edges):
    """Core integration: trust edges → graph → path → evaluate_path → T(S)."""
    graph = build_graph(trust_edges)

    # kube-apiserver should be reachable from kube-apiserver (self)
    path = shortest_path(graph, "kube-apiserver", "kubelet")
    assert path is not None, (
        "Expected at least one path from kube-apiserver to kubelet"
    )

    result = evaluate_path(graph, path)
    assert "terminal_state" in result
    assert "trace" in result
    assert "identity_chain" in result

    # The trace should record a non-empty edge_type (v0.9.1 fix verification)
    for step in result["trace"]:
        assert step.get("edge_type"), (
            f"Trace step at node {step.get('node')} has empty edge_type — "
            f"edge semantic contract broken in pipeline"
        )


def test_trust_map_terminal_state_without_attack_paths(trust_edges):
    """Terminal state on trust topology alone: no attack paths → SAFE.

    The trust topology alone (without attack paths) has no capability-bearing
    edges, so T(S) should evaluate to SAFE. This is the correct behavior —
    the trust topology is the graph substrate, not the attack.

    (This test documents the current correct behavior: trust_map produces
    benign topology. Capabilities only arise when attack paths are added.)
    """
    graph = build_graph(trust_edges)
    path = shortest_path(graph, "kube-apiserver", "kubelet")

    result = evaluate_path(graph, path)
    assert result["terminal_state"] == AttackTerminalState.SAFE, (
        f"Trust topology alone (no attack paths) should be SAFE, "
        f"got {result['terminal_state']}"
    )


# ============================================================================
# Integration: trust_map → counterfactual
# ============================================================================


def test_trust_map_counterfactual(trust_edges_full):
    """Counterfactual analysis on trust edges with docker socket."""
    graph = build_graph(trust_edges_full)

    docker_edges = [e for e in trust_edges_full if e.metadata.get("edge_type") == "DockerSocket"]
    if not docker_edges:
        pytest.skip("No DockerSocket edge available")

    # Counterfactual: remove kube-apiserver → kubelet edge (non-docker)
    kube_edges = [e for e in trust_edges_full if e.source == "kube-apiserver"]
    for edge in kube_edges[:1]:
        try:
            cf = counterfactual(graph, edge, "kube-apiserver", "kubelet", "standard")
        except ValueError:
            continue  # Edge breaks connectivity

        assert "delta" in cf
        assert "baseline_state" in cf
        assert "counterfactual_state" in cf


# ============================================================================
# Integration: trust_map → classifier
# ============================================================================


def test_trust_map_classifier(trust_edges):
    """Classifier on trust topology edges: should produce a label."""
    graph = build_graph(trust_edges)
    path = shortest_path(graph, "kube-apiserver", "etcd")

    if path is None:
        pytest.skip("No path from kube-apiserver to etcd")

    result = evaluate_path(graph, path)
    label = classify(result)

    assert label is not None
    # AttackLabel is a dataclass with .tactic, or this returns a string.
    assert hasattr(label, "tactic") or isinstance(label, str)


# ============================================================================
# Integration: AttackGraphEngine.from_trust_map → full pipeline
# ============================================================================


def test_engine_from_trust_map_full_pipeline(trust_edges):
    """Full pipeline through AttackGraphEngine with trust_map edges."""
    engine = AttackGraphEngine.from_trust_map(trust_edges)

    result = engine.analyze(
        entry_identity="kube-apiserver",
        critical_assets=["etcd"],
        run_counterfactuals=True,
        run_mcs=True,
        run_classifier=True,
        verify_mcs=True,
    )

    # All result fields should be populated (no crashes, no Nones).
    assert result.terminal_state is not None
    assert result.terminal_explanation  # non-empty string
    assert result.path_count >= 0
    assert isinstance(result.counterfactuals, list)
    assert isinstance(result.mcs_cut_edges, list)
    assert result.entry_identity == "kube-apiserver"
    assert "etcd" in result.critical_assets


def test_engine_from_trust_map_no_counterfactuals(trust_edges):
    """Engine with counterfactuals and MCS disabled."""
    engine = AttackGraphEngine.from_trust_map(trust_edges)

    result = engine.analyze(
        entry_identity="kube-apiserver",
        critical_assets=["etcd"],
        run_counterfactuals=False,
        run_mcs=False,
        run_classifier=False,
        verify_mcs=False,
    )

    assert result.terminal_state is not None
    assert result.counterfactuals == []
    assert result.mcs_cut_edges == []
    assert result.primary_tactic == ""


def test_engine_auto_entry(trust_edges):
    """Engine auto-detects entry point from graph sinks (no explicit entry)."""
    graph = build_graph(trust_edges)
    engine = AttackGraphEngine(graph)

    # Should auto-detect first entry point.
    assert engine.entry_identity, "Engine should auto-detect entry identity"

    result = engine.analyze()
    assert result.entry_identity == engine.entry_identity


def test_engine_raises_on_empty_graph():
    """Engine with no graph edges and no explicit entry → ValueError."""
    graph = build_graph([])
    engine = AttackGraphEngine(graph)

    with pytest.raises(ValueError, match="entry"):
        engine.analyze()


# ============================================================================
# Full-Contract: edge_type flows through all layers without loss
# ============================================================================


def test_full_contract_edge_type_survives_pipeline(trust_edges_full):
    """End-to-end contract: edge_type from trust_map survives all pipeline layers.

    This is the single test that validates the P0 fix from v0.9.1
    through the complete pipeline (G + S + T + Δ + MCS + Label).
    """
    engine = AttackGraphEngine.from_trust_map(trust_edges_full)

    result = engine.analyze(
        entry_identity="current-container",
        critical_assets=["docker-daemon"],
        run_counterfactuals=True,
        run_mcs=True,
        run_classifier=True,
        verify_mcs=True,
    )

    # Layer verification: every trace step must record a non-empty edge_type.
    for step in result.trace:
        assert step.get("edge_type"), (
            f"Contract violation: trace step at {step.get('node')} has empty edge_type. "
            f"Edge semantic contract broken during pipeline execution."
        )

    # Counterfactual results should reference valid edges.
    for cf in result.counterfactuals:
        src, tgt, rel = cf.edge
        assert src and tgt, f"Counterfactual edge has empty source or target: {cf.edge}"
        assert rel, f"Counterfactual edge has empty relationship: {cf.edge}"

    # MCS cut edges should not be empty tuples.
    for cut in result.mcs_cut_edges:
        assert len(cut) == 3, f"MCS cut edge malformed: {cut}"
        assert all(cut), f"MCS cut edge has empty fields: {cut}"
