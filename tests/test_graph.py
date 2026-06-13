"""attack_graph 攻击图基元测试

覆盖 AttackGraph 数据类、build_graph、reachable、shortest_path、
find_pivot_points 等图基元函数。
"""

from __future__ import annotations

import pytest

from k8s_arsenal.models import AttackGraph, TrustEdge, AttackPath, RiskLevel
from k8s_arsenal.playbook.chains import (
    build_graph,
    reachable,
    shortest_path,
    find_pivot_points,
)


# ------------------------------------------------------------------
# fixtures
# ------------------------------------------------------------------

@pytest.fixture
def sample_edges() -> list[TrustEdge]:
    """典型 minikube 环境信任拓扑"""
    return [
        TrustEdge(source="minimal-pod", target="kube-apiserver",
                  relationship="API access", risk=RiskLevel.HIGH),
        TrustEdge(source="minimal-pod", target="default-sa",
                  relationship="uses SA", risk=RiskLevel.MEDIUM),
        TrustEdge(source="minimal-pod", target="node-minikube",
                  relationship="pod runs on node", risk=RiskLevel.MEDIUM),
        TrustEdge(source="default-sa", target="kube-apiserver",
                  relationship="authenticated", risk=RiskLevel.MEDIUM),
        TrustEdge(source="node-minikube", target="etcd",
                  relationship="hosts", risk=RiskLevel.CRITICAL),
        TrustEdge(source="node-minikube", target="kubelet",
                  relationship="runs", risk=RiskLevel.CRITICAL),
        TrustEdge(source="node-minikube", target="all-pods",
                  relationship="node access", risk=RiskLevel.HIGH),
        TrustEdge(source="master-node", target="etcd",
                  relationship="hosts", risk=RiskLevel.CRITICAL),
    ]


@pytest.fixture
def sample_graph(sample_edges: list[TrustEdge]) -> AttackGraph:
    """从 trust edges 构建的攻击图"""
    return build_graph(sample_edges)


# ------------------------------------------------------------------
# AttackGraph 数据类
# ------------------------------------------------------------------

class TestAttackGraph:
    def test_default_empty(self) -> None:
        g = AttackGraph()
        assert g.nodes == {}
        assert g.edges == []
        assert g.paths == []
        assert g.entry_points == []
        assert g.critical_assets == []

    def test_with_paths(self) -> None:
        path = AttackPath(id="test-1", name="test", description="test path")
        g = AttackGraph(
            nodes={"a": "pod-a", "b": "node-b"},
            edges=[TrustEdge(source="a", target="b", relationship="runs_on")],
            paths=[path],
            entry_points=["a"],
            critical_assets=["b"],
        )
        assert len(g.nodes) == 2
        assert len(g.edges) == 1
        assert len(g.paths) == 1
        assert g.entry_points == ["a"]
        assert g.critical_assets == ["b"]


# ------------------------------------------------------------------
# build_graph
# ------------------------------------------------------------------

class TestBuildGraph:
    def test_basic(self, sample_edges: list[TrustEdge]) -> None:
        g = build_graph(sample_edges)
        assert len(g.edges) == len(sample_edges)
        assert "minimal-pod" in g.entry_points
        assert "master-node" in g.entry_points
        assert "kube-apiserver" in g.critical_assets
        assert "kubelet" in g.critical_assets
        assert "all-pods" in g.critical_assets
        assert "etcd" in g.critical_assets  # target only, no outgoing edges

    def test_with_nodes(self, sample_edges: list[TrustEdge]) -> None:
        nodes = {"minimal-pod": "minimal-pod (default)", "etcd": "etcd-0"}
        g = build_graph(sample_edges, nodes=nodes)
        assert g.nodes == nodes

    def test_with_paths(self, sample_edges: list[TrustEdge]) -> None:
        path1 = AttackPath(id="p1", name="path1", description="test")
        path2 = AttackPath(id="p2", name="path2", description="test")
        g = build_graph(sample_edges, attack_paths=[path1, path2])
        assert len(g.paths) == 2
        assert g.paths[0].id == "p1"

    def test_empty(self) -> None:
        g = build_graph([])
        assert g.edges == []
        assert g.entry_points == []
        assert g.critical_assets == []

    def test_single_edge(self) -> None:
        g = build_graph([
            TrustEdge(source="a", target="b", relationship="runs_on"),
        ])
        assert g.entry_points == ["a"]
        assert g.critical_assets == ["b"]


# ------------------------------------------------------------------
# reachable
# ------------------------------------------------------------------

class TestReachable:
    def test_direct(self, sample_graph: AttackGraph) -> None:
        assert reachable(sample_graph, "minimal-pod", "kube-apiserver") is True

    def test_multi_hop(self, sample_graph: AttackGraph) -> None:
        assert reachable(sample_graph, "minimal-pod", "etcd") is True
        assert reachable(sample_graph, "minimal-pod", "kubelet") is True
        assert reachable(sample_graph, "minimal-pod", "all-pods") is True

    def test_unreachable(self, sample_graph: AttackGraph) -> None:
        assert reachable(sample_graph, "kube-apiserver", "minimal-pod") is False
        assert reachable(sample_graph, "master-node", "minimal-pod") is False

    def test_self(self, sample_graph: AttackGraph) -> None:
        assert reachable(sample_graph, "minimal-pod", "minimal-pod") is True

    def test_nonexistent_source(self, sample_graph: AttackGraph) -> None:
        assert reachable(sample_graph, "ghost-node", "kube-apiserver") is False

    def test_empty_graph(self) -> None:
        g = AttackGraph()
        assert reachable(g, "a", "b") is False


# ------------------------------------------------------------------
# shortest_path
# ------------------------------------------------------------------

class TestShortestPath:
    def test_direct(self, sample_graph: AttackGraph) -> None:
        path = shortest_path(sample_graph, "minimal-pod", "kube-apiserver")
        assert path == ["minimal-pod", "kube-apiserver"]

    def test_two_hop(self, sample_graph: AttackGraph) -> None:
        path = shortest_path(sample_graph, "minimal-pod", "etcd")
        assert path == ["minimal-pod", "node-minikube", "etcd"]

    def test_unreachable(self, sample_graph: AttackGraph) -> None:
        assert shortest_path(
            sample_graph, "kube-apiserver", "minimal-pod"
        ) is None

    def test_self(self, sample_graph: AttackGraph) -> None:
        assert shortest_path(sample_graph, "minimal-pod", "minimal-pod") == ["minimal-pod"]

    def test_nonexistent_source(self, sample_graph: AttackGraph) -> None:
        assert shortest_path(sample_graph, "ghost", "etcd") is None

    def test_shortest_not_longest(self, sample_graph: AttackGraph) -> None:
        path = shortest_path(sample_graph, "master-node", "etcd")
        assert path is not None
        assert len(path) == 2


# ------------------------------------------------------------------
# find_pivot_points
# ------------------------------------------------------------------

class TestFindPivotPoints:
    def test_multiple_pivots(self, sample_graph: AttackGraph) -> None:
        pivots = find_pivot_points(sample_graph)
        pivot_ids = [p[0] for p in pivots]
        assert "node-minikube" in pivot_ids
        assert "minimal-pod" in pivot_ids
        assert pivots[0][1] >= pivots[-1][1]

    def test_single_pivot(self) -> None:
        g = build_graph([
            TrustEdge(source="a", target="x", relationship=""),
            TrustEdge(source="a", target="y", relationship=""),
            TrustEdge(source="a", target="z", relationship=""),
            TrustEdge(source="b", target="z", relationship=""),
        ])
        pivots = find_pivot_points(g)
        assert len(pivots) == 1
        assert pivots[0] == ("a", 3)

    def test_no_pivots(self) -> None:
        g = build_graph([
            TrustEdge(source="a", target="b", relationship=""),
        ])
        pivots = find_pivot_points(g)
        assert pivots == []

    def test_empty(self) -> None:
        g = build_graph([])
        assert find_pivot_points(g) == []
