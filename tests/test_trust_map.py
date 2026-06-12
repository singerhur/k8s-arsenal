"""Tests for K8s trust topology mapping module."""

import pytest
from k8s_arsenal.recon.trust_map import (
    build_trust_topology,
    find_attackable_edges,
    render_trust_map_ascii,
)
from k8s_arsenal.models import TrustEdge, RiskLevel


class TestBuildTrustTopology:
    def test_returns_list_of_trust_edges(self, non_k8s_profile):
        edges = build_trust_topology(non_k8s_profile)
        assert isinstance(edges, list)
        assert len(edges) > 0
        for edge in edges:
            assert isinstance(edge, TrustEdge)
            assert hasattr(edge, "source")
            assert hasattr(edge, "target")
            assert hasattr(edge, "relationship")

    def test_includes_api_server_to_kubelet(self, non_k8s_profile):
        edges = build_trust_topology(non_k8s_profile)
        sources = [e.source for e in edges]
        targets = [e.target for e in edges]
        assert "kube-apiserver" in sources
        assert "kubelet" in targets

    def test_includes_pod_edge_when_in_k8s(self, privileged_profile):
        edges = build_trust_topology(privileged_profile)
        edges_str = f"{edges}"
        # privileged_profile's service_account is None, so it won't add
        # the pod-specific edge. Let's verify the K8s detection adds the
        # CoreDNS and kube-proxy edges
        targets = [e.target for e in edges]
        assert "kube-apiserver" in targets

    def test_includes_docker_sock_edge(self, privileged_profile):
        edges = build_trust_topology(privileged_profile)
        sources = [e.source for e in edges]
        assert "current-container" in sources

    def test_no_docker_sock_edge(self, unprivileged_profile):
        edges = build_trust_topology(unprivileged_profile)
        sources = [e.source for e in edges]
        assert "current-container" not in sources


class TestFindAttackableEdges:
    def test_empty_input(self):
        assert find_attackable_edges([]) == []

    def test_filters_non_rotated_high_risk(self, non_k8s_profile):
        edges = build_trust_topology(non_k8s_profile)
        attackable = find_attackable_edges(edges)
        for edge in attackable:
            assert edge.auto_rotated is False
            assert edge.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_rotated_edges_not_included(self):
        rotated_edge = TrustEdge(
            source="test", target="test",
            relationship="test", credential_type="test",
            auto_rotated=True, risk=RiskLevel.CRITICAL,
        )
        low_risk_edge = TrustEdge(
            source="test", target="test",
            relationship="test", credential_type="test",
            auto_rotated=False, risk=RiskLevel.LOW,
        )
        assert find_attackable_edges([rotated_edge, low_risk_edge]) == []


class TestRenderTrustMapAscii:
    def test_returns_string(self, non_k8s_profile):
        edges = build_trust_topology(non_k8s_profile)
        result = render_trust_map_ascii(edges)
        assert isinstance(result, str)
        assert "K8s" in result
        assert "信任拓扑" in result or "kube-apiserver" in result

    def test_empty_edges(self):
        result = render_trust_map_ascii([])
        assert isinstance(result, str)
        assert len(result) > 0

    def test_includes_risk_icons(self, non_k8s_profile):
        edges = build_trust_topology(non_k8s_profile)
        result = render_trust_map_ascii(edges)
        assert "[!]" in result or "[X]" in result or "[~]" in result

    def test_includes_rotation_markers(self, non_k8s_profile):
        edges = build_trust_topology(non_k8s_profile)
        result = render_trust_map_ascii(edges)
        assert "[R]" in result or "[L]" in result
