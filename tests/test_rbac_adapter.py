"""Tests for Live RBAC Adapter.

Covers: rule parsing, capability inference, edge type classification,
risk level mapping, infrastructure edges, and mocked API integration.
"""
from unittest.mock import patch, MagicMock
import pytest

from k8s_arsenal.recon.rbac_adapter import (
    _infer_capabilities,
    _infer_edge_type_from_caps,
    _infer_risk_level,
    _rule_summary,
    _build_infrastructure_edges,
    build_live_rbac_edges,
    build_live_topology,
    _INFRA_EDGES,
    _DANGEROUS_PATTERNS,
)
from k8s_arsenal.models import TrustEdge, EdgeSource, RiskLevel, EnvironmentProfile


# ---------------------------------------------------------------------------
# unit tests: capability inference
# ---------------------------------------------------------------------------

class TestInferCapabilities:
    """Test rule-to-capability mapping."""

    def test_empty_rules(self):
        assert _infer_capabilities([]) == set()

    def test_impersonate_rule(self):
        rules = [{"apiGroups": [""], "resources": ["users"], "verbs": ["impersonate"]}]
        assert "impersonate" in _infer_capabilities(rules)

    def test_read_secrets(self):
        rules = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}]
        assert "read_secrets" in _infer_capabilities(rules)

    def test_write_secrets(self):
        rules = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create", "update"]}]
        assert "write_secrets" in _infer_capabilities(rules)

    def test_create_pod(self):
        rules = [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]
        assert "create_pod" in _infer_capabilities(rules)

    def test_exec_pod(self):
        rules = [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["get"]}]
        assert "exec_pod" in _infer_capabilities(rules)

    def test_escalate_rbac(self):
        rules = [{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"], "verbs": ["bind"]}]
        assert "escalate_rbac" in _infer_capabilities(rules)

    def test_node_access(self):
        rules = [{"apiGroups": [""], "resources": ["nodes"], "verbs": ["get", "list"]}]
        assert "node_access" in _infer_capabilities(rules)

    def test_create_workload(self):
        rules = [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["create", "update"]}]
        assert "create_workload" in _infer_capabilities(rules)

    def test_cluster_admin_wildcard(self):
        rules = [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        assert "cluster_admin" in _infer_capabilities(rules)

    def test_multiple_capabilities(self):
        rules = [
            {"apiGroups": [""], "resources": ["secrets", "pods"], "verbs": ["get", "list", "create"]},
        ]
        caps = _infer_capabilities(rules)
        assert "read_secrets" in caps
        assert "create_pod" in caps

    def test_safe_rule_ignored(self):
        rules = [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]
        assert _infer_capabilities(rules) == set()

    def test_aggregation_rules_grammar(self):
        """All _DANGEROUS_PATTERNS have valid structure."""
        for verbs, resources, cap_name in _DANGEROUS_PATTERNS:
            assert isinstance(verbs, set)
            assert isinstance(resources, set)
            assert isinstance(cap_name, str)
            assert len(verbs) > 0
            assert len(resources) > 0


# ---------------------------------------------------------------------------
# unit tests: edge type inference
# ---------------------------------------------------------------------------

class TestInferEdgeType:
    """Test capability-set -> edge_type mapping."""

    def test_cluster_admin_impersonate(self):
        assert _infer_edge_type_from_caps({"cluster_admin"}) == "Impersonate"

    def test_impersonate(self):
        assert _infer_edge_type_from_caps({"impersonate"}) == "Impersonate"

    def test_node_access(self):
        assert _infer_edge_type_from_caps({"node_access"}) == "NodeAccess"

    def test_read_secrets_token_access(self):
        assert _infer_edge_type_from_caps({"read_secrets"}) == "TokenAccess"

    def test_escalate_rbac(self):
        assert _infer_edge_type_from_caps({"escalate_rbac"}) == "RbacEdge"

    def test_create_pod(self):
        assert _infer_edge_type_from_caps({"create_pod"}) == "PodTrust"

    def test_empty_falls_back_to_observation(self):
        assert _infer_edge_type_from_caps(set()) == "ObservationEdge"

    def test_priority_impersonate_over_other(self):
        assert _infer_edge_type_from_caps({"impersonate", "read_secrets"}) == "Impersonate"


# ---------------------------------------------------------------------------
# unit tests: risk level inference
# ---------------------------------------------------------------------------

class TestInferRiskLevel:
    """Test capability-set -> RiskLevel mapping."""

    def test_cluster_admin_critical(self):
        assert _infer_risk_level({"cluster_admin"}) == RiskLevel.CRITICAL

    def test_impersonate_critical(self):
        assert _infer_risk_level({"impersonate"}) == RiskLevel.CRITICAL

    def test_escalate_critical(self):
        assert _infer_risk_level({"escalate_rbac"}) == RiskLevel.CRITICAL

    def test_node_access_high(self):
        assert _infer_risk_level({"node_access"}) == RiskLevel.HIGH

    def test_read_secrets_high(self):
        assert _infer_risk_level({"read_secrets"}) == RiskLevel.HIGH

    def test_create_workload_medium(self):
        assert _infer_risk_level({"create_workload"}) == RiskLevel.MEDIUM

    def test_empty_low(self):
        assert _infer_risk_level(set()) == RiskLevel.LOW


# ---------------------------------------------------------------------------
# unit tests: rule summary
# ---------------------------------------------------------------------------

class TestRuleSummary:
    """Test rule list -> compact dict conversion."""

    def test_empty_rules(self):
        assert _rule_summary([]) == {"verbs": [], "resources": []}

    def test_single_rule(self):
        result = _rule_summary([{"verbs": ["get"], "resources": ["pods"]}])
        assert result == {"verbs": ["get"], "resources": ["pods"]}

    def test_merges_multiple_rules(self):
        rules = [
            {"verbs": ["get", "list"], "resources": ["pods"]},
            {"verbs": ["create"], "resources": ["deployments"]},
        ]
        result = _rule_summary(rules)
        assert "get" in result["verbs"]
        assert "list" in result["verbs"]
        assert "create" in result["verbs"]
        assert "pods" in result["resources"]
        assert "deployments" in result["resources"]


# ---------------------------------------------------------------------------
# unit tests: infrastructure edges
# ---------------------------------------------------------------------------

class TestInfrastructureEdges:
    """Test static K8s component topology edges."""

    def test_seven_edges(self):
        edges = _build_infrastructure_edges()
        assert len(edges) == 7

    def test_all_are_trust_edges(self):
        for e in _build_infrastructure_edges():
            assert isinstance(e, TrustEdge)

    def test_all_have_default_source(self):
        for e in _build_infrastructure_edges():
            assert e.metadata["source"] == EdgeSource.DEFAULT.value

    def test_etcd_edge_is_critical(self):
        for e in _build_infrastructure_edges():
            if e.target == "etcd":
                assert e.risk == RiskLevel.CRITICAL

    def test_container_runtime_edge_not_rotated(self):
        for e in _build_infrastructure_edges():
            if e.target == "container-runtime":
                assert e.auto_rotated is False

    def test_infra_edges_match_spec(self):
        """Every edge in _INFRA_EDGES has required keys."""
        for e in _INFRA_EDGES:
            assert "s" in e
            assert "t" in e
            assert "r" in e
            assert "risk" in e
            assert "rot" in e


# ---------------------------------------------------------------------------
# integration tests: build_live_rbac_edges with mocked API
# ---------------------------------------------------------------------------

class TestBuildLiveRbacEdgesMocked:
    """Test edge generation with mocked K8s API responses."""

    @pytest.fixture
    def mock_clients(self):
        """Patch _get_k8s_clients to return mock API objects."""
        with patch("k8s_arsenal.recon.rbac_adapter._get_k8s_clients") as mock_get:
            core = MagicMock()
            rbac = MagicMock()
            apps = MagicMock()
            mock_get.return_value = (core, rbac, apps)
            yield core, rbac, apps

    def test_no_service_accounts(self, mock_clients):
        core, rbac, apps = mock_clients
        # Return empty namespace list
        ns_mock = MagicMock()
        ns_mock.items = []
        core.list_namespace.return_value = ns_mock

        edges = build_live_rbac_edges(include_infrastructure=False)
        assert edges == []

    def test_sa_with_no_dangerous_rules(self, mock_clients):
        core, rbac, apps = mock_clients
        # One namespace
        ns_mock = MagicMock()
        ns_mock.items = [MagicMock()]
        ns_mock.items[0].metadata.name = "default"
        core.list_namespace.return_value = ns_mock

        # One SA
        sa_mock = MagicMock()
        sa_mock.items = [MagicMock()]
        sa_mock.items[0].metadata.name = "test-sa"
        core.list_namespaced_service_account.return_value = sa_mock

        # No RoleBindings or ClusterRoleBindings
        rb_mock = MagicMock()
        rb_mock.items = []
        rbac.list_namespaced_role_binding.return_value = rb_mock
        crb_mock = MagicMock()
        crb_mock.items = []
        rbac.list_cluster_role_binding.return_value = crb_mock

        edges = build_live_rbac_edges(include_infrastructure=False)
        assert edges == []

    def test_sa_with_impersonate_binding(self, mock_clients):
        core, rbac, apps = mock_clients
        # One namespace
        ns_mock = MagicMock()
        ns_mock.items = [MagicMock()]
        ns_mock.items[0].metadata.name = "default"
        core.list_namespace.return_value = ns_mock

        # Two SAs
        sa1 = MagicMock()
        sa1.metadata.name = "attacker-sa"
        sa2 = MagicMock()
        sa2.metadata.name = "victim-sa"
        sa_mock = MagicMock()
        sa_mock.items = [sa1, sa2]
        core.list_namespaced_service_account.return_value = sa_mock

        # Attacker SA has ClusterRoleBinding with impersonate
        crb = MagicMock()
        subj = MagicMock()
        subj.kind = "ServiceAccount"
        subj.name = "attacker-sa"
        subj.namespace = "default"
        crb.subjects = [subj]
        crb.role_ref.name = "impersonator-cr"
        crb_mock = MagicMock()
        crb_mock.items = [crb]
        rbac.list_cluster_role_binding.return_value = crb_mock

        # No RoleBindings
        rb_mock = MagicMock()
        rb_mock.items = []
        rbac.list_namespaced_role_binding.return_value = rb_mock

        # ClusterRole has impersonate rule
        cr = MagicMock()
        rule = MagicMock()
        rule.api_groups = [""]
        rule.resources = ["users", "groups", "serviceaccounts"]
        rule.verbs = ["impersonate"]
        cr.rules = [rule]
        rbac.read_cluster_role.return_value = cr

        edges = build_live_rbac_edges(include_infrastructure=False)
        assert len(edges) > 0
        assert any(e.relationship == "Impersonate" for e in edges)

    def test_infrastructure_included_by_default(self, mock_clients):
        core, rbac, apps = mock_clients
        ns_mock = MagicMock()
        ns_mock.items = []
        core.list_namespace.return_value = ns_mock

        edges = build_live_rbac_edges(include_infrastructure=True)
        assert len(edges) == 7  # Only infrastructure edges
        assert all(e.metadata["source"] == EdgeSource.DEFAULT.value for e in edges)


# ---------------------------------------------------------------------------
# integration tests: build_live_topology compatibility
# ---------------------------------------------------------------------------

class TestBuildLiveTopology:
    """Test drop-in compatibility with build_trust_topology()."""

    def test_fallback_without_k8s_client(self):
        """Without kubernetes client installed, returns infrastructure edges."""
        with patch("k8s_arsenal.recon.rbac_adapter.HAS_K8S_CLIENT", False):
            edges = build_live_topology()
            assert len(edges) == 7

    def test_empty_profile_adds_no_docker_edge(self):
        with patch("k8s_arsenal.recon.rbac_adapter.HAS_K8S_CLIENT", False):
            edges = build_live_topology(profile=EnvironmentProfile())
            assert len(edges) == 7

    def test_docker_sock_profile_adds_edge(self):
        with patch("k8s_arsenal.recon.rbac_adapter.HAS_K8S_CLIENT", False):
            profile = EnvironmentProfile(
                is_kubernetes=True,
                mounted_docker_sock=True,
            )
            edges = build_live_topology(profile=profile)
            docker_edges = [e for e in edges if e.metadata.get("edge_type") == "DockerSocket"]
            assert len(docker_edges) == 1

    def test_sa_profile_adds_pod_trust_edge(self):
        with patch("k8s_arsenal.recon.rbac_adapter.HAS_K8S_CLIENT", False):
            profile = EnvironmentProfile(
                is_kubernetes=True,
                service_account="my-sa",
            )
            edges = build_live_topology(profile=profile)
            sa_edges = [
                e for e in edges
                if e.source == "pod/my-sa" and e.target == "kube-apiserver"
            ]
            assert len(sa_edges) == 1

    def test_returns_trust_edge_objects(self):
        with patch("k8s_arsenal.recon.rbac_adapter.HAS_K8S_CLIENT", False):
            edges = build_live_topology()
            for e in edges:
                assert isinstance(e, TrustEdge)
                assert isinstance(e.risk, RiskLevel)
                assert "edge_type" in e.metadata
                assert "source" in e.metadata