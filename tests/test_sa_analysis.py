"""Tests for ServiceAccount permission analysis module."""

import pytest
from k8s_arsenal.recon.sa_analysis import assess_permission_risk, HIGH_RISK_PERMISSIONS


class TestAssessPermissionRisk:
    def test_wildcard_is_critical(self):
        result = assess_permission_risk("*", ["*"])
        assert result["risk"] == "critical"
        assert "完全控制" in result["reason"]

    def test_wildcard_verbs_is_critical(self):
        result = assess_permission_risk("pods", ["*"])
        assert result["risk"] == "critical"

    def test_pods_exec_create_is_high(self):
        result = assess_permission_risk("pods/exec", ["create"])
        assert result["risk"] == "high"
        assert "Token" in result["reason"]

    def test_secrets_get_is_high(self):
        result = assess_permission_risk("secrets", ["get"])
        assert result["risk"] == "high"

    def test_clusterroles_bind_is_critical(self):
        result = assess_permission_risk("clusterroles", ["bind"])
        assert result["risk"] == "critical"

    def test_nodes_proxy_get_is_critical(self):
        result = assess_permission_risk("nodes/proxy", ["get"])
        assert result["risk"] == "critical"

    def test_mutating_webhook_create_is_critical(self):
        result = assess_permission_risk("mutatingwebhookconfigurations", ["create"])
        assert result["risk"] == "critical"

    def test_csr_create_is_high(self):
        result = assess_permission_risk("certificatesigningrequests", ["create"])
        assert result["risk"] == "high"

    def test_low_risk_permission(self):
        result = assess_permission_risk("pods", ["get"])
        assert result["risk"] == "low"

    def test_unknown_resource(self):
        result = assess_permission_risk("unknownresource", ["get"])
        assert result["risk"] == "low"

    def test_result_has_attack_path(self):
        result = assess_permission_risk("pods", ["create"])
        assert "attack_path" in result


class TestHighRiskPermissions:
    def test_high_risk_dict_not_empty(self):
        assert len(HIGH_RISK_PERMISSIONS) > 0

    def test_high_risk_keys_are_strings(self):
        for key in HIGH_RISK_PERMISSIONS:
            assert isinstance(key, str)

    def test_verbs_are_lists(self):
        for verbs in HIGH_RISK_PERMISSIONS.values():
            assert isinstance(verbs, list)
            assert len(verbs) > 0

    def test_all_pods_subresources_present(self):
        expected = {"pods", "pods/exec", "pods/log"}
        assert expected.issubset(set(HIGH_RISK_PERMISSIONS.keys()))
