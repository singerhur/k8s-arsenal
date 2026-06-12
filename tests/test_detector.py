"""Tests for container escape detector module.""" 

import pytest
from k8s_arsenal.escape.detector import (
    detect_escape_vectors,
    _check_vector_conditions,
    _evaluate_condition,
    get_escape_risk_assessment,
)
from k8s_arsenal.models import EnvironmentProfile, AttackPhase, RiskLevel
from k8s_arsenal.escape.vectors import ESCAPE_VECTORS


class TestEvaluateCondition:
    def test_privileged_true(self, privileged_profile):
        assert _evaluate_condition("privileged", privileged_profile) is True

    def test_privileged_false(self, unprivileged_profile):
        assert _evaluate_condition("privileged", unprivileged_profile) is False

    def test_host_pid_true(self, privileged_profile):
        assert _evaluate_condition("hostPID", privileged_profile) is True

    def test_host_network_true(self, privileged_profile):
        assert _evaluate_condition("hostNetwork", privileged_profile) is True

    def test_docker_sock_true(self, privileged_profile):
        assert _evaluate_condition("docker_sock", privileged_profile) is True

    def test_is_container_true(self, privileged_profile):
        assert _evaluate_condition("is_container", privileged_profile) is True

    def test_is_container_false(self, non_k8s_profile):
        assert _evaluate_condition("is_container", non_k8s_profile) is False

    def test_cap_check_present(self, privileged_profile):
        assert _evaluate_condition("CAP_SYS_ADMIN", privileged_profile) is True

    def test_cap_check_absent(self, unprivileged_profile):
        assert _evaluate_condition("CAP_SYS_ADMIN", unprivileged_profile) is False

    def test_unknown_condition(self, privileged_profile):
        assert _evaluate_condition("bogus_condition", privileged_profile) is False


class TestDetectEscapeVectors:
    def test_privileged_detects_vectors(self, privileged_profile):
        vectors = detect_escape_vectors(privileged_profile)
        ids = [v.id for v in vectors]
        assert "ESC-001" in ids  # nsenter (hostPID + SYS_ADMIN)
        assert "ESC-002" in ids  # Docker socket

    def test_unprivileged_returns_fewer(self, unprivileged_profile, privileged_profile):
        privileged_count = len(detect_escape_vectors(privileged_profile))
        unpriv_count = len(detect_escape_vectors(unprivileged_profile))
        assert unpriv_count <= privileged_count

    def test_non_k8s_returns_none(self, non_k8s_profile):
        vectors = detect_escape_vectors(non_k8s_profile)
        assert len(vectors) == 0

    def test_returns_escape_vector_type(self, privileged_profile):
        vectors = detect_escape_vectors(privileged_profile)
        for v in vectors:
            assert hasattr(v, "id")
            assert hasattr(v, "name")
            assert hasattr(v, "phase")
            assert hasattr(v, "risk")


class TestRiskAssessment:
    def test_assessment_returns_dict(self, privileged_profile):
        result = get_escape_risk_assessment(privileged_profile)
        assert isinstance(result, dict)
        assert "total_vectors" in result
        assert "summary" in result
        assert result["total_vectors"] > 0

    def test_assessment_safe_profile(self, non_k8s_profile):
        result = get_escape_risk_assessment(non_k8s_profile)
        assert result["total_vectors"] == 0
        assert "安全" in result["summary"]

    def test_assessment_unprivileged(self, unprivileged_profile):
        result = get_escape_risk_assessment(unprivileged_profile)
        assert isinstance(result, dict)
        assert result["total_vectors"] >= 0

    def test_assessment_vectors_list(self, privileged_profile):
        result = get_escape_risk_assessment(privileged_profile)
        for v in result["vectors"]:
            assert "id" in v
            assert "name" in v

    def test_assessment_counts(self, privileged_profile):
        result = get_escape_risk_assessment(privileged_profile)
        expected = result["critical"] + result["high"] + result["medium"] + result["low"]
        assert expected >= result["total_vectors"]
