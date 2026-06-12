"""Shared test fixtures for K8s Arsenal tests."""

import pytest
from k8s_arsenal.models import (
    EnvironmentProfile, AttackVector, AttackPath, EscapeVector,
    AttackPhase, RiskLevel,
)


@pytest.fixture
def privileged_profile() -> EnvironmentProfile:
    """高权限 Pod 环境画像 — privileged + hostPID + hostNetwork + docker sock"""
    return EnvironmentProfile(
        is_container=True,
        is_kubernetes=True,
        is_privileged=True,
        host_pid=True,
        host_network=True,
        host_ipc=False,
        capabilities=["CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE",
                       "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_DAC_READ_SEARCH"],
        mounted_docker_sock=True,
    )


@pytest.fixture
def unprivileged_profile() -> EnvironmentProfile:
    """低权限 Pod 环境画像 — 默认限制容器"""
    return EnvironmentProfile(
        is_container=True,
        is_kubernetes=True,
        is_privileged=False,
        host_pid=False,
        host_network=False,
        host_ipc=False,
        capabilities=[],
        mounted_docker_sock=False,
    )


@pytest.fixture
def non_k8s_profile() -> EnvironmentProfile:
    """非 K8s 环境（非容器）"""
    return EnvironmentProfile(
        is_container=False,
        is_kubernetes=False,
        is_privileged=False,
        host_pid=False,
        host_network=False,
        host_ipc=False,
        capabilities=[],
        mounted_docker_sock=False,
    )


@pytest.fixture
def sample_vector() -> AttackVector:
    return AttackVector(
        id="V-001", name="Sample Vector",
        phase=AttackPhase.DISCOVERY, risk=RiskLevel.LOW,
        description="A sample attack vector for testing",
    )


@pytest.fixture
def sample_escape_vector() -> EscapeVector:
    return EscapeVector(
        id="ESC-001",
        name="Docker Socket Escape",
        required_conditions=["docker_sock", "is_container"],
        required_capabilities=["CAP_SYS_ADMIN"],
        description="Escape via mounted Docker socket",
        success_rate="high",
        detection_difficulty="medium",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.HIGH,
    )
