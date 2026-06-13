"""Tests for k8s_arsenal.models — data model definitions."""

import pytest
from k8s_arsenal.models import AttackVector, AttackPath, AttackPhase, RiskLevel, TrustEdge, EdgeSource


class TestAttackPhase:
    def test_all_phases_defined(self):
        """All standard attack phases should be defined"""
        phases = list(AttackPhase)
        assert len(phases) >= 10
        assert AttackPhase.DISCOVERY in phases
        assert AttackPhase.PERSISTENCE in phases
        assert AttackPhase.PRIVILEGE_ESCALATION in phases
        assert AttackPhase.DEFENSE_EVASION in phases

    def test_phase_values_are_strings(self):
        for phase in AttackPhase:
            assert isinstance(phase.value, str)
            assert len(phase.value) > 0


class TestRiskLevel:
    def test_risk_levels_defined(self):
        assert RiskLevel.CRITICAL
        assert RiskLevel.HIGH
        assert RiskLevel.MEDIUM
        assert RiskLevel.LOW

    def test_risk_values_are_strings(self):
        for rl in RiskLevel:
            assert isinstance(rl.value, str)


class TestAttackVector:
    def test_create_minimal_vector(self):
        v = AttackVector(
            id="T-001",
            name="Test Vector",
            phase=AttackPhase.DISCOVERY,
            risk=RiskLevel.LOW,
            description="A test",
        )
        assert v.id == "T-001"
        assert v.name == "Test Vector"
        assert v.phase == AttackPhase.DISCOVERY
        assert v.risk == RiskLevel.LOW
        assert v.description == "A test"
        assert v.prerequisites == []
        assert v.steps == []
        assert v.detection_hints == []

    def test_create_full_vector(self):
        v = AttackVector(
            id="T-002",
            name="Full Vector",
            phase=AttackPhase.PERSISTENCE,
            risk=RiskLevel.CRITICAL,
            description="Full description",
            prerequisites=["root access", "API server"],
            steps=["Step 1", "Step 2"],
            detection_hints=["Check logs"],
        )
        assert len(v.prerequisites) == 2
        assert len(v.steps) == 2
        assert len(v.detection_hints) == 1


class TestAttackPath:
    def test_create_attack_path(self):
        vectors = [
            AttackVector(id="C-1", name="Step 1", phase=AttackPhase.DISCOVERY, risk=RiskLevel.LOW, description="desc"),
            AttackVector(id="C-2", name="Step 2", phase=AttackPhase.PERSISTENCE, risk=RiskLevel.CRITICAL, description="desc2"),
        ]
        path = AttackPath(
            id="PB-T",
            name="Test Playbook",
            description="A test playbook",
            difficulty=RiskLevel.HIGH,
            estimated_time="1 hour",
            vectors=vectors,
        )

        assert path.id == "PB-T"
        assert len(path.vectors) == 2
        assert path.difficulty == RiskLevel.HIGH
        assert path.estimated_time == "1 hour"

    def test_empty_path(self):
        path = AttackPath(
            id="EMPTY",
            name="Empty",
            description="No vectors",
            difficulty=RiskLevel.LOW,
            estimated_time="N/A",
        )
        assert len(path.vectors) == 0


class TestEdgeSource:
    def test_edge_source_values(self):
        assert EdgeSource.OBSERVATION.value == "observation"
        assert EdgeSource.INFERENCE.value == "inference"
        assert EdgeSource.DEFAULT.value == "default"

    def test_edge_source_members(self):
        values = [e.value for e in EdgeSource]
        assert "observation" in values
        assert "inference" in values
        assert "default" in values


class TestTrustEdge:
    def test_create_minimal_edge(self):
        e = TrustEdge(
            source="sa-a",
            target="sa-b",
            relationship="RoleBinding",
        )
        assert e.source == "sa-a"
        assert e.target == "sa-b"
        assert e.relationship == "RoleBinding"
        assert e.auto_rotated is False
        assert e.risk == RiskLevel.MEDIUM
        assert e.metadata == {}

    def test_edge_with_metadata_observation(self):
        e = TrustEdge(
            source="ci-ns/ci-sa",
            target="prod-ns/ci-admin",
            relationship="RoleBinding: Role/ci-admin",
            credential_type="RBAC: RoleBinding",
            auto_rotated=False,
            risk=RiskLevel.HIGH,
            metadata={
                "source": EdgeSource.OBSERVATION.value,
                "evidence": {
                    "type": "RoleBinding",
                    "name": "ci-admin-binding",
                    "namespace": "prod-ns",
                },
            },
        )
        assert e.metadata["source"] == "observation"
        assert e.metadata["evidence"]["type"] == "RoleBinding"
        assert e.metadata["evidence"]["namespace"] == "prod-ns"

    def test_edge_with_metadata_inference(self):
        e = TrustEdge(
            source="prod-ns/ci-admin",
            target="prod-ns/prod-app-sa",
            relationship="Role capability derivation",
            credential_type="RBAC: verbs=create",
            auto_rotated=False,
            risk=RiskLevel.HIGH,
            metadata={
                "source": EdgeSource.INFERENCE.value,
                "derived_from": ["ci-ns/ci-sa->prod-ns/ci-admin"],
                "capability": {
                    "verbs": ["create", "get"],
                    "resources": ["deployments"],
                },
                "reasoning": "ci-admin can create deployments -> can deploy pods with prod-app-sa",
            },
        )
        assert e.metadata["source"] == "inference"
        assert len(e.metadata["derived_from"]) == 1
        assert "deployments" in e.metadata["capability"]["resources"]

    def test_edge_with_metadata_default(self):
        e = TrustEdge(
            source="any-sa",
            target="kube-apiserver",
            relationship="Standard SA Token",
            credential_type="ServiceAccount Token (JWT)",
            auto_rotated=True,
            risk=RiskLevel.MEDIUM,
            metadata={
                "source": EdgeSource.DEFAULT.value,
                "reasoning": "Every SA has default JWT token",
            },
        )
        assert e.metadata["source"] == "default"
        assert e.auto_rotated is True

    def test_edges_can_be_distinguished_by_source(self):
        """可以按 metadata.source 区分观测边和推导边"""
        obs = TrustEdge(
            source="a", target="b", relationship="X",
            metadata={"source": "observation"},
        )
        inf = TrustEdge(
            source="c", target="d", relationship="Y",
            metadata={"source": "inference"},
        )
        edges = [obs, inf]
        obs_edges = [e for e in edges if e.metadata.get("source") == "observation"]
        inf_edges = [e for e in edges if e.metadata.get("source") == "inference"]
        assert len(obs_edges) == 1
        assert len(inf_edges) == 1
