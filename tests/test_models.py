"""Tests for k8s_arsenal.models — data model definitions."""

import pytest
from k8s_arsenal.models import AttackVector, AttackPath, AttackPhase, RiskLevel


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
