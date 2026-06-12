"""SmartAttackChain 测试"""
import pytest
from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel
from k8s_arsenal.playbook.chains import (
    SmartAttackChain, ScoredVector,
    AttackChainBuilder, print_smart_chain_score,
)
from k8s_arsenal.persistence.catalog import PERSISTENCE_VECTORS
from k8s_arsenal.lateral.movement import LATERAL_VECTORS


def _make_vector(id_: str, phase: AttackPhase, risk: RiskLevel,
                  detection_hints: int = 2) -> AttackVector:
    return AttackVector(
        id=id_, name=id_,
        phase=phase, risk=risk,
        description=f"Test {id_}",
        steps=["step1", "step2"],
        detection_hints=["hint"] * detection_hints,
    )


class TestSmartAttackChain:
    """SmartAttackChain 核心测试"""

    def test_init(self):
        sc = SmartAttackChain()
        assert len(sc._vectors) > 0
        assert sc._executed == []
        assert sc._blocked == []
        assert sc._feedback == []

    def test_init_custom_weights(self):
        sc = SmartAttackChain(optimizer_weights={
            "success": 0.5, "stealth": 0.2, "speed": 0.1, "impact": 0.2
        })
        assert sc._optimizer.weights["success"] == 0.5

    def test_init_custom_vectors(self):
        v1 = _make_vector("T-A", AttackPhase.DISCOVERY, RiskLevel.LOW)
        v2 = _make_vector("T-B", AttackPhase.PERSISTENCE, RiskLevel.HIGH)
        sc = SmartAttackChain(vectors=[v1, v2])
        assert len(sc._vectors) == 2

    def test_generate_optimal_chain(self):
        sc = SmartAttackChain()
        chain = sc.generate_optimal_chain(max_depth=4)

        assert len(chain) > 0
        assert len(chain) <= 4
        assert all(isinstance(sv, ScoredVector) for sv in chain)
        # 链按阶段顺序排列；每个阶段取评分最高的向量
        phases = {sv.vector.phase for sv in chain}
        assert len(phases) > 0

    def test_generate_stealth_priority(self):
        sc = SmartAttackChain()
        chain = sc.generate_optimal_chain(max_depth=4, stealth_priority=True)
        assert len(chain) > 0
        assert sc._optimizer.weights["stealth"] > 0.40

    def test_adapt_feedback_success(self):
        sc = SmartAttackChain()
        response = sc.adapt_to_feedback("PER-001", success=True)
        assert response["action"] == "continue"
        assert "PER-001" in sc._executed

    def test_adapt_feedback_detection_triggered(self):
        v_loud = _make_vector("T-LOUD", AttackPhase.EXECUTION, RiskLevel.HIGH,
                               detection_hints=5)
        sc = SmartAttackChain(vectors=[v_loud])
        response = sc.adapt_to_feedback("T-LOUD", success=True, detection_triggered=True)

        assert response["action"] == "recalibrate"
        assert sc._optimizer.weights["stealth"] > 0.40
        assert len(sc._blocked) > 0  # 5 detection_hints >= 4 → 被封锁

    def test_adapt_feedback_failure(self):
        sc = SmartAttackChain()
        response = sc.adapt_to_feedback("NONEXIST", success=False)

        assert response["action"] == "retry_or_skip"
        assert "fallback_vectors" in response

    def test_get_available_phases(self):
        sc = SmartAttackChain()
        phases = sc.get_available_phases()
        assert len(phases) > 0
        assert all(isinstance(p, AttackPhase) for p in phases)

    def test_get_progress_report(self):
        sc = SmartAttackChain()
        sc.adapt_to_feedback("PER-001", success=True)
        report = sc.get_progress_report()

        assert report["executed_vectors"] == ["PER-001"]
        assert report["feedback_count"] == 1
        assert "current_weights" in report

    def test_reset(self):
        sc = SmartAttackChain()
        sc.adapt_to_feedback("PER-001", success=True)
        sc.reset()

        assert sc._executed == []
        assert sc._blocked == []
        assert sc._feedback == []

    def test_block_loud_vectors(self):
        """使用高噪声自定义向量测试封锁逻辑"""
        v_loud = _make_vector("T-LOUD", AttackPhase.EXECUTION, RiskLevel.HIGH,
                               detection_hints=5)
        sc = SmartAttackChain(vectors=[v_loud])
        sc._block_loud_vectors()
        assert len(sc._blocked) > 0
        assert "T-LOUD" in sc._blocked

    def test_progress_after_multiple_steps(self):
        """多步执行后进度应正确累计"""
        sc = SmartAttackChain()
        sc.adapt_to_feedback("PER-001", success=True)
        sc.adapt_to_feedback("LAT-001", success=True)
        sc.adapt_to_feedback("NET-001", success=False)

        report = sc.get_progress_report()
        assert len(report["executed_vectors"]) >= 1
        assert report["feedback_count"] == 3


class TestSmartChainConvenience:
    """便捷函数测试"""

    def test_print_smart_chain_score(self):
        output = print_smart_chain_score(max_depth=4)
        assert "=" in output
        assert len(output) > 50

    def test_print_smart_chain_score_custom_vectors(self):
        v1 = _make_vector("T-1", AttackPhase.DISCOVERY, RiskLevel.LOW)
        v2 = _make_vector("T-2", AttackPhase.PERSISTENCE, RiskLevel.CRITICAL)
        output = print_smart_chain_score(vectors=[v1, v2], max_depth=2)
        assert "T-1" in output or "T-2" in output


class TestBackwardCompat:
    """确保旧 AttackChainBuilder 仍可用"""

    def test_old_build_chain(self):
        builder = AttackChainBuilder()
        chains = builder.build(entry_condition="low-privilege-sa")
        assert isinstance(chains, list)

    def test_old_build_composite(self):
        builder = AttackChainBuilder()
        chains = builder.build_composite()
        assert isinstance(chains, list)

    def test_old_get_all_phases(self):
        builder = AttackChainBuilder()
        phases = builder.get_all_phases()
        assert len(phases) > 0

    def test_old_kill_chain_coverage(self):
        builder = AttackChainBuilder()
        coverage = builder.get_kill_chain_coverage()
        assert len(coverage) > 0
