"""优化器模块测试"""
import pytest
from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel
from k8s_arsenal.core.optimizer import (
    AttackVectorOptimizer, ScoredVector, OptimizedSequence,
    prioritize_vectors, optimize_chain,
)
from k8s_arsenal.persistence.catalog import PERSISTENCE_VECTORS
from k8s_arsenal.lateral.movement import LATERAL_VECTORS
from k8s_arsenal.network.attacks import NETWORK_VECTORS


def _make_vector(id_: str, phase: AttackPhase, risk: RiskLevel,
                  prereqs: int = 0, steps: int = 3,
                  detection_hints: int = 2, cve: str = "") -> AttackVector:
    return AttackVector(
        id=id_, name=id_,
        phase=phase, risk=risk,
        description=f"Test vector {id_}",
        prerequisites=["p"] * prereqs,
        steps=["s"] * steps,
        detection_hints=["d"] * detection_hints,
        cve=cve or None,
    )


class TestScoredVector:
    """ScoredVector 测试"""

    def test_create(self):
        v = _make_vector("T-001", AttackPhase.PERSISTENCE, RiskLevel.HIGH)
        sv = ScoredVector(vector=v)
        assert sv.vector.id == "T-001"
        assert sv.composite_score == 0.0

    def test_repr(self):
        v = _make_vector("T-001", AttackPhase.PERSISTENCE, RiskLevel.HIGH)
        sv = ScoredVector(vector=v, composite_score=0.75)
        r = repr(sv)
        assert "T-001" in r
        assert "0.75" in r


class TestOptimizedSequence:
    """OptimizedSequence 测试"""

    def test_empty(self):
        seq = OptimizedSequence(name="empty")
        assert seq.name == "empty"
        assert seq.vectors == []
        assert seq.total_composite == 0.0


class TestAttackVectorOptimizer:
    """AttackVectorOptimizer 核心测试"""

    def test_init_default_weights(self):
        opt = AttackVectorOptimizer()
        assert opt.weights["success"] == 0.35
        assert opt.weights["stealth"] == 0.30
        assert opt.weights["speed"] == 0.15
        assert opt.weights["impact"] == 0.20

    def test_init_custom_weights(self):
        opt = AttackVectorOptimizer(weights={
            "success": 0.5, "stealth": 0.2, "speed": 0.1, "impact": 0.2
        })
        assert opt.weights["success"] == 0.5

    def test_score_vector_high_risk(self):
        """高风险向量 → 低成功率、高影响力"""
        v = _make_vector("T-HIGH", AttackPhase.PRIVILEGE_ESCALATION,
                          RiskLevel.CRITICAL, prereqs=5, steps=8, detection_hints=6)
        opt = AttackVectorOptimizer()
        sv = opt.score_vector(v)

        assert sv.success_score < 0.6
        assert sv.stealth_score < 0.5
        assert sv.speed_score < 0.4
        assert sv.impact_score > 0.5

    def test_score_vector_low_risk(self):
        """低风险向量 → 高成功率、中等影响力"""
        v = _make_vector("T-LOW", AttackPhase.DISCOVERY,
                          RiskLevel.LOW, prereqs=0, steps=1, detection_hints=0)
        opt = AttackVectorOptimizer()
        sv = opt.score_vector(v)

        assert sv.success_score > 0.7
        assert sv.stealth_score > 0.7
        assert sv.speed_score > 0.8

    def test_score_vector_cve(self):
        """CVE 标注 → 成功率提升"""
        v = _make_vector("T-CVE", AttackPhase.EXECUTION,
                          RiskLevel.HIGH, cve="2024-21626")
        opt = AttackVectorOptimizer()
        sv = opt.score_vector(v)
        assert sv.success_score > 0.3  # CVE gives +0.1 base

    def test_prioritize_empty(self):
        opt = AttackVectorOptimizer()
        result = opt.prioritize([])
        assert result == []

    def test_prioritize_ordering(self):
        """验证按综合评分降序"""
        v1 = _make_vector("T-1", AttackPhase.DISCOVERY, RiskLevel.LOW,
                           prereqs=0, steps=1, detection_hints=0)
        v2 = _make_vector("T-2", AttackPhase.PRIVILEGE_ESCALATION,
                           RiskLevel.CRITICAL, prereqs=5, steps=8, detection_hints=6)
        opt = AttackVectorOptimizer()
        scored = opt.prioritize([v1, v2])

        assert scored[0].composite_score >= scored[1].composite_score
        assert scored[0].vector.id == "T-1"  # low risk beats critical

    def test_prioritize_top_n(self):
        """top_n 限制"""
        v1 = _make_vector("A", AttackPhase.DISCOVERY, RiskLevel.LOW)
        v2 = _make_vector("B", AttackPhase.DISCOVERY, RiskLevel.LOW)
        v3 = _make_vector("C", AttackPhase.DISCOVERY, RiskLevel.LOW)
        opt = AttackVectorOptimizer()
        scored = opt.prioritize([v1, v2, v3], top_n=2)
        assert len(scored) == 2

    def test_prioritize_by_phase(self):
        """按阶段分组排序"""
        v1 = _make_vector("D-1", AttackPhase.DISCOVERY, RiskLevel.LOW)
        v2 = _make_vector("PE-1", AttackPhase.PRIVILEGE_ESCALATION, RiskLevel.HIGH)
        opt = AttackVectorOptimizer()
        result = opt.prioritize_by_phase(
            [v1, v2],
            [AttackPhase.DISCOVERY, AttackPhase.PRIVILEGE_ESCALATION],
        )
        assert "discovery" in result
        assert "privilege_escalation" in result
        assert len(result["discovery"]) == 1

    def test_optimize_sequence_real_vectors(self):
        """实战向量序列优化"""
        all_vectors = (list(PERSISTENCE_VECTORS) + list(LATERAL_VECTORS)
                       + list(NETWORK_VECTORS))
        opt = AttackVectorOptimizer()
        seq = opt.optimize_sequence(all_vectors, max_depth=4)

        assert isinstance(seq, OptimizedSequence)
        assert len(seq.vectors) > 0
        assert len(seq.vectors) <= 4
        assert seq.total_composite > 0
        assert seq.estimated_steps > 0

    def test_get_top_by_phase(self):
        """阶段取 top N"""
        opt = AttackVectorOptimizer()
        top = opt.get_top_by_phase(list(PERSISTENCE_VECTORS),
                                    AttackPhase.PERSISTENCE, n=3)
        assert len(top) <= 3
        for sv in top:
            assert sv.vector.phase == AttackPhase.PERSISTENCE

    def test_compare_vectors_output(self):
        """评分对比表输出"""
        opt = AttackVectorOptimizer()
        result = opt.compare_vectors(list(PERSISTENCE_VECTORS))
        assert "Rank" in result
        assert "Composite" in result
        assert "PER-" in result


class TestConvenienceFunctions:
    """便捷函数测试"""

    def test_prioritize_vectors(self):
        result = prioritize_vectors(list(PERSISTENCE_VECTORS))
        assert len(result) > 0
        assert isinstance(result[0], ScoredVector)

    def test_optimize_chain(self):
        all_vectors = (list(PERSISTENCE_VECTORS) + list(LATERAL_VECTORS))
        result = optimize_chain(all_vectors, max_depth=3)
        assert isinstance(result, OptimizedSequence)


class TestScoreConsistency:
    """评分一致性测试"""

    def test_composite_in_range(self):
        """综合评分始终在 [0, 1] 范围内"""
        opt = AttackVectorOptimizer()
        all_v = list(PERSISTENCE_VECTORS) + list(LATERAL_VECTORS) + list(NETWORK_VECTORS)
        for v in all_v:
            sv = opt.score_vector(v)
            assert 0.0 <= sv.success_score <= 1.0
            assert 0.0 <= sv.stealth_score <= 1.0
            assert 0.0 <= sv.speed_score <= 1.0
            assert 0.0 <= sv.impact_score <= 1.0
            assert 0.0 <= sv.composite_score <= 1.0

    def test_weights_sum_hint(self):
        """权重是独立系数，不需要保证和=1（但合理性检查）"""
        opt = AttackVectorOptimizer()
        assert abs(sum(opt.weights.values()) - 1.0) < 0.01
