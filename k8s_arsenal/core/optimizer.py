"""攻击向量优化器

对攻击向量进行多维评分排序和序列优化。
支持可自定义的评分权重，适配不同战场环境。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel
from k8s_arsenal.utils.cache import cached


# 基础评分数据库 — 从向量属性计算细分评分
_PHASE_IMPACT_WEIGHTS: dict[AttackPhase, float] = {
    AttackPhase.INITIAL_ACCESS: 0.6,
    AttackPhase.EXECUTION: 0.8,
    AttackPhase.PERSISTENCE: 0.9,
    AttackPhase.PRIVILEGE_ESCALATION: 0.95,
    AttackPhase.DEFENSE_EVASION: 0.5,
    AttackPhase.CREDENTIAL_ACCESS: 0.85,
    AttackPhase.DISCOVERY: 0.3,
    AttackPhase.LATERAL_MOVEMENT: 0.8,
    AttackPhase.COLLECTION: 0.5,
    AttackPhase.EXFILTRATION: 0.4,
    AttackPhase.IMPACT: 0.7,
}

_RISK_SPEED: dict[RiskLevel, float] = {
    RiskLevel.CRITICAL: 0.2,  # 高风险操作通常复杂且慢
    RiskLevel.HIGH: 0.4,
    RiskLevel.MEDIUM: 0.65,
    RiskLevel.LOW: 0.9,
    RiskLevel.INFO: 1.0,
}


@dataclass
class ScoredVector:
    """带多维评分的攻击向量"""

    vector: AttackVector
    success_score: float = 0.0   # 成功率 0-1
    stealth_score: float = 0.0   # 隐蔽性 0-1
    speed_score: float = 0.0     # 执行速度 0-1
    impact_score: float = 0.0    # 影响力 0-1
    composite_score: float = 0.0 # 加权综合评分

    def __repr__(self) -> str:
        return (
            f"ScoredVector({self.vector.id!r}, "
            f"cmps={self.composite_score:.2f}, "
            f"s={self.success_score:.2f}, "
            f"st={self.stealth_score:.2f}, "
            f"sp={self.speed_score:.2f}, "
            f"i={self.impact_score:.2f})"
        )


@dataclass
class OptimizedSequence:
    """优化后的攻击序列"""

    name: str
    vectors: list[AttackVector] = field(default_factory=list)
    total_composite: float = 0.0
    total_stealth: float = 0.0
    estimated_steps: int = 0
    phase_coverage: list[AttackPhase] = field(default_factory=list)
    risk_factors: list[str] = field(default_factory=list)


class AttackVectorOptimizer:
    """攻击向量优化器

    多维评分 + 优先级排序 + 序列优化。
    权重可通过构造参数自定义或由 AdaptiveEngine 动态提供。
    """

    def __init__(self, weights: Optional[dict[str, float]] = None) -> None:
        self.weights = weights or {
            "success": 0.35,
            "stealth": 0.30,
            "speed": 0.15,
            "impact": 0.20,
        }

    # ------------------------------------------------------------------
    # 评分
    # ------------------------------------------------------------------

    def score_vector(self, vector: AttackVector) -> ScoredVector:
        """对单个攻击向量进行多维评分

        评分维度:
        - success: 基于风险等级和前置条件复杂度
        - stealth: 基于检测提示数量和阶段特征
        - speed: 基于步骤数和风险等级
        - impact: 基于攻击阶段和风险等级
        """
        sv = ScoredVector(vector=vector)

        sv.success_score = self._score_success(vector)
        sv.stealth_score = self._score_stealth(vector)
        sv.speed_score = self._score_speed(vector)
        sv.impact_score = self._score_impact(vector)

        sv.composite_score = (
            self.weights["success"] * sv.success_score
            + self.weights["stealth"] * sv.stealth_score
            + self.weights["speed"] * sv.speed_score
            + self.weights["impact"] * sv.impact_score
        )

        return sv

    def score_vectors(self, vectors: list[AttackVector]) -> list[ScoredVector]:
        """批量评分"""
        return [self.score_vector(v) for v in vectors]

    # ------------------------------------------------------------------
    # 排序
    # ------------------------------------------------------------------

    @cached()
    def prioritize(
        self,
        vectors: list[AttackVector],
        top_n: Optional[int] = None,
    ) -> list[ScoredVector]:
        """按综合评分降序排列攻击向量

        Args:
            vectors: 待评分向量
            top_n: 返回 top N，None 返回全部
        """
        scored = self.score_vectors(vectors)
        scored.sort(key=lambda sv: sv.composite_score, reverse=True)
        return scored[:top_n] if top_n is not None else scored

    def prioritize_by_phase(
        self,
        vectors: list[AttackVector],
        phases: list[AttackPhase],
    ) -> dict[str, list[ScoredVector]]:
        """按攻击阶段分组后分别排序"""
        result: dict[str, list[ScoredVector]] = {}
        for phase in phases:
            phase_vectors = [v for v in vectors if v.phase == phase]
            if phase_vectors:
                result[phase.value] = self.prioritize(phase_vectors)
        return result

    # ------------------------------------------------------------------
    # 序列优化
    # ------------------------------------------------------------------

    def optimize_sequence(
        self,
        vectors: list[AttackVector],
        phases: Optional[list[AttackPhase]] = None,
        max_depth: int = 6,
    ) -> OptimizedSequence:
        """生成优化后的攻击序列

        按阶段顺序遍历，每阶段选评分最高的向量。
        自动跳过不适用的阶段。

        Args:
            vectors: 待优化的所有攻击向量
            phases: 目标攻击阶段序列，None 则自动按攻击链顺序
            max_depth: 最大序列长度
        """
        if phases is None:
            phases = [
                AttackPhase.DISCOVERY,
                AttackPhase.INITIAL_ACCESS,
                AttackPhase.EXECUTION,
                AttackPhase.PRIVILEGE_ESCALATION,
                AttackPhase.CREDENTIAL_ACCESS,
                AttackPhase.LATERAL_MOVEMENT,
                AttackPhase.PERSISTENCE,
                AttackPhase.DEFENSE_EVASION,
                AttackPhase.COLLECTION,
                AttackPhase.EXFILTRATION,
                AttackPhase.IMPACT,
            ]

        scored_by_phase = self.prioritize_by_phase(vectors, phases)
        seq_vectors: list[AttackVector] = []
        phase_used: list[AttackPhase] = []
        risks: list[str] = []

        for phase in phases[:max_depth]:
            scored = scored_by_phase.get(phase.value, [])
            if not scored:
                continue

            # 选择该阶段评分最高的向量
            best = scored[0]
            seq_vectors.append(best.vector)
            phase_used.append(phase)

            # 如果向量有 CVE 标注或高风险，记录
            if hasattr(best.vector, "cve") and best.vector.cve:
                risks.append(f"{best.vector.id}: CVE-{best.vector.cve}")
            if best.vector.risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                if best.vector.id not in risks:
                    risks.append(f"{best.vector.id}: {best.vector.risk.value} risk")

        total_composite = sum(
            self.score_vector(v).composite_score for v in seq_vectors
        ) / max(len(seq_vectors), 1)

        total_stealth = sum(
            self._score_stealth(v) for v in seq_vectors
        ) / max(len(seq_vectors), 1)

        return OptimizedSequence(
            name="optimized-chain",
            vectors=seq_vectors,
            total_composite=round(total_composite, 3),
            total_stealth=round(total_stealth, 3),
            estimated_steps=sum(len(v.steps) for v in seq_vectors),
            phase_coverage=phase_used,
            risk_factors=risks,
        )

    # ------------------------------------------------------------------
    # 内部评分函数
    # ------------------------------------------------------------------

    def _score_success(self, v: AttackVector) -> float:
        """成功率评分"""
        score = 0.5

        # 风险越低 → 成功率越高
        if v.risk == RiskLevel.LOW:
            score += 0.3
        elif v.risk == RiskLevel.MEDIUM:
            score += 0.15
        elif v.risk == RiskLevel.HIGH:
            score -= 0.1
        elif v.risk == RiskLevel.CRITICAL:
            score -= 0.2

        # 前置条件少 → 更容易成功
        if len(v.prerequisites) <= 1:
            score += 0.15
        elif len(v.prerequisites) <= 3:
            score += 0.05

        # CVE 标注 → 有已知漏洞利用，成功率更高
        if v.cve:
            score += 0.1

        return max(0.0, min(1.0, score))

    def _score_stealth(self, v: AttackVector) -> float:
        """隐蔽性评分"""
        score = 0.5

        # 检测提示多 → 不隐蔽
        if len(v.detection_hints) == 0:
            score += 0.3
        elif len(v.detection_hints) <= 2:
            score += 0.1
        elif len(v.detection_hints) >= 5:
            score -= 0.2

        # 某些阶段天然更隐蔽
        stealthy_phases = {
            AttackPhase.DEFENSE_EVASION,
            AttackPhase.CREDENTIAL_ACCESS,
            AttackPhase.DISCOVERY,
        }
        if v.phase in stealthy_phases:
            score += 0.15

        # noisy 阶段
        noisy_phases = {
            AttackPhase.EXECUTION,
            AttackPhase.EXFILTRATION,
            AttackPhase.IMPACT,
        }
        if v.phase in noisy_phases:
            score -= 0.15

        # 步骤多 → 暴露窗口大
        if len(v.steps) > 5:
            score -= 0.15

        return max(0.0, min(1.0, score))

    def _score_speed(self, v: AttackVector) -> float:
        """执行速度评分"""
        # 步骤数直接映射到速度
        steps = len(v.steps)
        if steps == 0:
            return 1.0
        elif steps <= 2:
            return 0.9
        elif steps <= 4:
            return 0.7
        elif steps <= 7:
            return 0.5
        else:
            return 0.3

    def _score_impact(self, v: AttackVector) -> float:
        """影响力评分"""
        score = 0.5

        # 风险越高 → 影响力越大
        if v.risk == RiskLevel.CRITICAL:
            score += 0.3
        elif v.risk == RiskLevel.HIGH:
            score += 0.15
        elif v.risk == RiskLevel.LOW:
            score -= 0.15

        # 使用阶段权重
        phase_weight = _PHASE_IMPACT_WEIGHTS.get(v.phase, 0.5)
        score = score * 0.4 + phase_weight * 0.6

        return max(0.0, min(1.0, score))

    # ------------------------------------------------------------------
    # 便利方法
    # ------------------------------------------------------------------

    def get_top_by_phase(
        self, vectors: list[AttackVector], phase: AttackPhase, n: int = 3
    ) -> list[ScoredVector]:
        """获取某个阶段评分最高的 n 个向量"""
        phase_vectors = [v for v in vectors if v.phase == phase]
        return self.prioritize(phase_vectors, top_n=n)

    def compare_vectors(self, vectors: list[AttackVector]) -> str:
        """生成向量评分对比表（供 CLI 展示）"""
        scored = self.prioritize(vectors)
        lines = [f"{'Rank':<5} {'ID':<30} {'Composite':<10} {'Suc':<6} {'Stl':<6} {'Spd':<6} {'Imp':<6}"]
        lines.append("-" * 75)
        for i, sv in enumerate(scored, 1):
            lines.append(
                f"{i:<5} {sv.vector.id:<30} {sv.composite_score:<10.3f} "
                f"{sv.success_score:<6.3f} {sv.stealth_score:<6.3f} "
                f"{sv.speed_score:<6.3f} {sv.impact_score:<6.3f}"
            )
        return "\n".join(lines)


# 模块级便捷函数
def prioritize_vectors(
    vectors: list[AttackVector],
    weights: Optional[dict[str, float]] = None,
    top_n: Optional[int] = None,
) -> list[ScoredVector]:
    """便捷函数：评分+排序"""
    opt = AttackVectorOptimizer(weights)
    return opt.prioritize(vectors, top_n=top_n)


def optimize_chain(
    vectors: list[AttackVector],
    weights: Optional[dict[str, float]] = None,
    max_depth: int = 6,
) -> OptimizedSequence:
    """便捷函数：生成最优攻击序列"""
    opt = AttackVectorOptimizer(weights)
    return opt.optimize_sequence(vectors, max_depth=max_depth)
