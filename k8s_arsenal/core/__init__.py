"""核心引擎模块

自适应攻击引擎与攻击向量优化器。
"""

from k8s_arsenal.core.engine import (
    AdaptiveEngine,
    BattlefieldAssessment,
    run_battlefield_assessment,
)
from k8s_arsenal.core.optimizer import (
    AttackVectorOptimizer,
    OptimizedSequence,
    ScoredVector,
    optimize_chain,
    prioritize_vectors,
)

__all__ = [
    "AdaptiveEngine",
    "BattlefieldAssessment",
    "run_battlefield_assessment",
    "AttackVectorOptimizer",
    "OptimizedSequence",
    "ScoredVector",
    "optimize_chain",
    "prioritize_vectors",
]
