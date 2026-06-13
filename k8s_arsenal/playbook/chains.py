"""攻击链组合引擎

基于入口条件和目标权限，组合现有攻击向量生成攻击链。
v0.3: 集成加权评分排序引擎，支持动态反馈调整。
"""

from __future__ import annotations

from typing import Any, Optional

from k8s_arsenal.models import (
    AttackVector, AttackPath, AttackPhase, RiskLevel,
    TrustEdge, AttackGraph,
)
from k8s_arsenal.persistence.catalog import PERSISTENCE_VECTORS
from k8s_arsenal.lateral.movement import LATERAL_VECTORS
from k8s_arsenal.network.attacks import NETWORK_VECTORS
from k8s_arsenal.supply_chain.catalog import SUPPLY_CHAIN_VECTORS
from k8s_arsenal.evasion.catalog import EVASION_VECTORS
from k8s_arsenal.playbook.templates import CHAIN_TEMPLATES

ALL_VECTORS = (
    list(PERSISTENCE_VECTORS)
    + list(LATERAL_VECTORS)
    + list(NETWORK_VECTORS)
    + list(SUPPLY_CHAIN_VECTORS)
    + list(EVASION_VECTORS)
)


class AttackChainBuilder:
    """攻击链构建器（基础版）

    根据入口条件与目标权限，从现有攻击向量中组合攻击链。
    """

    def __init__(self) -> None:
        self._vector_registry = {v.id: v for v in ALL_VECTORS}

    def build(
        self,
        entry_condition: str = "low-privilege-sa",
        target: str = "cluster-admin",
        max_depth: int = 6,
    ) -> list[AttackPath]:
        """基于模板构建攻击链

        Args:
            entry_condition: 入口条件标识
            target: 目标权限
            max_depth: 最大链长度

        Returns:
            匹配的攻击链列表
        """
        from k8s_arsenal.playbook.templates import get_playbook_by_entry

        templates = get_playbook_by_entry(entry_condition)
        if templates:
            return templates
        return []

    def build_composite(
        self,
        entry_condition: str = "low-privilege-sa",
        target: str = "cluster-admin",
    ) -> list[AttackPath]:
        """当无直接模板时，动态组合攻击向量生成攻击链"""
        chain = AttackPath(
            id="composite-001",
            name=f"{entry_condition} → {target} (动态组合)",
            description="自动组合的攻击链",
            difficulty=RiskLevel.HIGH,
            estimated_time="未知",
        )

        discovery = self._find_vectors(AttackPhase.DISCOVERY)
        if discovery:
            chain.vectors.append(discovery[0])

        if "sa" in entry_condition.lower() or "token" in entry_condition.lower():
            cred = self._find_vectors(AttackPhase.CREDENTIAL_ACCESS)
            if cred:
                chain.vectors.append(cred[0])
            pe = self._find_vectors(AttackPhase.PRIVILEGE_ESCALATION)
            if pe:
                chain.vectors.append(pe[0])

        if "node" in entry_condition.lower() or "escape" in entry_condition.lower():
            lm = self._find_vectors(AttackPhase.LATERAL_MOVEMENT)
            if lm:
                chain.vectors.append(lm[0])

        persist = self._find_vectors(AttackPhase.PERSISTENCE)
        if persist:
            chain.vectors.append(persist[0])

        evade = self._find_vectors(AttackPhase.DEFENSE_EVASION)
        if evade:
            chain.vectors.append(evade[0])

        return [chain] if chain.vectors else []

    def _find_vectors(self, phase: AttackPhase) -> list[AttackVector]:
        """查找特定阶段的所有向量"""
        return [v for v in ALL_VECTORS if v.phase == phase]

    def get_all_phases(self) -> dict[str, dict[str, Any]]:
        """获取所有阶段及其向量的统计"""
        phase_stats: dict[str, dict[str, Any]] = {}
        for phase in AttackPhase:
            vectors = self._find_vectors(phase)
            phase_stats[phase.value] = {
                "count": len(vectors),
                "vectors": [v.id for v in vectors],
            }
        return phase_stats

    def get_kill_chain_coverage(self) -> dict[str, dict[str, Any]]:
        """评估攻击链的覆盖度"""
        coverage: dict[str, dict[str, Any]] = {}
        for phase in AttackPhase:
            vectors = self._find_vectors(phase)
            coverage[phase.value] = {
                "covered": len(vectors) > 0,
                "count": len(vectors),
            }
        return coverage


class SmartAttackChain:
    """智能攻击链生成器

    基于加权评分排序引擎，根据环境和策略参数生成最优攻击链。
    支持动态反馈调整——根据每一步的执行结果重新规划后续路径。
    """

    def __init__(
        self,
        optimizer_weights: Optional[dict[str, float]] = None,
        vectors: Optional[list[AttackVector]] = None,
    ) -> None:
        from k8s_arsenal.core.optimizer import AttackVectorOptimizer

        self._optimizer = AttackVectorOptimizer(weights=optimizer_weights)
        self._vectors = vectors if vectors is not None else list(ALL_VECTORS)
        self._executed: list[str] = []   # 已执行的向量 ID
        self._blocked: list[str] = []    # 被封锁的向量 ID
        self._feedback: list[dict[str, Any]] = []  # 执行反馈记录
        self._detection_threshold: int = 4  # 检测提示阈值：>= 此值则封锁

    # ------------------------------------------------------------------
    # 公共 API
    # ------------------------------------------------------------------

    def generate_optimal_chain(
        self,
        phases: Optional[list[AttackPhase]] = None,
        max_depth: int = 6,
        stealth_priority: bool = False,
    ) -> list[ScoredVector]:
        """生成最优攻击链

        Args:
            phases: 目标攻击阶段列表，None 则自动推导
            max_depth: 最大链深度
            stealth_priority: True 时优先隐蔽性

        Returns:
            排序后的 ScoredVector 列表
        """
        from k8s_arsenal.core.optimizer import ScoredVector

        if stealth_priority:
            self._optimizer.weights = {
                "success": 0.20,
                "stealth": 0.45,
                "speed": 0.10,
                "impact": 0.25,
            }

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
            ]

        # 过滤已执行和被封锁的向量
        available = self._filter_available(self._vectors)
        chain: list[ScoredVector] = []

        for phase in phases:
            if len(chain) >= max_depth:
                break

            phase_vectors = [v for v in available if v.phase == phase]
            if not phase_vectors:
                continue

            # 选择该阶段评分最高的可用向量
            ranked = self._optimizer.prioritize(phase_vectors, top_n=1)
            if ranked:
                chain.append(ranked[0])
                self._executed.append(ranked[0].vector.id)

                # 执行后可能解锁新的向量（移除对已执行向量的前置依赖）
                available = self._filter_available(self._vectors)

        return chain

    def adapt_to_feedback(
        self,
        vector_id: str,
        success: bool,
        detection_triggered: bool = False,
        time_spent: float = 0.0,
    ) -> dict[str, Any]:
        """根据执行反馈自适应调整

        Args:
            vector_id: 执行的向量 ID
            success: 是否成功
            detection_triggered: 是否触发检测
            time_spent: 耗时（秒）

        Returns:
            调整后的策略建议
        """
        self._feedback.append({
            "vector_id": vector_id,
            "success": success,
            "detection_triggered": detection_triggered,
            "time_spent": time_spent,
        })

        response: dict[str, Any] = {
            "action": "continue",
            "message": "",
            "adjustments": [],
            "blocked_vectors": [],
        }

        if detection_triggered:
            # 最高优先级：检测触发 → 切换隐蔽模式
            response["action"] = "recalibrate"
            response["message"] = "检测被触发，切换至高隐蔽模式"
            self._optimizer.weights = {
                "success": 0.15,
                "stealth": 0.50,
                "speed": 0.10,
                "impact": 0.25,
            }
            response["adjustments"].append("weights shifted to stealth priority")
            self._block_loud_vectors()
            response["blocked_vectors"] = list(self._blocked)
            response["adjustments"].append("recommend adding DEFENSE_EVASION phase before next step")
        elif not success:
            # 失败 → 跳过或重试
            response["action"] = "retry_or_skip"
            response["message"] = f"向量 {vector_id} 执行失败"

            phases_to_search: list[AttackVector] = [
                v for v in self._filter_available(self._vectors)
                if v.id != vector_id
            ]
            if phases_to_search:
                response["fallback_vectors"] = [
                    {"id": v.id, "name": v.name} for v in phases_to_search[:3]
                ]
            response["adjustments"].append(
                f"searching {len(phases_to_search)} fallback vectors"
            )
        elif success:
            # 成功且未触发检测 → 继续
            self._executed.append(vector_id)
            response["action"] = "continue"
            response["message"] = f"向量 {vector_id} 执行成功"
            response["progress"] = {
                "executed": len(self._executed),
                "available": len(self._filter_available(self._vectors)),
            }

        return response

    def _block_loud_vectors(self) -> None:
        """封锁高噪声向量（触发检测后自动执行）"""
        for v in self._vectors:
            if len(v.detection_hints) >= self._detection_threshold:
                self._blocked.append(v.id)

    def get_available_phases(self) -> list[AttackPhase]:
        """获取当前可用的攻击阶段"""
        available = self._filter_available(self._vectors)
        phases = {v.phase for v in available}
        return sorted(phases, key=lambda p: p.value)

    def get_progress_report(self) -> dict[str, Any]:
        """生成进度报告"""
        available = self._filter_available(self._vectors)
        return {
            "executed_vectors": self._executed,
            "blocked_vectors": self._blocked,
            "available_vectors": len(available),
            "feedback_count": len(self._feedback),
            "phases_covered": [p.value for p in self.get_available_phases()],
            "current_weights": self._optimizer.weights,
        }

    def reset(self) -> None:
        """重置状态（用于新一轮攻击）"""
        self._executed.clear()
        self._blocked.clear()
        self._feedback.clear()

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    @property
    def _vector_registry(self) -> dict[str, AttackVector]:
        """向量 ID → 对象映射"""
        if not hasattr(self, '_vector_registry_cache'):
            self._vector_registry_cache = {v.id: v for v in ALL_VECTORS}
        return self._vector_registry_cache

    def _filter_available(self, vectors: list[AttackVector]) -> list[AttackVector]:
        """过滤：排除已执行和被封锁的向量"""
        return [
            v for v in vectors
            if v.id not in self._executed and v.id not in self._blocked
        ]


# ------------------------------------------------------------------
# 重新导出 ScoredVector 以保持向后兼容
# ------------------------------------------------------------------
from k8s_arsenal.core.optimizer import ScoredVector  # noqa: E402


def print_kill_chain_analysis() -> str:
    """打印 Kill Chain 覆盖分析（命令行工具用）"""
    builder = AttackChainBuilder()
    coverage = builder.get_kill_chain_coverage()

    lines = ["攻击链覆盖分析:", "=" * 50]
    for phase, stats in coverage.items():
        status = "✅" if stats["covered"] else "❌"
        lines.append(f"  {status} {phase}: {stats['count']} 个向量")

    return "\n".join(lines)


def print_smart_chain_score(
    vectors: Optional[list[AttackVector]] = None,
    max_depth: int = 6,
) -> str:
    """打印智能评分攻击链（供 CLI 使用）"""
    from k8s_arsenal.core.optimizer import AttackVectorOptimizer

    vecs = vectors or list(ALL_VECTORS)
    opt = AttackVectorOptimizer()
    seq = opt.optimize_sequence(vecs, max_depth=max_depth)

    lines = [
        f"智能攻击链评分 — {seq.name}",
        f"{'='*50}",
        f"  综合评分:  {seq.total_composite:.3f}",
        f"  隐蔽性:    {seq.total_stealth:.3f}",
        f"  总步骤数:  {seq.estimated_steps}",
        f"  覆盖阶段:  {len(seq.phase_coverage)}",
        f"{'='*50}",
        "向量序列:",
    ]

    for i, v in enumerate(seq.vectors, 1):
        sv = opt.score_vector(v)
        cve_tag = f" [CVE-{v.cve}]" if v.cve else ""
        lines.append(
            f"  {i}. {v.id} ({v.phase.value}) — "
            f"risky={v.risk.value} score={sv.composite_score:.3f}{cve_tag}"
        )

    if seq.risk_factors:
        lines.append(f"\n⚠️  风险因素:")
        for r in seq.risk_factors:
            lines.append(f"  - {r}")

    return "\n".join(lines)


# ------------------------------------------------------------------
# 攻击图基元（graph primitives）
# ------------------------------------------------------------------

def build_graph(
    trust_edges: list[TrustEdge],
    attack_paths: Optional[list[AttackPath]] = None,
    nodes: Optional[dict[str, str]] = None,
) -> AttackGraph:
    """从信任关系和攻击路径构建统一攻击图

    Args:
        trust_edges: 信任关系列表（来自 trust_map.build_trust_topology）
        attack_paths: 攻击路径列表（可选，来自 AttackChainBuilder）
        nodes: 节点名称映射（可选，node_id → node_label）

    Returns:
        统一的 AttackGraph 容器
    """
    graph = AttackGraph(
        nodes=nodes or {},
        edges=list(trust_edges),
        paths=list(attack_paths) if attack_paths else [],
    )

    # 自动提取入口点：只作为 source 出现但不作为 target 的节点
    sources = {e.source for e in trust_edges}
    targets = {e.target for e in trust_edges}
    graph.entry_points = sorted(sources - targets)

    # 自动识别关键资产：只作为 target 但不作为 source 的节点
    graph.critical_assets = sorted(targets - sources)

    return graph


def reachable(graph: AttackGraph, src: str, dst: str) -> bool:
    """BFS 判断图中两节点是否可达

    Args:
        graph: 攻击图
        src: 源节点 ID
        dst: 目标节点 ID

    Returns:
        True 如果存在从 src 到 dst 的路径
    """
    if src == dst:
        return True

    adj: dict[str, list[str]] = {}
    for e in graph.edges:
        if e.source not in adj:
            adj[e.source] = []
        adj[e.source].append(e.target)

    if src not in adj:
        return False

    visited = {src}
    queue = [src]
    while queue:
        current = queue.pop(0)
        for neighbor in adj.get(current, []):
            if neighbor == dst:
                return True
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)

    return False


def shortest_path(
    graph: AttackGraph,
    src: str,
    dst: str,
) -> Optional[list[str]]:
    """BFS 寻找最短可达路径

    Args:
        graph: 攻击图
        src: 源节点 ID
        dst: 目标节点 ID

    Returns:
        节点 ID 列表（最短路径），或 None（不可达）
    """
    if src == dst:
        return [src]

    adj: dict[str, list[str]] = {}
    for e in graph.edges:
        if e.source not in adj:
            adj[e.source] = []
        adj[e.source].append(e.target)

    if src not in adj:
        return None

    visited = {src}
    queue: list[list[str]] = [[src]]
    while queue:
        path = queue.pop(0)
        current = path[-1]
        for neighbor in adj.get(current, []):
            if neighbor == dst:
                return path + [neighbor]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(path + [neighbor])

    return None


def find_pivot_points(graph: AttackGraph) -> list[tuple[str, int]]:
    """找出枢纽节点（出度 >= 2 的关键跳板节点）

    Args:
        graph: 攻击图

    Returns:
        排序后的 (node_id, out_degree) 列表，按出度降序
    """
    degree: dict[str, int] = {}
    for e in graph.edges:
        degree[e.source] = degree.get(e.source, 0) + 1

    pivots = [(node, d) for node, d in degree.items() if d >= 2]
    pivots.sort(key=lambda x: x[1], reverse=True)
    return pivots
