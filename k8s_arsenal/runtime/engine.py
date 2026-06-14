"""AttackGraphEngine — unified API for the full v0.5+ runtime pipeline.

v0.9.2: Bridges the CLI↔runtime gap identified during Grok review.
Exposes the full six-layer analysis pipeline as a single, clean Python API:

  engine = AttackGraphEngine.from_trust_map(trust_edges)
  result = engine.analyze(entry_identity="ci-pipeline-sa")

Architecture:
  trust_map edges → build_graph → evaluate_path → counterfactual → mcs → classify
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import TYPE_CHECKING, Optional

from k8s_arsenal.models import AttackGraph, AttackTerminalState, TrustEdge

logger = logging.getLogger(__name__)
from k8s_arsenal.playbook.chains import build_graph, shortest_path
from k8s_arsenal.runtime.evaluator import evaluate_path
from k8s_arsenal.runtime.terminal_state import evaluate_terminal_state
from k8s_arsenal.runtime.counterfactual import counterfactual
from k8s_arsenal.runtime.minimal_cut import minimal_cut_set, greedy_minimal_cut, ilp_minimal_cut
from k8s_arsenal.runtime.classifier import classify, AttackLabel
from k8s_arsenal.runtime.identity_flow import IdentityState

if TYPE_CHECKING:
    pass


# ============================================================================
# Result containers
# ============================================================================


@dataclass
class CounterfactualResult:
    """Single-edge counterfactual delta."""
    edge: tuple[str, str, str]   # (source, target, relationship)
    baseline_state: AttackTerminalState
    counterfactual_state: AttackTerminalState
    became_safe: bool
    became_compromised: bool
    explanation: str


@dataclass
class AnalysisResult:
    """Full pipeline analysis result.

    Contains the complete output of all six layers:
    G → S → T → Δ → MCS → Label
    """
    # Graph layer (G)
    graph: AttackGraph
    entry_identity: str
    critical_assets: list[str] = field(default_factory=list)

    # State evolution (S) + Terminal (T)
    terminal_state: AttackTerminalState = AttackTerminalState.SAFE
    terminal_explanation: str = ""
    final_identity: str = ""
    identity_chain: list[str] = field(default_factory=list)
    capabilities: set[str] = field(default_factory=set)
    trace: list[dict] = field(default_factory=list)

    # Counterfactual (Δ)
    counterfactuals: list[CounterfactualResult] = field(default_factory=list)
    critical_edges: list[tuple[str, str, str]] = field(default_factory=list)

    # Minimal Cut Set (MCS)
    mcs_cut_edges: list[tuple[str, str, str]] = field(default_factory=list)
    mcs_strategy: str = ""
    mcs_explanation: str = ""
    mcs_verified: bool | None = None  # None = verification not run
    mcs_verification_note: str = ""

    # Classifier (Label)
    labels: list[str] = field(default_factory=list)
    primary_tactic: str = ""

    # Metadata
    threshold: str = "standard"
    path_count: int = 0


# ============================================================================
# Engine
# ============================================================================


class AttackGraphEngine:
    """Unified attack graph analysis engine.

    Wraps the full v0.5+ runtime pipeline as a clean Python API,
    designed to bridge the CLI↔runtime integration gap.

    Usage::

        from k8s_arsenal.recon.trust_map import build_trust_topology
        from k8s_arsenal.runtime.engine import AttackGraphEngine

        edges = build_trust_topology(profile)
        engine = AttackGraphEngine.from_trust_map(edges)
        result = engine.analyze(entry_identity="ci-pipeline-sa")

        print(result.terminal_state)       # SAFE / PARTIAL / COMPROMISED
        print(result.primary_tactic)       # PRIVILEGE_ESCALATION / ...
        print(result.mcs_cut_edges)        # minimal cut set

    Conforms to invariants layer (v0.9) assertions on all outputs.
    """

    def __init__(
        self,
        graph: AttackGraph,
        entry_identity: str = "",
        critical_assets: Optional[list[str]] = None,
    ) -> None:
        self.graph = graph
        self.entry_identity: str = entry_identity or _first_entry_point(graph)
        self.critical_assets: list[str] = (
            critical_assets or graph.critical_assets or _derive_critical(graph)
        )

    # ---- factory methods --------------------------------------------------

    @classmethod
    def from_trust_map(
        cls,
        trust_edges: list[TrustEdge],
        entry_identity: str = "",
        critical_assets: Optional[list[str]] = None,
        nodes: Optional[dict[str, str]] = None,
    ) -> "AttackGraphEngine":
        """Build engine from trust topology (recon/trust_map output).

        This is the primary factory — bridges the v0.4 recon world
        into the v0.5+ runtime pipeline.

        Also runs edge metadata validation and emits warnings for
        edges that lack edge_type / capability metadata (common with
        static trust topology edges).
        """
        warnings = cls.validate_edges(trust_edges)
        for w in warnings:
            logger.warning("Edge validation: %s", w)

        graph = build_graph(trust_edges, nodes=nodes)

        # If no entry provided, use first entry point from graph topology.
        if not entry_identity:
            entry_identity = _first_entry_point(graph)

        # If no critical assets, default to graph sinks.
        if not critical_assets:
            critical_assets = graph.critical_assets or _derive_critical(graph)

        return cls(graph, entry_identity=entry_identity, critical_assets=critical_assets)

    @staticmethod
    def validate_edges(edges: list[TrustEdge]) -> list[str]:
        """Validate trust edges and return diagnostic warnings.

        Checks for common issues that cause silent degradation:
        - Empty metadata (edge_type missing → identity flow breaks)
        - Empty capability annotation (capabilities never grow)
        - Relationship string that doesn't match any known hint

        Returns list of warning strings (empty = all clear).
        """
        warnings: list[str] = []
        if not edges:
            return ["No trust edges provided — graph is empty."]

        missing_edge_type = 0
        missing_capability = 0
        unknown_relationship: set[str] = set()

        # Known relationships from trust_map.py and test fixtures
        known_rels = {
            # Production trust_map.py strings (Chinese)
            "客户端证书认证", "挂载 ServiceAccount Token", "Bearer Token 认证",
            "Unix Socket (CRI)", "跳过 TLS 验证 (默认)", "ServiceAccount 认证",
            "当前 Pod 信任关系", "挂载 Docker Socket",
            # Test fixture / English aliases
            "Docker Socket",
            "RoleBinding", "TokenAccess", "Impersonate", "RBAC Binding",
            "ClusterRoleBinding",
            "exec_pod", "create_pod", "read_secret", "grant_rbac",
        }

        for i, e in enumerate(edges):
            meta = e.metadata or {}
            has_edge_type = bool(meta.get("edge_type"))
            has_capability = bool(meta.get("capability") or meta.get("role_rules"))

            if not has_edge_type:
                missing_edge_type += 1
            if not has_capability:
                missing_capability += 1
            if e.relationship not in known_rels:
                unknown_relationship.add(e.relationship)

        if missing_edge_type > 0:
            warnings.append(
                f"{missing_edge_type}/{len(edges)} edge(s) missing metadata.edge_type — "
                f"identity flow will not transition identities on these edges. "
                f"Consider calling build_trust_topology() which now sets edge_type as of v0.9.1."
            )
        if missing_capability > 0:
            warnings.append(
                f"{missing_capability}/{len(edges)} edge(s) missing metadata.capability/role_rules — "
                f"capabilities will not grow on these edges (T(S) may stay SAFE). "
                f"This is expected for static trust topology without RBAC data. "
                f"Some relationships have hint capabilities (Docker Socket → node_access)."
            )
        if unknown_relationship:
            warnings.append(
                f"{len(unknown_relationship)} unrecognized relationship type(s): "
                f"{sorted(unknown_relationship)}. No capability hints available."
            )

        return warnings

    # ---- primary pipeline -------------------------------------------------

    def analyze(
        self,
        entry_identity: str = "",
        critical_assets: Optional[list[str]] = None,
        compromise_threshold: str = "standard",
        run_counterfactuals: bool = True,
        run_mcs: bool = True,
        run_classifier: bool = True,
        verify_mcs: bool = True,
    ) -> AnalysisResult:
        """Run the full six-layer attack graph pipeline.

        Args:
            entry_identity: Override the entry point identity.
            critical_assets: Override critical asset nodes.
            compromise_threshold: Terminal state threshold
                ("standard", "host", "rbac_escalation", "any_host", "any_impersonate").
            run_counterfactuals: Whether to compute single-edge ΔT.
            run_mcs: Whether to compute minimal cut set.
            run_classifier: Whether to classify attack tactics.
            verify_mcs: Whether to run MCS counterfactual verification.

        Returns:
            AnalysisResult with complete pipeline output.

        Raises:
            ValueError: If entry identity is not in the graph.
        """
        entry = entry_identity or self.entry_identity
        critical = list(critical_assets) if critical_assets else list(self.critical_assets)

        if not entry:
            raise ValueError("No entry identity — provide entry_identity or set graph.entry_points")

        result = AnalysisResult(
            graph=self.graph,
            entry_identity=entry,
            critical_assets=critical,
            threshold=compromise_threshold,
        )

        # ---- G + S + T: Path evaluation -----------------------------------
        paths_evaluated = 0
        best_trace = None
        worst_state = AttackTerminalState.SAFE

        for target in critical:
            path = shortest_path(self.graph, entry, target)
            if path is None:
                continue
            paths_evaluated += 1
            eval_result = evaluate_path(self.graph, path, compromise_threshold=compromise_threshold)
            state = eval_result["terminal_state"]

            # Track worst terminal state across all critical assets.
            if _state_rank(state) >= _state_rank(worst_state):
                worst_state = state
                best_trace = eval_result

        result.path_count = paths_evaluated

        if best_trace:
            result.terminal_state = best_trace["terminal_state"]
            result.final_identity = best_trace["final_identity"]
            result.identity_chain = best_trace["identity_chain"]
            result.capabilities = best_trace["capabilities"]
            result.trace = best_trace["trace"]

            # Build human-readable explanation.
            result.terminal_explanation = _explain_terminal(result)
        else:
            result.terminal_explanation = (
                f"No path from {entry} to any critical asset {critical}. "
                "Graph may be incomplete or entry is isolated."
            )

        # ---- Δ: Counterfactual analysis ----------------------------------
        if run_counterfactuals and self.graph.edges:
            result.counterfactuals = self._run_counterfactuals(
                entry, critical, compromise_threshold
            )
            result.critical_edges = [
                cf.edge for cf in result.counterfactuals if cf.became_safe
            ]

        # ---- MCS: Minimal cut set ----------------------------------------
        if run_mcs and paths_evaluated > 0:
            result.mcs_cut_edges, result.mcs_strategy, result.mcs_explanation = (
                self._run_mcs(entry, critical, compromise_threshold)
            )

            # Counterfactual verification gate.
            if verify_mcs and result.mcs_cut_edges:
                result.mcs_verified, result.mcs_verification_note = (
                    self._verify_mcs_cut(result.mcs_cut_edges, entry, critical, compromise_threshold)
                )

        # ---- Label: Classifier projection ---------------------------------
        if run_classifier and best_trace:
            label = classify(best_trace)
            result.labels = [label.value] if hasattr(label, "value") else [str(label)]
            result.primary_tactic = label.value if hasattr(label, "value") else str(label)

        return result

    # ---- internal helpers -------------------------------------------------

    def _run_counterfactuals(
        self,
        entry: str,
        critical: list[str],
        threshold: str,
    ) -> list[CounterfactualResult]:
        cfs: list[CounterfactualResult] = []
        for target in critical:
            for edge in self.graph.edges:
                try:
                    cf = counterfactual(self.graph, edge, entry, target, threshold)
                    delta = cf["delta"]
                    cfs.append(CounterfactualResult(
                        edge=cf["edge"],
                        baseline_state=cf["baseline_state"],
                        counterfactual_state=cf["counterfactual_state"],
                        became_safe=delta["became_safe"],
                        became_compromised=delta["became_compromised"],
                        explanation=delta["explanation"],
                    ))
                except (ValueError, KeyError):
                    # Edge removal broke all connectivity — skip.
                    continue
        return cfs

    def _run_mcs(
        self,
        entry: str,
        critical: list[str],
        threshold: str,
    ) -> tuple[list[tuple[str, str, str]], str, str]:
        best_mcs = None
        best_size = float("inf")

        for target in critical:
            mcs = minimal_cut_set(self.graph, entry, target, threshold, use_ilp=True)
            if mcs["size"] > 0 and mcs["size"] < best_size:
                best_size = mcs["size"]
                best_mcs = mcs

        if best_mcs is None:
            return [], "none", "No minimal cut set computed (no COMPROMISED paths found)."

        return best_mcs["cut_edges"], best_mcs["strategy"], best_mcs["explanation"]

    def _verify_mcs_cut(
        self,
        cut_edges: list[tuple[str, str, str]],
        entry: str,
        critical: list[str],
        threshold: str,
    ) -> tuple[bool, str]:
        """Verify MCS cuts actually neutralize all COMPROMISED paths.

        Creates a counterfactual graph with all cut edges removed,
        then re-checks terminal state across all critical assets.
        """
        from copy import deepcopy

        G_cf = deepcopy(self.graph)
        cut_set = set(cut_edges)
        G_cf.edges = [
            e for e in G_cf.edges
            if (e.source, e.target, e.relationship) not in cut_set
        ]

        for target in critical:
            path = shortest_path(G_cf, entry, target)
            if path is None:
                continue
            eval_result = evaluate_path(G_cf, path, compromise_threshold=threshold)
            if eval_result["terminal_state"] == AttackTerminalState.COMPROMISED:
                return False, (
                    f"MCS verification FAILED: residual COMPROMISED path to {target} "
                    f"after removing {len(cut_edges)} edge(s). Cut set is incomplete."
                )

        return True, (
            f"MCS verified: removing {len(cut_edges)} edge(s) neutralizes "
            f"all COMPROMISED paths to {critical}."
        )


# ============================================================================
# Internal helpers
# ============================================================================


def _state_rank(state: AttackTerminalState) -> int:
    """Quantify terminal state severity: SAFE=0, PARTIAL=1, COMPROMISED=2."""
    return {AttackTerminalState.SAFE: 0, AttackTerminalState.PARTIAL: 1, AttackTerminalState.COMPROMISED: 2}[state]


def _first_entry_point(graph: AttackGraph) -> str:
    """Return the first entry point from the graph, or empty string if none."""
    return graph.entry_points[0] if graph.entry_points else ""


def _derive_critical(graph: AttackGraph) -> list[str]:
    """Derive critical assets from graph topology (sink nodes)."""
    sources = {e.source for e in graph.edges}
    targets = {e.target for e in graph.edges}
    return sorted(targets - sources)


def _explain_terminal(result: AnalysisResult) -> str:
    """Build a human-readable explanation of the terminal state."""
    state_name = result.terminal_state.value.upper()
    caps_str = ", ".join(sorted(result.capabilities)) if result.capabilities else "none"
    identity_str = " → ".join(result.identity_chain) if result.identity_chain else result.final_identity

    parts = [
        f"Terminal state: {state_name}",
        f"Entry: {result.entry_identity}",
        f"Final identity: {result.final_identity}",
        f"Identity chain: {identity_str}",
        f"Capabilities: {caps_str}",
        f"Critical assets: {result.critical_assets}",
        f"Threshold: {result.threshold}",
    ]

    if result.critical_edges:
        parts.append(f"Critical edges (ΔT): {result.critical_edges}")

    if result.mcs_cut_edges:
        parts.append(f"MCS ({result.mcs_strategy}): {len(result.mcs_cut_edges)} edge(s)")

    if result.primary_tactic:
        parts.append(f"Primary tactic: {result.primary_tactic}")

    return "\n".join(parts)
