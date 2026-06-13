"""Attack Semantics Classifier — v0.8 semantic projection layer.

Projects attack path traces into tactic labels using only
v0.5/v0.6 data structures (no new abstractions).

Tactic Set (5 classes):
  PRIVILEGE_ESCALATION — caps monotonically increase to compromise level
  LATERAL_MOVEMENT     — identity shifts without significant cap growth
  CREDENTIAL_ACCESS    — credential theft (read_secret, steal_token)
  PERSISTENCE          — creating future access (grant_rbac, RoleBinding)
  EXECUTION            — code execution in pod (exec_pod, create_pod)

Output: AttackLabel(tactic, outcome, evidence, confidence)
  - tactic:   tactic label
  - outcome:  T(S) terminal state (v0.5.1, NOT classified)
  - evidence: trace fragments supporting the classification
  - confidence: 0..1 score

Architecture:
  v0.8 is a PROJECTION operator, not a new system:
    trace → (tactic, outcome)
  It adds zero new graph structures — only labels existing traces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from k8s_arsenal.models import AttackTerminalState


# ── output type ──────────────────────────────────────────────────────────


@dataclass
class AttackLabel:
    """Single-path attack semantic label.

    Separates Outcome (T(S)) from Tactic (how the attack proceeds).
    CLUSTER_TAKEOVER is not a tactic — it is T(S)=COMPROMISED.
    """

    tactic: str
    outcome: "AttackTerminalState"
    evidence: list[str] = field(default_factory=list)
    confidence: float = 1.0


# ── tactic signal constants ──────────────────────────────────────────────

_HARD_ESCALATION: frozenset[str] = frozenset({"escalate_rbac", "impersonate"})
_ESCALATION: frozenset[str] = frozenset(
    {"escalate_rbac", "impersonate", "grant_rbac", "modify_workload"}
)
_PERSISTENCE: frozenset[str] = frozenset({"grant_rbac"})
_CREDENTIAL: frozenset[str] = frozenset({"read_secret", "steal_token"})
_EXECUTION: frozenset[str] = frozenset({"exec_pod", "create_pod"})


# ── core public API ──────────────────────────────────────────────────────


def classify(trace_result: dict) -> AttackLabel:
    """Project an attack path trace into (tactic, outcome).

    Args:
        trace_result: Dict from evaluate_path() with keys:
            final_identity, identity_chain, capabilities, trace[], terminal_state

    Returns:
        AttackLabel with tactic classification + terminal state outcome.
    """
    tactic = infer_tactic(trace_result)
    outcome = trace_result["terminal_state"]
    evidence = _extract_evidence(trace_result, tactic)
    confidence = _score(trace_result, tactic)

    return AttackLabel(
        tactic=tactic,
        outcome=outcome,
        evidence=evidence,
        confidence=confidence,
    )


def infer_tactic(trace_result: dict) -> str:
    """Core inference: trace → tactic label.

    Decision order follows severity hierarchy (most severe first):

      1. PRIVILEGE_ESCALATION — dangerous cap growth / hard escalation signals
      2. PERSISTENCE          — grant_rbac (future access injection)
      3. CREDENTIAL_ACCESS    — secret/token theft
      4. LATERAL_MOVEMENT     — identity shift without escalation/credential
      5. EXECUTION            — code execution in pods, no escalation

    All rules operate solely on the trace_result dict (v0.5/v0.6 structures).
    No new graph traversals, no new abstraction layers.
    """
    caps: set[str] = set(trace_result.get("capabilities", set()))
    terminal = trace_result.get("terminal_state")
    identity_chain: list[str] = trace_result.get("identity_chain", [])
    trace: list[dict] = trace_result.get("trace", [])

    # ── signal extraction ─────────────────────────────────────────
    identity_shifted: bool = len(identity_chain) > 1
    caps_grew: bool = _caps_grew(trace)

    edge_types: set[str] = {step.get("edge_type", "") for step in trace}
    has_token_access: bool = "TokenAccess" in edge_types

    # ── ordered classification (severity hierarchy) ───────────────

    # 1. Hard escalation signals → unconditional PRIVILEGE_ESCALATION
    if caps & _HARD_ESCALATION:
        return "PRIVILEGE_ESCALATION"

    # 2. Cap growth to dangerous level (not SAFE) → PRIVILEGE_ESCALATION
    if caps_grew and caps & _ESCALATION and _not_safe(terminal):
        return "PRIVILEGE_ESCALATION"

    # 3. grant_rbac → PERSISTENCE (future access injection)
    #    Even if terminal is COMPROMISED, grant_rbac without hard escalation
    #    is persistence (laying groundwork) not escalation (immediate elevation).
    if caps & _PERSISTENCE:
        return "PERSISTENCE"

    # 4. Credential theft → CREDENTIAL_ACCESS
    #    TokenAccess alone (no credential caps) is NOT credential_access —
    #    it may be lateral movement (identity transfer without secret theft).
    if caps & _CREDENTIAL:
        return "CREDENTIAL_ACCESS"

    # 5. Identity shift without escalation/credential → LATERAL_MOVEMENT
    #    TokenAccess edge causing identity shift is lateral movement.
    if identity_shifted:
        return "LATERAL_MOVEMENT"

    # 6. TokenAccess edge WITHOUT credential caps or identity shift →
    #    still credential-adjacent (observed token access primitive).
    if has_token_access:
        return "CREDENTIAL_ACCESS"

    # 7. Code execution in pods → EXECUTION
    if caps & _EXECUTION:
        return "EXECUTION"

    return "UNKNOWN"


# ── helpers ──────────────────────────────────────────────────────────────


def _caps_grew(trace: list[dict]) -> bool:
    """Check if cumulative capabilities increased over the path."""
    if len(trace) < 2:
        return False
    first: int = len(set(trace[0].get("capabilities", [])))
    last: int = len(set(trace[-1].get("capabilities", [])))
    return last > first


def _not_safe(terminal: object | None) -> bool:
    """Check terminal state is not SAFE (nor None/missing)."""
    if terminal is None:
        return False
    return getattr(terminal, "value", str(terminal)) != "safe"


def _extract_evidence(trace_result: dict, tactic: str) -> list[str]:
    """Extract evidence fragments supporting the classification."""
    caps: set[str] = set(trace_result.get("capabilities", set()))
    trace: list[dict] = trace_result.get("trace", [])
    identity_chain: list[str] = trace_result.get("identity_chain", [])
    edge_types: set[str] = {step.get("edge_type", "") for step in trace}

    evidence: list[str] = []

    if tactic == "PRIVILEGE_ESCALATION":
        hard = caps & _HARD_ESCALATION
        if hard:
            evidence.append(f"hard_escalation_signal: {sorted(hard)}")
        if _caps_grew(trace):
            first_caps = sorted(set(trace[0].get("capabilities", [])))
            last_caps = sorted(set(trace[-1].get("capabilities", [])))
            evidence.append(f"cap_growth: {first_caps} -> {last_caps}")

    elif tactic == "PERSISTENCE":
        evidence.append(
            "persistence_cap: grant_rbac (future access injection via "
            "RoleBinding/ClusterRoleBinding creation)"
        )

    elif tactic == "CREDENTIAL_ACCESS":
        cred_caps = caps & _CREDENTIAL
        if cred_caps:
            evidence.append(f"credential_cap: {sorted(cred_caps)}")
        if "TokenAccess" in edge_types:
            evidence.append("token_steal_edge: TokenAccess edge present in trace")

    elif tactic == "LATERAL_MOVEMENT":
        evidence.append(f"identity_shift: {' -> '.join(identity_chain)}")

    elif tactic == "EXECUTION":
        exec_caps = caps & _EXECUTION
        evidence.append(f"execution_cap: {sorted(exec_caps)}")

    return evidence


def _score(trace_result: dict, tactic: str) -> float:
    """Confidence score for the classification (0..1).

    Rule-based classifications score by signal strength:
    - Hard signals (escalate_rbac, impersonate): 1.0
    - Strong signals (read_secret, grant_rbac): 0.85-0.9
    - Weaker signals (identity shift, exec): 0.7
    """
    caps: set[str] = set(trace_result.get("capabilities", set()))

    if tactic == "UNKNOWN":
        return 0.0

    if tactic == "PRIVILEGE_ESCALATION":
        return 1.0 if caps & _HARD_ESCALATION else 0.8

    if tactic == "PERSISTENCE":
        return 0.85

    if tactic == "CREDENTIAL_ACCESS":
        return 0.9 if "read_secret" in caps else 0.8

    if tactic == "LATERAL_MOVEMENT":
        chain = trace_result.get("identity_chain", [])
        return min(0.9, 0.5 + len(chain) * 0.1)

    if tactic == "EXECUTION":
        return 0.7

    return 0.5
