"""Architectural invariants — executable design constraints (v0.9).

Transforms v0.4-v0.8 implicit design consensus into CI-enforceable
assertions.  Each invariant is independently testable and raises
AssertionError on violation.

These are METARULES that protect the system from abstraction creep,
taxonomy inflation, and accidental regression — NOT new semantic rules
for the security model itself.

CI integration:
    pytest -m invariants
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from k8s_arsenal.models import AttackGraph, AttackTerminalState, TrustEdge

from k8s_arsenal.runtime.classifier import AttackLabel


# ===========================================================================
# v0.5.1 — terminal state invariants
# ===========================================================================

_VALID_TS: frozenset[str] = frozenset({"safe", "partial", "compromised"})


def assert_terminal_state_valid(state: "AttackTerminalState") -> None:
    """T(S) ∈ {SAFE, PARTIAL, COMPROMISED}.  No fourth state."""
    msg = (
        f"Invalid terminal state: {state.value!r}.  "
        f"Must be one of {sorted(_VALID_TS)}."
    )
    assert state.value in _VALID_TS, msg


# ===========================================================================
# v0.8 — classifier invariants
# ===========================================================================

_VALID_TACTICS: frozenset[str] = frozenset({
    "PRIVILEGE_ESCALATION",
    "PERSISTENCE",
    "CREDENTIAL_ACCESS",
    "LATERAL_MOVEMENT",
    "EXECUTION",
    "UNKNOWN",
})

_FORBIDDEN_TACTICS: frozenset[str] = frozenset({
    "CLUSTER_TAKEOVER",  # T(S), not tactic
    "safe", "partial", "compromised",  # terminal states, not tactics
})


def assert_tactic_label_valid(tactic: str) -> None:
    """tactic must be one of exactly 6 valid labels.
    CLUSTER_TAKEOVER and terminal-state values are forbidden.
    """
    assert tactic in _VALID_TACTICS, (
        f"Invalid tactic: {tactic!r}.  "
        f"Expected one of {sorted(_VALID_TACTICS)}."
    )
    assert tactic not in _FORBIDDEN_TACTICS, (
        f"Forbidden tactic: {tactic!r}.  "
        f"This is a terminal-state value or composite outcome, not a tactic."
    )


def assert_attack_label_dimensions_separated(label: "AttackLabel") -> None:
    """outcome = T(S) ∈ AttackTerminalState.  tactic ≠ terminal-state value."""
    from k8s_arsenal.models import AttackTerminalState as ATS

    assert isinstance(label.outcome, ATS), (
        f"outcome must be AttackTerminalState, got {type(label.outcome).__name__}"
    )
    assert label.tactic not in {"safe", "partial", "compromised"}, (
        f"tactic {label.tactic!r} is a terminal-state value — "
        f"outcome/tactic dimensions must stay separate."
    )
    assert label.tactic != "CLUSTER_TAKEOVER", (
        "CLUSTER_TAKEOVER = T(S)=COMPROMISED, not a tactic."
    )


def assert_classify_produces_valid_label(trace_result: dict) -> None:
    """classify() output must be a structurally valid AttackLabel."""
    from k8s_arsenal.runtime.classifier import classify

    label = classify(trace_result)
    assert isinstance(label, AttackLabel), (
        f"classify() returned {type(label).__name__}, expected AttackLabel"
    )
    assert_attack_label_dimensions_separated(label)
    assert_confidence_in_range(label.confidence)


def assert_confidence_in_range(confidence: float) -> None:
    """confidence ∈ [0.0, 1.0]."""
    assert 0.0 <= confidence <= 1.0, (
        f"confidence {confidence} not in [0.0, 1.0]"
    )


# ===========================================================================
# v0.5 — identity flow invariants
# ===========================================================================

_ID_TRANSITION_TYPES: frozenset[str] = frozenset({"TokenAccess", "Impersonate"})


def assert_identity_chain_non_empty(chain: list[str]) -> None:
    """Identity chain always has at least the starting node."""
    assert len(chain) >= 1, "identity_chain is empty"


def assert_identity_only_changes_on_defined_edges(
    trace: list[dict],
    identity_chain: list[str],
) -> None:
    """Identity transitions must ONLY happen on TokenAccess / Impersonate edges.

    Walks the trace and checks: whenever the current identity differs
    from the previous step's identity, the edge that produced the change
    must have edge_type in {TokenAccess, Impersonate}.
    """
    if len(trace) == 0:
        return

    # previous_identity starts as the first identity in the chain
    prev_id = identity_chain[0] if identity_chain else ""

    for i, step in enumerate(trace):
        curr_id: str = step.get("identity", "")
        edge_type: str = step.get("edge_type", "")

        if curr_id != prev_id:
            assert edge_type in _ID_TRANSITION_TYPES, (
                f"Identity changed at trace[{i}]: {prev_id!r} → {curr_id!r} "
                f"but edge_type={edge_type!r} is not a transition edge "
                f"({sorted(_ID_TRANSITION_TYPES)})."
            )
        prev_id = curr_id


def assert_identity_chain_grows_monotonically(chain: list[str]) -> None:
    """Identity chain only appends, never shrinks or duplicates adjacent."""
    for i in range(1, len(chain)):
        assert chain[i] != chain[i - 1], (
            f"Identity chain has adjacent duplicate at index {i}: {chain}"
        )


# ===========================================================================
# v0.5 — capability set invariants
# ===========================================================================

_FORBIDDEN_CAPS: frozenset[str] = frozenset({
    "CLUSTER_TAKEOVER",
    "cluster_admin",
    "full_access",
})


def assert_capability_set_monotonic(trace: list[dict]) -> None:
    """Capabilities must grow monotonically across a path — never regress."""
    if len(trace) <= 1:
        return
    for i in range(1, len(trace)):
        prev = set(trace[i - 1].get("capabilities", []))
        curr = set(trace[i].get("capabilities", []))
        lost = prev - curr
        assert not lost, (
            f"Capability regression at trace[{i}]: lost {sorted(lost)}.  "
            f"Capabilities must accumulate monotonically."
        )


def assert_capability_is_atomic(caps: set[str]) -> None:
    """Capabilities must be atomic primitives, never composite outcomes."""
    overlap = caps & _FORBIDDEN_CAPS
    assert not overlap, (
        f"Composite outcomes in capability set: {sorted(overlap)}.  "
        f"Capabilities must be atomic (e.g., 'create_pod', not 'CLUSTER_TAKEOVER')."
    )


# ===========================================================================
# v0.5 — evaluator output invariants
# ===========================================================================

_EVAL_KEYS: frozenset[str] = frozenset({
    "final_identity",
    "identity_chain",
    "capabilities",
    "trace",
    "terminal_state",
})


def assert_evaluate_path_result_structure(result: dict) -> None:
    """evaluate_path() dict must have all five required keys."""
    for key in _EVAL_KEYS:
        assert key in result, f"evaluate_path() missing key: {key!r}"
    assert_terminal_state_valid(result["terminal_state"])
    assert isinstance(result["identity_chain"], list)
    assert isinstance(result["capabilities"], (set, frozenset))
    assert isinstance(result["trace"], list)


# ===========================================================================
# v0.4 — graph structure invariants
# ===========================================================================


def assert_shortest_path_valid(path: object) -> None:
    """shortest_path() returns list[str] or None."""
    if path is None:
        return
    assert isinstance(path, list), (
        f"shortest_path() returned {type(path).__name__}, expected list or None"
    )
    assert len(path) >= 2, f"Path needs ≥2 nodes, got {len(path)}"
    assert all(isinstance(n, str) for n in path), "Path nodes must be strings"


def assert_reachable_returns_bool(result: object) -> None:
    """reachable() returns bool."""
    assert isinstance(result, bool), (
        f"reachable() returned {type(result).__name__}, expected bool"
    )


# ===========================================================================
# v0.6 — counterfactual invariants
# ===========================================================================

_CF_KEYS: frozenset[str] = frozenset({
    "edge",
    "baseline_path",
    "baseline_state",
    "counterfactual_path",
    "counterfactual_state",
    "delta",
})

_DELTA_KEYS: frozenset[str] = frozenset({
    "became_safe",
    "became_compromised",
    "state_change",
    "explanation",
})


def assert_counterfactual_result_structure(result: dict) -> None:
    """counterfactual() result must have all required keys."""
    for key in _CF_KEYS:
        assert key in result, f"counterfactual() missing key: {key!r}"
    delta = result["delta"]
    for key in _DELTA_KEYS:
        assert key in delta, f"delta missing key: {key!r}"


def assert_counterfactual_no_mutation(
    graph: "AttackGraph",
    edge: "TrustEdge",
) -> None:
    """counterfactual() must deep-copy — the original graph is untouched."""
    original_count = len(graph.edges)
    original_sigs = {(e.source, e.target, e.relationship) for e in graph.edges}

    from k8s_arsenal.runtime.counterfactual import counterfactual

    a = graph.entry_points[0]
    b = graph.critical_assets[0]
    counterfactual(graph, edge, a, b)

    assert len(graph.edges) == original_count, (
        f"Graph mutated: {original_count} → {len(graph.edges)} edges"
    )
    for e in graph.edges:
        sig = (e.source, e.target, e.relationship)
        assert sig in original_sigs, f"Graph mutated: edge {sig} not in original"


# ===========================================================================
# v0.7 — minimal cut set invariants
# ===========================================================================

_MCS_KEYS: frozenset[str] = frozenset({
    "strategy",
    "cut_edges",
    "size",
    "baseline_paths",
    "explanation",
})


def assert_mcs_result_structure(result: dict) -> None:
    """Minimal cut result must have all required keys and consistent sizes."""
    for key in _MCS_KEYS:
        assert key in result, f"minimal-cuts result missing key: {key!r}"
    assert isinstance(result["cut_edges"], list), "cut_edges must be list"
    assert isinstance(result["size"], int), "size must be int"
    assert result["size"] == len(result["cut_edges"]), (
        f"size={result['size']} ≠ len(cut_edges)={len(result['cut_edges'])}"
    )


def assert_mcs_exact_not_larger_than_greedy(
    greedy_size: int,
    exact_size: int,
) -> None:
    """Exact MCS cardinality ≤ greedy (greedy provides ceiling)."""
    assert exact_size <= greedy_size, (
        f"exact MCS {exact_size} > greedy {greedy_size} — greedy must be upper bound"
    )


# ===========================================================================
# global runner — CI entry point
# ===========================================================================


def validate_trace_result(tr: dict) -> list[str]:
    """Run all invariants against an evaluate_path() result.

    Returns list of violation messages — empty means all passed.
    """
    violations: list[str] = []

    def _check(fn, *args):
        try:
            fn(*args)
        except Exception as exc:
            violations.append(f"{fn.__name__}: {exc}")

    _check(assert_evaluate_path_result_structure, tr)

    ts = tr.get("terminal_state")
    if ts is not None:
        _check(assert_terminal_state_valid, ts)

    trace = tr.get("trace", [])
    chain = tr.get("identity_chain", [])
    caps = tr.get("capabilities", set())

    _check(assert_identity_chain_non_empty, chain)
    _check(assert_identity_chain_grows_monotonically, chain)
    _check(assert_identity_only_changes_on_defined_edges, trace, chain)
    _check(assert_capability_set_monotonic, trace)
    _check(assert_capability_is_atomic, caps)
    _check(assert_classify_produces_valid_label, tr)

    return violations
