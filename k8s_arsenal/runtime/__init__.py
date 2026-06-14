"""Runtime layer — IdentityFlow + CapabilitySet path evaluation.

Converts AttackGraph paths (node lists) into state evolution traces,
answering:
- Who is the attacker at each step? (IdentityFlow)
- What cumulative capabilities have they assembled? (CapabilitySet)
- Does the capability set imply cluster compromise? (composition check)
"""

from k8s_arsenal.runtime.evaluator import evaluate_path
from k8s_arsenal.runtime.identity_flow import IdentityState, propagate_identity
from k8s_arsenal.runtime.capability_set import (
    CapabilityState,
    is_compromised,
    update_capability,
)
from k8s_arsenal.runtime.terminal_state import evaluate_terminal_state
from k8s_arsenal.runtime.counterfactual import counterfactual
from k8s_arsenal.runtime.minimal_cut import greedy_minimal_cut, ilp_minimal_cut, minimal_cut_set, verify_cut_set
from k8s_arsenal.runtime.classifier import AttackLabel, classify, infer_tactic
from k8s_arsenal.runtime.invariants import (
    assert_attack_label_dimensions_separated,
    assert_capability_is_atomic,
    assert_capability_set_monotonic,
    assert_classify_produces_valid_label,
    assert_confidence_in_range,
    assert_counterfactual_no_mutation,
    assert_counterfactual_result_structure,
    assert_evaluate_path_result_structure,
    assert_identity_chain_grows_monotonically,
    assert_identity_chain_non_empty,
    assert_identity_only_changes_on_defined_edges,
    assert_mcs_exact_not_larger_than_greedy,
    assert_mcs_result_structure,
    assert_reachable_returns_bool,
    assert_shortest_path_valid,
    assert_tactic_label_valid,
    assert_terminal_state_valid,
    validate_trace_result,
)
from k8s_arsenal.runtime.engine import (
    AnalysisResult,
    AttackGraphEngine,
    CounterfactualResult,
)

__all__ = [
    "IdentityState",
    "propagate_identity",
    "CapabilityState",
    "update_capability",
    "is_compromised",
    "evaluate_path",
    "evaluate_terminal_state",
    "counterfactual",
    "greedy_minimal_cut",
    "ilp_minimal_cut",
    "minimal_cut_set",
    "verify_cut_set",
    "AttackLabel",
    "classify",
    "infer_tactic",
    # v0.9 invariants
    "assert_attack_label_dimensions_separated",
    "assert_capability_is_atomic",
    "assert_capability_set_monotonic",
    "assert_classify_produces_valid_label",
    "assert_confidence_in_range",
    "assert_counterfactual_no_mutation",
    "assert_counterfactual_result_structure",
    "assert_evaluate_path_result_structure",
    "assert_identity_chain_grows_monotonically",
    "assert_identity_chain_non_empty",
    "assert_identity_only_changes_on_defined_edges",
    "assert_mcs_exact_not_larger_than_greedy",
    "assert_mcs_result_structure",
    "assert_reachable_returns_bool",
    "assert_shortest_path_valid",
    "assert_tactic_label_valid",
    "assert_terminal_state_valid",
    "validate_trace_result",
    # v0.9.2 engine
    "AnalysisResult",
    "AttackGraphEngine",
    "CounterfactualResult",
]
