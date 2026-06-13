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
from k8s_arsenal.runtime.minimal_cut import greedy_minimal_cut, minimal_cut_set

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
    "minimal_cut_set",
]
