"""Identity flow tracker — answers "who is the attacker at each step."

Identity does NOT mutate arbitrarily on every edge traversal.
It only transitions via explicit identity-transfer primitives:
- TokenAccess: SA can read another SA's token (secrets/get, projected SA)
- Impersonate: SA can impersonate another identity (users/groups impersonate)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from k8s_arsenal.models import TrustEdge


# Edge types that trigger identity transition.
# Checked against TrustEdge.metadata["edge_type"].
_IDENTITY_TRANSITION_TYPES = frozenset({"TokenAccess", "Impersonate"})


@dataclass
class IdentityState:
    """Attacker identity at a point on the attack path."""

    node: str
    identity_chain: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.identity_chain:
            self.identity_chain = [self.node]


def propagate_identity(edge: TrustEdge, state: IdentityState) -> IdentityState:
    """Evolve identity state across one trust edge.

    Identity transitions happen on explicit identity-transfer edges only
    (TokenAccess or Impersonate). All other edges leave identity unchanged.
    """
    edge_type = edge.metadata.get("edge_type", "")

    if edge_type in _IDENTITY_TRANSITION_TYPES:
        return IdentityState(
            node=edge.target,
            identity_chain=state.identity_chain + [edge.target],
        )

    # Identity unchanged — attacker moves position but remains the same identity
    return state
