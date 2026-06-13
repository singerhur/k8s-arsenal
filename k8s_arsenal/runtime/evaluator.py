"""Path evaluator — converts graph path into state evolution trace.

Bridges identity_flow + capability_set to produce a full trace of
how an attacker's identity and capabilities evolve across a path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from k8s_arsenal.runtime.identity_flow import IdentityState, propagate_identity
from k8s_arsenal.runtime.capability_set import CapabilityState, is_compromised, update_capability

if TYPE_CHECKING:
    from k8s_arsenal.models import AttackGraph, PathEvaluationResult, TrustEdge


def _resolve_edges(graph: AttackGraph, node_path: list[str]) -> list[TrustEdge]:
    """Convert node path (list of IDs) to edge list by matching against graph."""
    edges: list[TrustEdge] = []
    edge_map: dict[tuple[str, str], list[TrustEdge]] = {}

    # Build multi-map: (source, target) → [edges]
    for e in graph.edges:
        key = (e.source, e.target)
        edge_map.setdefault(key, []).append(e)

    for i in range(len(node_path) - 1):
        src, dst = node_path[i], node_path[i + 1]
        candidates = edge_map.get((src, dst), [])
        if candidates:
            # Take first candidate; if multiple edges exist, prefer
            # edges with richer metadata (non-empty capability or role_rules)
            candidates.sort(
                key=lambda e: (
                    bool(e.metadata.get("capability"))
                    or bool(e.metadata.get("role_rules")),
                ),
                reverse=True,
            )
            edges.append(candidates[0])

    return edges


def evaluate_path(
    graph: AttackGraph,
    node_path: list[str],
    compromise_threshold: str = "standard",
) -> dict:
    """Evaluate an attack path as a state evolution trace.

    Args:
        graph: The AttackGraph containing all trust edges.
        node_path: Ordered list of node IDs (from shortest_path etc.).
        compromise_threshold: Compromise check threshold
            ("standard", "host", "rbac_escalation", "any_host", "any_impersonate").

    Returns:
        Dict with keys:
        - final_identity: attacker's identity at path end
        - identity_chain: full identity transition trace
        - capabilities: cumulative capability set
        - trace: step-by-step (node, identity, capabilities)
        - is_compromised: bool — does capability set meet threshold?

    Raises:
        ValueError: If path has < 2 nodes or edges cannot be resolved.
    """
    if len(node_path) < 2:
        raise ValueError(f"Path needs ≥2 nodes, got {len(node_path)}")

    edges = _resolve_edges(graph, node_path)

    if not edges:
        raise ValueError("No edges found for the given node path")

    identity = IdentityState(node=node_path[0])
    caps = CapabilityState()

    trace: list[dict] = []

    for edge in edges:
        identity = propagate_identity(edge, identity)
        caps = update_capability(caps, edge)

        trace.append(
            {
                "node": edge.target,
                "identity": identity.node,
                "edge_type": edge.metadata.get("edge_type", edge.relationship),
                "capabilities": sorted(caps.capabilities),
            }
        )

    return {
        "final_identity": identity.node,
        "identity_chain": identity.identity_chain,
        "capabilities": caps.capabilities,
        "trace": trace,
        "is_compromised": is_compromised(caps, compromise_threshold),
    }
