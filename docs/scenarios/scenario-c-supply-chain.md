# Scenario C: Supply Chain Permission Collapse

## Overview

Scenario C validates AttackGraph on a **real minikube cluster** with a deliberately crafted
multi-hop supply chain trust collapse. It proves that AttackGraph can discover non-obvious
attack paths that span 3 namespaces and 7 trust edges, where RBAC alone only exposes 3 of those 7 edges.

## Attack Chain Architecture

```
ci-pipeline-sa (ci-ns)                           [ENTRY]
    |
    | E1: RoleBinding -> ci-deployer Role (prod-ns)   [observation]
    v
ci-deployer (prod-ns)
    |
    | E4: can deploy pods -> implicit access to prod-app-sa  [inference]
    v
prod-app-sa (prod-ns)                            [PIVOT]
    |\
    | \ E6: Standard SA Token -> API Server             [default]
    |  \
    |   v
    |  kube-apiserver                             [CRITICAL ASSET]
    |
    | E2: RoleBinding -> monitoring-reader Role (monitoring-ns)  [observation]
    v
monitoring-reader (monitoring-ns)
    |
    | E5: can read secrets -> implicit access to monitoring-operator-sa  [inference]
    v
monitoring-operator-sa (monitoring-ns)
    |
    | E3: ClusterRoleBinding -> kubelet-impersonator   [observation]
    v
kubelet-impersonator (cluster)
    |
    | E7: impersonate kubelet -> full API access        [inference]
    v
kube-apiserver                                   [CRITICAL ASSET]
```

## Graph Analysis Results

| Metric | Value |
|--------|-------|
| Nodes | 7 |
| Edges | 7 |
| Entry Points | ci-ns/ci-pipeline-sa |
| Critical Assets | kube-apiserver |
| CI -> API Reachable | Yes |
| Shortest Path | 3 hops (ci -> ci-deployer -> prod-sa -> api) |
| Alternative Path | 7 hops (via monitoring-operator -> kubelet) |
| Pivot Points | prod-ns/prod-app-sa (out-degree=2) |

## Edge Source Classification

| Source Type | Count | Description |
|-------------|-------|-------------|
| observation | 3 | Extracted directly from kubectl (RoleBinding / ClusterRoleBinding) |
| inference | 3 | Derived from Role rules (capability -> resource -> asset) |
| default | 1 | System implicit (SA Token -> API Server) |

## Key Finding: RBAC Semantic Gap

**The most important finding from Scenario C is that Kubernetes RBAC objects
do not form a complete attack graph on their own.**

- `kubectl get rolebinding` gives us: SA -> Role -> Binding
- But attack graph needs: SA -> Role -> **Capability** -> **Asset** -> **Identity**

The 3 inference edges (E4, E5, E7) bridge this gap by interpreting what a Role
can actually **do** to what **resource**:

- `ci-deployer` has `deployments/create` in prod-ns -> can deploy pods with prod-app-sa
- `monitoring-reader` has `secrets/get` in monitoring-ns -> can read monitoring-operator-sa token
- `kubelet-impersonator` has `users/impersonate` for `system:node:*` -> can become kubelet

Without these semantic bridges, the graph would be disconnected:
only 3 edges, no path from entry to critical asset.

## TrustEdge.metadata: Why It Matters

This finding directly motivated the `TrustEdge.metadata` field (v0.4.7):

```python
# Observation edge — directly from K8s API
TrustEdge(
    source="ci-ns/ci-pipeline-sa",
    target="prod-ns/ci-deployer",
    metadata={"source": "observation", "evidence": {"type": "RoleBinding", ...}},
)

# Inference edge — derived from Role rules
TrustEdge(
    source="prod-ns/ci-deployer",
    target="prod-ns/prod-app-sa",
    metadata={
        "source": "inference",
        "derived_from": ["ci-ns/ci-pipeline-sa->prod-ns/ci-deployer"],
        "capability": {"verbs": ["create"], "resources": ["deployments"]},
        "reasoning": "ci-deployer can deploy pods using prod-app-sa",
    },
)
```

Without metadata, you cannot distinguish fact edges from derived edges,
making the graph unverifiable and unexplainable.

## Files

- `scenario_c/DESIGN.md` — Attack chain design & expected results
- `scenario_c/chain.py` — Design-time validation (hardcoded chain, runs 4 graph primitives)
- `scenario_c/setup.py` — minikube environment deployment (namespaces, SA, RBAC)
- `scenario_c/verify_cluster.py` — Live cluster verification (discovers edges, runs AttackGraph)

## Related Version History

| Version | Change |
|---------|--------|
| v0.4.4 | AttackGraph + graph primitives (build_graph, reachable, shortest_path, find_pivot_points) |
| v0.4.7 | TrustEdge.metadata (EdgeSource enum: observation/inference/default) |
