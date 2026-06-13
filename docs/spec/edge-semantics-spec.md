# Edge Semantics Spec v0.5

## Why This Exists

AttackGraph correctness = INFERENCE edges must be grounded in OBSERVATION edges.

Without this spec, different agents (human or LLM) derive different inference edges
from the same RBAC config. This spec defines **what constitutes a valid inference**
so the graph's semantics don't drift with the writer.

---

## 1. Edge Source Taxonomy

```
OBSERVATION  — fact extracted from K8s API (no interpretation)
INFERENCE    — derived from capability rules (requires this spec)
DEFAULT      — system-wide assumptions (implicit trust, must be explicit)
```

---

## 2. OBSERVATION Edge Sources

| Source | Mapped To | Evidence |
|--------|-----------|----------|
| `RoleBinding` | SA → Role (in namespace) | `kubectl get rolebinding -A -o json` |
| `ClusterRoleBinding` | SA → ClusterRole (cluster-scoped) | `kubectl get clusterrolebinding -o json` |
| `Pod.spec.serviceAccountName` | Pod → SA | Pod spec via K8s API |
| `ServiceAccount.secrets` | SA → Secret (token) | SA object via K8s API |

No other edges should have `source: "observation"`.

---

## 3. INFERENCE Derivation Rules

Every INFERENCE edge MUST cite ≥1 OBSERVATION edge in its `derived_from` field.

### 3.1 Resource Creation → Implicit Identity Access

| Trigger | Edge | Condition |
|---------|------|-----------|
| Role rule: `create` on `deployments`, `pods`, `jobs`, `cronjobs`, `replicasets`, `statefulsets`, `daemonsets` | **Role → SA_in_same_namespace** | SA exists in target namespace |
| Reasoning | Can create workloads → can bind a different SA → transitive identity access |

### 3.2 Secret Access → Token/Identity Theft

| Trigger | Edge | Condition |
|---------|------|-----------|
| Role rule: `get` on `secrets` | **Role → SA_in_same_namespace** | SA's token Secret exists in that namespace |
| Role rule: `list`, `watch` on `secrets` | **Role → SA_in_same_namespace** MUST list all secrets | Only `get` is sufficient for targeted attack; `list` upgrades to bulk |
| Reasoning | Can read SA token Secret → can impersonate that SA → identity theft |

### 3.3 Impersonate → Identity Escalation

| Trigger | Edge | Condition |
|---------|------|-----------|
| ClusterRole rule: `impersonate` on `users` | **ClusterRole → impersonated_identity** | Identity exists (e.g., `system:node:*` → kubelet) |
| ClusterRole rule: `impersonate` on `groups` | **ClusterRole → group_members** | Group has members (e.g., `system:masters`) |
| Reasoning | Can become another identity → inherits all permissions of that identity |

### 3.4 Pod Exec/Attach → Pod Compromise

| Trigger | Edge | Condition |
|---------|------|-----------|
| Role rule: `create` on `pods/exec` | **SA → Pod** | Pod exists in same namespace |
| Role rule: `create` on `pods/attach` | **SA → Pod** | Pod exists in same namespace |
| Reasoning | Can exec into running pod → access to pod's SA, /proc, mount points |

### 3.5 Pod Create + Privileged → Host Access

| Trigger | Edge | Condition |
|---------|------|-----------|
| Role rule: `create` on `pods` **AND** no PodSecurityPolicy blocking privileged | **SA → node/kubelet** | Can deploy privileged pod → nsenter to host |
| Reasoning | Privileged pod = hostPID + hostNetwork + full capability → host compromise |

### 3.6 Volume Mount Access → Data Exfiltration

| Trigger | Edge | Condition |
|---------|------|-----------|
| Role rule: `create` on `pods` **AND** can reference `hostPath` / `configMap` / `secret` volumes | **SA → volume_data** | Volume type permits cross-pod data access |
| Reasoning | Can mount volumes from other sources → data bridge between identities |

---

## 4. DEFAULT Edge Rules

DEFAULT edges are **system-level trust assumptions**. They must NOT be inferred from RBAC.

| Edge | Condition | Always True? |
|------|-----------|--------------|
| SA → `kube-apiserver` | Every SA gets a JWT token granting API access | Yes |
| `kube-apiserver` → `etcd` | API server is the only etcd client in standard K8s | Yes (if etcd exists) |
| `kubelet` → `kube-apiserver` | Kubelet has client certificate for API access | Yes |

**Constraint**: DEFAULT edges have `risk ≤ RiskLevel.MEDIUM` because they represent
baseline access, not escalated privilege. If a DEFAULT edge is the *only* link in a
critical path, the path is suspect.

---

## 5. Forbidden Inferences

The following MUST NOT be added as inference edges:

| Anti-Pattern | Why |
|--------------|-----|
| INFERENCE without `derived_from` | Orphan — no fact anchor |
| Circular inference (A→B via inference, B→A via inference) | Creates self-sustaining loop with no observation ground |
| `get` on `pods` → pod compromise | Reading pod metadata ≠ compromising pod. Needs `exec` or `create`+privileged. |
| `*` (all verbs) → all INFERENCE rules apply | Over-permissive. Each verb cluster must be reasoned about independently. |
| DEFAULT edge with `risk=CRITICAL` | System trust is baseline, not escalation |

---

## 6. Path Groundedness Constraint

A valid attack path from ENTRY to CRITICAL_ASSET must satisfy:

```
OBSERVATION_ratio = count(OBSERVATION_edges_on_path) / total_edges_on_path
OBSERVATION_ratio >= 0.33
```

i.e., at least 1 in 3 edges must be directly observable. Paths with fewer than this
are "speculative" and should be flagged.

---

## 7. Edge Metadata Schema

```python
# OBSERVATION edge metadata
{
    "source": "observation",
    "evidence": {
        "type": "RoleBinding | ClusterRoleBinding",
        "name": "<object-name>",
        "namespace": "<namespace>",  # omitted for cluster-scoped
    }
}

# INFERENCE edge metadata
{
    "source": "inference",
    "derived_from": ["<source>-><target>", ...],  # ≥1 OBSERVATION edge
    "capability": {
        "verbs": ["create", "get", ...],
        "resources": ["deployments", "secrets", ...],
        "apiGroups": ["", "apps", ...],
    },
    "reasoning": "<human-readable derivation logic>",
}

# DEFAULT edge metadata
{
    "source": "default",
    "reasoning": "<why this trust is always present>",
}
```

---

## 8. Versioning

| Version | Change |
|---------|--------|
| 0.5.0 | Initial spec: 3 source types, 6 inference rules, 5 forbidden patterns, groundedness constraint |
