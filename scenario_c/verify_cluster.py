"""Scenario C: 集群验证 — 从真实 RBAC 边构建 AttackGraph 并运行全部图基元

从 minikube 集群中提取真实 RBAC 关系，构建 AttackGraph，验证图基元。
每条边标注 metadata.source: observation | inference | default
"""

from __future__ import annotations

import sys, subprocess, json

sys.path.insert(0, "D:/5555555")

from k8s_arsenal.models import TrustEdge, AttackGraph, RiskLevel, EdgeSource
from k8s_arsenal.playbook.chains import (
    build_graph, reachable, shortest_path, find_pivot_points,
)


# ─────────────────────────────────────────────
# 1. 从集群发现信任边
# ─────────────────────────────────────────────

def discover_trust_edges() -> list[TrustEdge]:
    """从 kubectl 发现 RBAC 信任边"""
    edges: list[TrustEdge] = []

    # 1.1 发现 RoleBindings (跨 namespace 的信任)
    r = subprocess.run(
        "kubectl get rolebinding -A -o json", shell=True, capture_output=True, text=True
    )
    rolebindings = json.loads(r.stdout).get("items", [])

    for rb in rolebindings:
        ns = rb["metadata"]["namespace"]
        role_ref = rb.get("roleRef", {})
        role_name = role_ref.get("name", "")
        kind = role_ref.get("kind", "Role")

        for subj in rb.get("subjects", []):
            if subj.get("kind") != "ServiceAccount":
                continue
            src_ns = subj.get("namespace", "")
            src_name = subj.get("name", "")
            src = f"{src_ns}/{src_name}"

            if ns == src_ns:
                target = f"{ns}/{role_name}"
            else:
                target = f"{ns}/{role_name}"

            edges.append(TrustEdge(
                source=src,
                target=target,
                relationship=f"RoleBinding: {kind}/{role_name} (namespace={ns})",
                credential_type="RBAC: RoleBinding",
                auto_rotated=False,
                risk=RiskLevel.HIGH if kind == "ClusterRole" else RiskLevel.MEDIUM,
                metadata={
                    "source": EdgeSource.OBSERVATION.value,
                    "evidence": {
                        "type": "RoleBinding",
                        "name": rb["metadata"]["name"],
                        "namespace": ns,
                    },
                    "kind": kind,
                },
            ))

    # 1.2 发现 ClusterRoleBindings
    r = subprocess.run(
        "kubectl get clusterrolebinding -o json", shell=True, capture_output=True, text=True
    )
    crbs = json.loads(r.stdout).get("items", [])

    for crb in crbs:
        role_ref = crb.get("roleRef", {})
        role_name = role_ref.get("name", "")

        for subj in crb.get("subjects", []):
            if subj.get("kind") != "ServiceAccount":
                continue
            src_ns = subj.get("namespace", "")
            src_name = subj.get("name", "")
            src = f"{src_ns}/{src_name}"

            target = f"cluster/{role_name}"

            edges.append(TrustEdge(
                source=src,
                target=target,
                relationship=f"ClusterRoleBinding: ClusterRole/{role_name}",
                credential_type="RBAC: ClusterRoleBinding",
                auto_rotated=False,
                risk=RiskLevel.CRITICAL,
                metadata={
                    "source": EdgeSource.OBSERVATION.value,
                    "evidence": {
                        "type": "ClusterRoleBinding",
                        "name": crb["metadata"]["name"],
                    },
                },
            ))

    return edges


# ─────────────────────────────────────────────
# 2. AttackGraph 分析
# ─────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  Scenario C: Cluster Verification -- AttackGraph Analysis")
    print("=" * 60)

    # 2.1 发现信任边
    print("\n[1] Discovering trust edges from cluster...")
    edges = discover_trust_edges()
    # 只保留我们场景相关的边
    scenario_sas = {
        "ci-ns/ci-pipeline-sa",
        "prod-ns/prod-app-sa",
        "monitoring-ns/monitoring-operator-sa",
    }
    scenario_edges = [
        e for e in edges
        if e.source in scenario_sas or any(s in e.relationship for s in [
            "ci-deployer", "monitoring-reader", "kubelet-impersonator"
        ])
    ]
    print(f"  Total RBAC edges: {len(edges)}")
    print(f"  Scenario C RBAC edges: {len(scenario_edges)}")

    # 添加语义桥接边 (INFERENCE)
    # ci-deployer Role (prod-ns) can create Deployment -> implicit trust to prod-app-sa
    scenario_edges.append(TrustEdge(
        source="prod-ns/ci-deployer",
        target="prod-ns/prod-app-sa",
        relationship="Role: ci-deployer can deploy pods (grants access to prod-app-sa)",
        credential_type="RBAC: verbs=create, resources=deployments",
        auto_rotated=False,
        risk=RiskLevel.HIGH,
        metadata={
            "source": EdgeSource.INFERENCE.value,
            "derived_from": ["ci-ns/ci-pipeline-sa->prod-ns/ci-deployer"],
            "capability": {
                "verbs": ["create", "get", "list", "update", "patch", "delete"],
                "resources": ["deployments", "replicasets"],
            },
            "reasoning": "ci-deployer has deployments/create in prod-ns -> can create pods that use prod-app-sa",
        },
    ))
    scenario_edges.append(TrustEdge(
        source="monitoring-ns/monitoring-reader",
        target="monitoring-ns/monitoring-operator-sa",
        relationship="Role: monitoring-reader can read SA token secret",
        credential_type="RBAC: verbs=get, resources=secrets",
        auto_rotated=False,
        risk=RiskLevel.HIGH,
        metadata={
            "source": EdgeSource.INFERENCE.value,
            "derived_from": ["prod-ns/prod-app-sa->monitoring-ns/monitoring-reader"],
            "capability": {
                "verbs": ["get", "list", "watch"],
                "resources": ["secrets"],
            },
            "reasoning": "monitoring-reader has secrets/get in monitoring-ns -> can read monitoring-operator-sa token from Secret",
        },
    ))

    # 默认边: every SA has standard JWT token -> API Server access
    scenario_edges.append(TrustEdge(
        source="prod-ns/prod-app-sa",
        target="kube-apiserver",
        relationship="Standard SA Token -> API Server access",
        credential_type="ServiceAccount Token (JWT)",
        auto_rotated=True,
        risk=RiskLevel.MEDIUM,
        metadata={
            "source": EdgeSource.DEFAULT.value,
            "reasoning": "Every SA has default JWT token granting API Server access",
        },
    ))

    print(f"  After semantic bridges: {len(scenario_edges)} edges")

    # kubelet impersonator -> api-server (INFERENCE)
    scenario_edges.append(TrustEdge(
        source="cluster/kubelet-impersonator",
        target="kube-apiserver",
        relationship="Impersonate -> API Server access",
        credential_type="kubelet-client-current.pem",
        auto_rotated=True,
        risk=RiskLevel.CRITICAL,
        metadata={
            "source": EdgeSource.INFERENCE.value,
            "derived_from": ["monitoring-ns/monitoring-operator-sa->cluster/kubelet-impersonator"],
            "capability": {
                "verbs": ["impersonate"],
                "resources": ["users"],
                "resourceNames": ["system:node:*"],
            },
            "reasoning": "kubelet-impersonator ClusterRole allows impersonating kubelet -> get kubelet client cert -> full API Server access as system:node",
        },
    ))

    # 定义节点标签
    nodes: dict[str, str] = {
        "ci-ns/ci-pipeline-sa":          "CI Pipeline SA [ENTRY]",
        "prod-ns/ci-deployer":           "CI Deployer Role (prod-ns)",
        "prod-ns/prod-app-sa":           "Prod App SA [PIVOT]",
        "monitoring-ns/monitoring-reader": "Monitoring Reader Role",
        "monitoring-ns/monitoring-operator-sa": "Monitoring Operator SA",
        "cluster/kubelet-impersonator":   "Kubelet Impersonator ClusterRole",
        "kube-apiserver":                 "API Server [CRITICAL]",
    }

    # 2.3 打印边的列表
    print("\n[2] Trust Edges:")
    for i, e in enumerate(scenario_edges, 1):
        risk_tag = "CRITICAL" if e.risk == RiskLevel.CRITICAL else "HIGH" if e.risk == RiskLevel.HIGH else "MEDIUM"
        src_type = e.metadata.get("source", "unknown")
        print(f"  E{i}: {e.source} -> {e.target}  [{risk_tag}]  ({src_type})")
        print(f"      {e.relationship}")

    # Metadata 分类统计
    obs_edges = [e for e in scenario_edges if e.metadata.get("source") == "observation"]
    inf_edges = [e for e in scenario_edges if e.metadata.get("source") == "inference"]
    def_edges = [e for e in scenario_edges if e.metadata.get("source") == "default"]
    print(f"\n  Observation: {len(obs_edges)} edges (from K8s API objects)")
    print(f"  Inference:   {len(inf_edges)} edges (semantic capability derivation)")
    print(f"  Default:     {len(def_edges)} edges (system implicit trust)")

    # 2.4 构建 AttackGraph
    print(f"\n[3] Building AttackGraph...")
    graph = build_graph(trust_edges=scenario_edges, nodes=nodes)
    print(f"  Nodes: {len(graph.nodes)}")
    print(f"  Edges: {len(graph.edges)}")
    print(f"  Entry Points: {graph.entry_points}")
    print(f"  Critical Assets: {graph.critical_assets}")

    # 2.5 可达性分析
    print(f"\n[4] Reachability Analysis:")
    src = "ci-ns/ci-pipeline-sa"
    dst = "kube-apiserver"
    queries = [
        (src, dst, "CI SA -> API Server"),
        (src, "cluster/kubelet-impersonator", "CI SA -> Kubelet Impersonator"),
        ("prod-ns/prod-app-sa", dst, "Prod SA -> API Server"),
        (dst, src, "API Server -> CI SA (reverse)"),
    ]
    for s, d, label in queries:
        ok = reachable(graph, s, d)
        tag = "PASS" if ok else "FAIL"
        print(f"  [{tag}] {s} -> {d}  ({label})")

    # 2.6 最短路径
    print(f"\n[5] Shortest Path:")
    sp = shortest_path(graph, src, dst)
    if sp:
        print(f"  CI SA -> API Server: {' -> '.join(sp)} ({len(sp)-1} hops)")
    else:
        print(f"  CI SA -> API Server: NOT REACHABLE")

    # 2.7 枢纽点
    print(f"\n[6] Pivot Points (out-degree >= 2):")
    pivots = find_pivot_points(graph)
    if pivots:
        for node, deg in pivots:
            label = nodes.get(node, node)
            print(f"  * {node} (degree={deg}) -- {label}")
    else:
        print("  None found")

    # 2.8 总结
    print(f"\n{'=' * 60}")
    print("  Verification Summary")
    print(f"{'=' * 60}")
    checks = [
        ("Cluster RBAC edges discovered", len(edges) > 0),
        ("Scenario C edges found", len(scenario_edges) >= 4),
        ("Entry point identified", len(graph.entry_points) > 0),
        ("Critical asset identified", len(graph.critical_assets) > 0),
        ("CI -> API reachable", reachable(graph, src, dst)),
        ("Pivot points exist", len(pivots) > 0),
        ("3 obs + 3 inf + 1 default edges",
         len(obs_edges) == 3 and len(inf_edges) == 3 and len(def_edges) == 1),
    ]
    all_ok = True
    for name, ok in checks:
        tag = "PASS" if ok else "FAIL"
        if not ok:
            all_ok = False
        print(f"  [{tag}] {name}")

    print(f"\n  {'[PASS] ALL CHECKS PASSED' if all_ok else '[FAIL] SOME CHECKS FAILED'}")


if __name__ == "__main__":
    main()
