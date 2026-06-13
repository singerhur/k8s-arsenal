"""Scenario C: 供应链权限坍塌 — AttackGraph 验证脚本

硬编码供应链攻击链的信任边，运行全部 4 个图基元，
验证 AttackGraph 在非显而易见的多跳攻击链中的分析能力。
"""

from __future__ import annotations

import sys
sys.path.insert(0, "D:/5555555")

from k8s_arsenal.models import TrustEdge, AttackGraph, RiskLevel
from k8s_arsenal.playbook.chains import (
    build_graph,
    reachable,
    shortest_path,
    find_pivot_points,
)


# ─────────────────────────────────────────────
# 1. 攻击链定义
# ─────────────────────────────────────────────

NODES: dict[str, str] = {
    "ci-pipeline-sa":      "CI Pipeline ServiceAccount (ci-ns) [ENTRY]",
    "helm-registry":       "Helm Chart Registry (被污染的镜像仓库)",
    "prod-app-sa":         "Production App ServiceAccount (prod-ns) [PIVOT]",
    "monitoring-operator": "Monitoring Operator ServiceAccount (monitoring-ns)",
    "kubelet":             "Kubelet Node Agent",
    "api-server":          "Kubernetes API Server [CRITICAL ASSET]",
}

EDGES: list[TrustEdge] = [
    TrustEdge(
        source="ci-pipeline-sa",
        target="helm-registry",
        relationship="镜像标签覆盖 (SC-004: Tag Override)",
        credential_type="CI Token (长期有效)",
        auto_rotated=False,
        risk=RiskLevel.HIGH,
    ),
    TrustEdge(
        source="helm-registry",
        target="prod-app-sa",
        relationship="Helm Chart 静默部署 (GitOps Sync)",
        credential_type="GitOps Sync Token",
        auto_rotated=False,
        risk=RiskLevel.CRITICAL,
    ),
    TrustEdge(
        source="prod-app-sa",
        target="monitoring-operator",
        relationship="跨 Namespace Secret 读取 (RBAC: get secrets)",
        credential_type="RBAC: verbs=get, resources=secrets",
        auto_rotated=False,
        risk=RiskLevel.HIGH,
    ),
    TrustEdge(
        source="prod-app-sa",
        target="api-server",
        relationship="标准 SA Token 访问 API Server",
        credential_type="ServiceAccount Token (JWT)",
        auto_rotated=True,
        risk=RiskLevel.MEDIUM,
    ),
    TrustEdge(
        source="monitoring-operator",
        target="kubelet",
        relationship="Impersonate Kubelet 身份 (ClusterRole)",
        credential_type="ClusterRole: impersonate, resource=users",
        auto_rotated=False,
        risk=RiskLevel.CRITICAL,
    ),
    TrustEdge(
        source="kubelet",
        target="api-server",
        relationship="Kubelet 客户端证书认证",
        credential_type="kubelet-client-current.pem",
        auto_rotated=True,
        risk=RiskLevel.CRITICAL,
    ),
]


# ─────────────────────────────────────────────
# 2. AttackGraph 分析
# ─────────────────────────────────────────────

def verify_scenario_c() -> dict:
    """运行供应链攻击链的 AttackGraph 全量分析"""
    results = {}

    # 2.1 构建攻击图
    graph = build_graph(trust_edges=EDGES, nodes=NODES)
    results["build"] = {
        "nodes": list(graph.nodes.keys()),
        "edges": len(graph.edges),
        "entry_points": graph.entry_points,
        "critical_assets": graph.critical_assets,
    }

    # 2.2 可达性分析
    key_queries = [
        ("ci-pipeline-sa", "api-server", "主攻击链：入口→关键资产"),
        ("ci-pipeline-sa", "kubelet", "入口→节点代理"),
        ("helm-registry", "api-server", "供应链入口→关键资产"),
        ("prod-app-sa", "api-server", "枢纽节点→关键资产（短路径）"),
        ("ci-pipeline-sa", "monitoring-operator", "入口→运维算子"),
        ("api-server", "ci-pipeline-sa", "反向：关键资产→入口（预期不可达）"),
    ]
    results["reachable"] = [
        {"src": s, "dst": d, "label": label, "result": reachable(graph, s, d)}
        for s, d, label in key_queries
    ]

    # 2.3 最短路径
    results["shortest_path"] = {
        "主链 (ci → api)": shortest_path(graph, "ci-pipeline-sa", "api-server"),
        "入口→kubelet": shortest_path(graph, "ci-pipeline-sa", "kubelet"),
        "供应链→api": shortest_path(graph, "helm-registry", "api-server"),
    }

    # 2.4 枢纽点分析
    results["pivot_points"] = find_pivot_points(graph)

    # 2.5 备用路径分析
    alternative_paths = []
    if results["shortest_path"]["主链 (ci → api)"]:
        alt_path = _find_alternative_path(
            graph,
            "ci-pipeline-sa",
            "api-server",
            results["shortest_path"]["主链 (ci → api)"],
        )
        if alt_path:
            alternative_paths.append(alt_path)
    results["alternative_paths"] = alternative_paths

    return results


def _find_alternative_path(
    graph: AttackGraph, src: str, dst: str, shortest: list[str]
) -> list[str] | None:
    """BFS 寻找与最短路径不同的备用路径"""
    adj: dict[str, list[str]] = {}
    for e in graph.edges:
        if e.source not in adj:
            adj[e.source] = []
        adj[e.source].append(e.target)

    visited = {src}
    queue: list[list[str]] = [[src]]
    while queue:
        path = queue.pop(0)
        current = path[-1]
        for neighbor in adj.get(current, []):
            if neighbor == dst:
                candidate = path + [neighbor]
                if candidate != shortest:
                    return candidate
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(path + [neighbor])
    return None


# ─────────────────────────────────────────────
# 3. 格式化输出
# ─────────────────────────────────────────────

def print_results(results: dict) -> None:
    """格式化打印 AttackGraph 分析结果"""
    b = results["build"]
    r = results["reachable"]
    sp = results["shortest_path"]
    pp = results["pivot_points"]

    print("=" * 60)
    print("  Scenario C: 供应链权限坍塌 -- AttackGraph 分析报告")
    print("=" * 60)

    # -- 图结构 --
    print(f"\n[GRAPH] 图结构")
    print(f"  Nodes: {', '.join(b['nodes'])} ({len(b['nodes'])} total)")
    print(f"  Edges: {b['edges']}")
    print(f"  Entry Points: {b['entry_points']}")
    print(f"  Critical Assets: {b['critical_assets']}")

    # -- 可达性 --
    print(f"\n[REACH] 可达性分析")
    for query in r:
        ok = "PASS" if query["result"] else "FAIL"
        print(f"  [{ok}] {query['src']} -> {query['dst']}  ({query['label']})")

    # -- 最短路径 --
    print(f"\n[PATH] 最短路径")
    for name, path in sp.items():
        if path:
            arrow = " -> ".join(path)
            print(f"  {name} ({len(path)-1} hops): {arrow}")
        else:
            print(f"  {name}: [FAIL] 不可达")

    # -- 枢纽点 --
    print(f"\n[PIVOT] 枢纽节点 (out-degree >= 2)")
    if pp:
        for node, degree in pp:
            role = NODES.get(node, node)
            print(f"  * {node}  (out-degree={degree}) -- {role}")
    else:
        print("  (无枢纽点)")

    # -- 备用路径 --
    alt = results.get("alternative_paths", [])
    if alt:
        print(f"\n[ALT] 备用攻击路径 ({len(alt)} found):")
        for p in alt:
            print(f"  {' -> '.join(p)} ({len(p)-1} hops)")

    # -- 验证结论 --
    print(f"\n{'=' * 60}")
    print("  验证结论")
    print(f"{'=' * 60}")

    checks = [
        ("入口点识别", b["entry_points"] == ["ci-pipeline-sa"]),
        ("关键资产识别", b["critical_assets"] == ["api-server"]),
        ("主攻击链可达", r[0]["result"] is True),
        ("反向不可达", r[5]["result"] is False),
        ("枢纽点 prod-app-sa", any(n == "prod-app-sa" and d >= 2 for n, d in pp)),
        ("最短路径 3 hops", sp.get("主链 (ci → api)") and len(sp["主链 (ci → api)"]) == 4),
        ("备用路径存在", len(alt) > 0),
    ]

    all_pass = True
    for name, passed in checks:
        ok = "PASS" if passed else "FAIL"
        if not passed:
            all_pass = False
        print(f"  [{ok}] {name}")

    print(f"\n  {'[PASS] ALL CHECKS PASSED' if all_pass else '[FAIL] SOME CHECKS FAILED'}")

    return all_pass


# ─────────────────────────────────────────────
# 4. 入口
# ─────────────────────────────────────────────

if __name__ == "__main__":
    results = verify_scenario_c()
    ok = print_results(results)
    sys.exit(0 if ok else 1)
