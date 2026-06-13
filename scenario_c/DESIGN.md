# Scenario C: 供应链权限坍塌 (Supply Chain Permission Collapse)

> v0.5.0 验收标准 — 验证 AttackGraph 在非显而易见的供应链攻击链中的分析能力

## 攻击情景

一个开发团队使用 GitOps 流水线。攻击者污染了 CI 镜像仓库中的 Helm Chart，导致一条跨越 5 层信任边界的权限坍塌链。

## 攻击链

```
                      ┌─────────────────┐
                      │  ci-pipeline-sa  │  ← 入口点 (ENTRY)
                      │  (CI Namespace)  │
                      └────────┬────────┘
                               │ SC-004: Tag Override
                               │ (推送恶意 Chart 到 registry)
                               ▼
                      ┌─────────────────┐
                      │  helm-registry   │
                      │  (镜像仓库)       │
                      └────────┬────────┘
                               │ CHART_DEPLOY
                               │ (GitOps sync 部署)
                               ▼
          ┌────────────────────────────────────────┐
          │            prod-app-sa                 │  ★ 枢纽点 (PIVOT)
          │          (Production NS)               │  出度 = 2
          └───────┬──────────────────┬─────────────┘
                  │                  │
     SECRET_READ  │                  │ TOKEN_ACCESS
     (RBAC: 读    │                  │ (标准 SA Token
      monitoring  │                  │  → API Server)
      secrets)    │                  │
                  ▼                  ▼
    ┌────────────────────┐  ┌──────────────────┐
    │ monitoring-operator│  │   api-server     │  ★ 关键资产 (CRITICAL)
    │ (System NS)        │  │  (集群控制平面)   │
    └────────┬───────────┘  └──────────────────┘
             │                     ▲
    IMPERSONATE                   │
    (ClusterRole:                 │
     impersonate-kubelet)         │
             │          CLIENT_CERT
             ▼          (kubelet 证书)
    ┌────────────────┐            │
    │    kubelet     │────────────┘
    │  (Node Agent)  │
    └────────────────┘
```

## 信任边明细

| 边 | Source → Target | 关系 | 凭证 | 风险 |
|----|----------------|------|------|------|
| E1 | ci-pipeline-sa → helm-registry | PUSH_IMAGE | CI Token (长期) | HIGH |
| E2 | helm-registry → prod-app-sa | CHART_DEPLOY | GitOps Sync | CRITICAL |
| E3 | prod-app-sa → monitoring-operator | SECRET_READ | RBAC: get secrets in monitoring-ns | HIGH |
| E4 | prod-app-sa → api-server | TOKEN_ACCESS | SA Token (标准) | MEDIUM |
| E5 | monitoring-operator → kubelet | IMPERSONATE | ClusterRole: impersonate | CRITICAL |
| E6 | kubelet → api-server | CLIENT_CERT | kubelet-client-current.pem | CRITICAL |

## AttackGraph 预期结果

### build_graph()
- nodes: 6
- edges: 6
- entry_points: ["ci-pipeline-sa"]  (只有出边，无入边)
- critical_assets: ["api-server"]  (只有入边，无出边)

### reachable()
- ci-pipeline-sa → api-server: **True** (两条路径均可达)
- ci-pipeline-sa → kubelet: **True**
- helm-registry → api-server: **True**

### shortest_path()
- ci-pipeline-sa → api-server: 3-hop 路径
  `ci-pipeline-sa → helm-registry → prod-app-sa → api-server`

### find_pivot_points()
- prod-app-sa: out-degree **2** (→ monitoring-operator, → api-server)
- helm-registry: out-degree 1 (不满足 ≥2 阈值)

## 验证标准

- [ ] 全部 4 个图基元正常返回
- [ ] 两条攻击路径均可达
- [ ] 枢纽点正确识别为 prod-app-sa
- [ ] 最短路径优先走 TOKEN_ACCESS (不绕 kubelet)
- [ ] critical_assets 仅 api-server

## 后续：minikube 实战

设计验证通过后，在 minikube 中实际部署：
1. 创建 ci-ns / prod-ns / monitoring-ns 三个 Namespace
2. 部署 CI Pipeline SA + RBAC
3. 部署 Monitoring Operator + ClusterRole (impersonate kubelet)
4. 运行 k8s-arsenal trust-map 生成真实信任拓扑
5. 对比设计态与运行态图结构
