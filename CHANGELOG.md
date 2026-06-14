# Changelog

All notable changes to K8s Arsenal will be documented in this file.

## [0.10.0] - 2026-06-14

### Added
- **Live RBAC Adapter** (`recon/rbac_adapter.py`): Real-time K8s RBAC trust edge discovery
  - `build_live_rbac_edges()` — queries live cluster RoleBinding/ClusterRoleBinding to build TrustEdge objects
  - `build_live_topology()` — drop-in replacement for `build_trust_topology()`, merges infrastructure + RBAC edges
  - `list_service_accounts()` — discovers all SAs and resolves their effective RBAC rules
  - Rule-to-edge-type inference: 10 dangerous verb/resource patterns mapped to 5 edge types (Impersonate, TokenAccess, NodeAccess, RbacEdge, PodTrust)
  - Capability-to-risk-level mapping: CRITICAL (cluster_admin/impersonate/escalate) down to LOW
  - 46 new unit + integration tests (mocked K8s API)
- `recon/__init__.py` exports: `build_live_rbac_edges`, `build_live_topology`, `list_service_accounts`

### Changed
- Version: 0.9.3 -> 0.10.0 — first feature release since engine consolidation

## [0.9.0] - 2026-06-13

### Added
- **Architectural Invariants** (`runtime/invariants.py`): 18 个可执行设计约束，覆盖 v0.4–v0.8 六层体系
  - `assert_tactic_label_valid()` — tactic 五值互斥
  - `assert_identity_only_changes_on_defined_edges()` — 身份只在 TokenAccess/Impersonate 边缘上漂移
  - `assert_capability_set_monotonic()` — 能力单调累加
  - `assert_counterfactual_no_mutation()` — ΔT 不移除边外改变其他变量
  - `assert_evaluate_path_result_structure()` — trace 结构完整性
  - `assert_attack_label_dimensions_separated()` — outcome ≠ tactic 分离
  - `assert_mcs_exact_not_larger_than_greedy()` — 精确解边界
  - 等共 18 项
- `validate_trace_result()` — 单入口运行全部 invariants
- CI gate: `pytest -m invariants`，386 tests: 383 passed + 3 invariants marker tests = 386 collected (384 pass / 3 skip / 0 fail)

## [0.9.1] - 2026-06-14

### Fixed
- **Edge Semantic Contract**: `build_trust_topology()` 产出的 TrustEdge 缺失 `metadata` 字段，
  导致 v0.5-v0.9 runtime 管线在这些边上静默失效（identity_flow/capability_set/evaluator 读到空字符串）
- `trust_map.py` 9 处 TrustEdge 调用添加 `metadata={"edge_type": "ClientCertAuth"}` 等，
  8 种中文关系串映射为英文语义类型
- `identity_flow.py` 添加 `edge.relationship` fallback：
  `edge.metadata.get("edge_type") or edge.relationship or ""`

### Changed
- 无行为变更（T(S)/identity/capability 输出不变），仅数据可见性增强
- 384 passed / 3 skipped / 0 failed — 零回归

## [0.9.3] - 2026-06-14

### Added
- **ILP Minimal Cut Set** (`runtime/minimal_cut.py`): `ilp_minimal_cut()` — PuLP + CBC exact hitting-set solver
  - Replaces greedy overestimation on parallel-path graphs with provably optimal ILP
  - Formulation: min Σ x_e subject to Σ_{e in p} x_e ≥ 1 for all COMPROMISED paths
  - Trivial-path shortcut: single edge covering all paths → skips ILP, returns O(1)
  - Graceful fallback: if PuLP unavailable or solver fails → greedy
- PuLP dependency (`pyproject.toml`): `PuLP>=2.7.0`

### Changed
- `minimal_cut_set()`: ILP is now the default solver (`use_ilp=True`)
  - Falls back to exact subset enumeration → greedy when ILP is disabled/unavailable
- `AttackGraphEngine._run_mcs()`: passes `use_ilp=True` to `minimal_cut_set()`
- `runtime/__init__.py`: exports `ilp_minimal_cut`

### Fixed
- MCS strategy strings in tests now accept `"ilp"` / `"ilp (trivial)"` variants

---
- 403 passed / 3 skipped / 0 failures — 零回归
- 6 new ILP-specific tests added (14 total MCS tests)

## [0.9.2] - 2026-06-14

### Added
- **AttackGraphEngine** (`runtime/engine.py`): 统一的六层管线 API，桥接 CLI↔runtime 断裂
  - `AttackGraphEngine.from_trust_map(edges, entry_identity, critical_assets)` — 一行构建
  - `engine.analyze(compromise_threshold, run_counterfactuals, run_mcs, run_classifier, verify_mcs)` — 全管线执行
  - `EngineResult` dataclass: graph, terminal_state, final_identity, identity_chain, capabilities,
    trace, counterfactuals, mcs_cut_edges, labels, terminal_explanation
- **CLI `analyze` 命令** (`cli.py`, ~130 LOC): 将 `AttackGraphEngine` 接入 CLI
  - `--full-pipeline`, `--quick`, `--json`, `--entry`, `--target` 选项
  - Interactive menu option 10
- **MCS 验证门** (`runtime/minimal_cut.py`): `verify_cut_set()` — 验证每条割边移除后目标不可达
- **集成契约测试** (`tests/test_recon_to_runtime_contract.py`, 13 tests): trust_map 产出 → runtime 管线的端到端验证
- **Edge 验证警告** (`engine.py`): 运行时检测 metadata 缺失/关系未识别，不崩溃仅警告
- **能力 Source 3 回退** (`capability_set.py`): DockerSocket → node_access, HostPID → node_access, Privileged → node_access

### Fixed
- `known_rels` 补全 9 个中文关系名（之前只含英文 key，中文边被误报 unrecognized）
- `_RELATIONSHIP_HINT_CAPABILITIES` 补全中文 key 映射
- `build_graph()` nodes 自动从 edges 提取（修复 `graph_summary.nodes: 0`）
- `best_trace` 在 SAFE 路径下为 None 的 bug (`>` 改为 `>=` 比较)
- `AttackGraph.paths` 死字段移除
- `capability_set.is_compromised()` → DeprecationWarning + 委托到 `terminal_state.is_compromised()`

### Changed
- `models.py`: 移除 `AttackGraph.paths`（G-layer 不再缓存路径）
- `runtime/capability_set.py`: `is_compromised()` 标记 deprecated，迁移到 terminal_state 版本
- `playbook/chains.py`: `build_graph()` 从 edges 自动填充 nodes set

---
- 397 passed / 3 skipped / 0 failures — 零回归
- 实战验证: minikube 攻防实验通过，攻击面全生命周期（部署→探测→清理）

## [0.8.0] - 2026-06-13

### Added
- **Attack Semantics Classifier** (`runtime/classifier.py`): 语义投影层，从 trace 结果推导 MITRE 风格 tactic
  - 5 tactic labels: PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, CREDENTIAL_ACCESS, PERSISTENCE, EXECUTION
  - `CLUSTER_TAKEOVER` 显式移除 — 它是 T(S)=COMPROMISED 的结果，不是攻击机制
  - 两维分离: Outcome = T(S)（v0.5.1），Tactic = classifier（v0.8）
  - `AttackLabel` dataclass: tactic + outcome + evidence + confidence
- `classify(trace_result)` — 从 capabilities/identity_chain/trace 推导 tactic
- `infer_tactic()` — 单步推断

### Fixed
- `_CAPABILITY_MAP` 缺少 clusterroles/escalate → escalate_rbac 映射
- TokenAccess-only edge 误分类为 CREDENTIAL_ACCESS → 修正为 LATERAL_MOVEMENT

## [0.7.0] - 2026-06-13

### Added
- **Minimal Cut Set** (`runtime/minimal_cut.py`): 组合因果分析，找到打破所有 compromised paths 的最小边集合
  - 双轨策略: greedy (快速基线) + exact (ILP replacement, brute-force 枚举)
  - `minimal_cut_set()` — hitting-set 形式化，所有 COMPROMISED witness paths 的精确最小割
  - `greedy_minimal_cut()` — 贪心启发式，迭代移除覆盖最多 compromised paths 的边
- `PathEvaluationResult` dataclass — path 沿路的完整状态演化 trace

## [0.6.0] - 2026-06-13

### Added
- **Counterfactual Delta-T Kernel** (`runtime/counterfactual.py`): 单边因果分析 ΔT(S, G, G-e)
  - 4 种结果类型: Critical（T 改变）, Non-critical（T 不变）, Mitigation（改善）, Paradox（恶化）
  - 深拷贝整图后移除边，重新计算 shortest_path + T(S)，对比 baseline
  - `counterfactual()` — 返回 baseline vs counterfactual 完整对比

## [0.5.1] - 2026-06-13

### Added
- **Terminal State Function** (`runtime/evaluator.py`): 统一 T(S, G, p)
  - 三值终端状态: SAFE, PARTIAL, COMPROMISED
  - PARTIAL 覆盖有危险能力但尚未沦陷的退化状态
  - Decision order: escalate_rbac/impersonate → COMPROMISED 硬信号, 阈值能力累加, 关键资源可达
  - `is_compromised()` 向后兼容

## [0.5.0] - 2026-06-13

### Added
- **Identity Flow** (`runtime/identity_flow.py`): 身份沿路径的状态传播
  - 身份只在 TokenAccess/Impersonate 边缘上跃迁
  - 非变换边 (RbacEdge, InferenceEdge) 不得漂移身份
- **Capability Set** (`runtime/capability_set.py`): 路径上的能力累积
  - `_CAPABILITY_MAP`: resource/verb 对 → 能力 token 映射
  - 来源: InferenceEdge explicit cap annotations + Role/ClusterRole rules
- `evaluate_path()` — 桥接 identity_flow + capability_set 产生全路径 state evolution trace
- **AttackGraph** dataclass (`models.py`): (G, S, T, Δ, MCS, Label) 统一容器
  - nodes, edges, paths, entry_points, critical_assets
  - `TrustEdge.metadata` (dict) 向后兼容
- `build_graph()`, `reachable()`, `shortest_path()`, `find_pivot_points()` 图基元

## [0.4.0] - 2026-06-07

### Added
- PlaybookExecutor: 攻击检测→可执行命令，支持 --run / --stealth / --list-commands / --dry-run
- _VECTOR_ID_MAP: 直接 ID 映射表，消除命令匹配误/漏

### Fixed
- 命令关键字误匹配（P0）: _get_vector_command() 子串匹配导致 3 个向量返回 None（ESC-007/008/011），ESC-002 拿错命令 → 改用 _VECTOR_ID_MAP 直接 ID 映射
- 自检身份字段为空（P0）: _build_report() 直接 os.environ.get() 绕过 _check_identity() 解析结果 → 存储实例属性并复用
- Docker 内置 docker.io 包（CRI Socket 检测）
- catalog --phase 别名支持
- 靶场环境识别中文指纹匹配
- nginx:alpine → k8s-arsenal-pod:latest（国内镜像兼容）

### Changed
- executor.py 命令映射三合为一（_ESCAPE_COMMANDS 类常量）
- 7 个子模块 __init__.py 正式导出（advanced/evasion/lateral/network/persistence/supply_chain/utils）
- 清除死依赖 jinja2/python-dateutil
- 测试覆盖 200 用例（+65 新增）

## [0.3.0] - 2026-06-06

### Added
- 智能适应引擎（AdaptiveEngine）
- 攻击向量优化器（AttackVectorOptimizer）
- SmartAttackChain 加权评分排序

## [0.2.0] - 2026-06-05

### Added
- 基础攻击向量编目（72 项）
- 信任拓扑映射（trust-map）
- Pod 自检扫描（self-check）

## [0.1.0] - 2026-06-05

### Added
- 初始项目结构
- 基础环境探测（recon）
- 攻击面评估（assess）