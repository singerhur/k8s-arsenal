# Changelog

All notable changes to K8s Arsenal will be documented in this file.

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