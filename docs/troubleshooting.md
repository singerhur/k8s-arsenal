# 故障排除指南

## 安装问题

### `pip install` 失败

```bash
# 确保 Python 版本 >= 3.10
python --version

# 使用虚拟环境
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # macOS/Linux

# 重新安装
pip install -e .
```

### `k8s-arsenal` 命令不可用

```bash
# 确认已安装
pip list | grep k8s-arsenal

# 使用完整模块路径
python -m k8s_arsenal.cli --help
```

### rich 模块缺失

```bash
# rich 在 requirements.txt 中声明，确保 pip install -e . 完成
pip install rich
```

---

## 运行时问题

### 非 K8s 环境运行

`recon` 和 `self-check` 在非 K8s 环境下会降级运行：
```bash
# recon 仍可运行（显示 bare-metal）
k8s-arsenal recon

# self-check 会检测到非容器环境
k8s-arsenal self-check

# catalog / optimize / assess 可离线使用
k8s-arsenal catalog
```

### Kubernetes API 连接失败

```bash
# 检查 kubeconfig
kubectl config current-context

# 显式指定 kubeconfig
k8s-arsenal recon --kubeconfig /path/to/kubeconfig

# 在 Pod 内运行时检查 SA token
ls /var/run/secrets/kubernetes.io/serviceaccount/

# 跳过 RBAC 检查
k8s-arsenal self-check --no-rbac
```

### AWS IMDS 超时

```bash
# IMDSv2 token 超时在网络受限的 Pod 中常见
# cloud base.py 有过期时间和重试机制
# 如持续失败，可限制检查范围：
k8s-arsenal catalog --phase credential_access | grep -v aws
```

### PowerShell 中文乱码

```bash
# 终端的 PowerShell 中文显示乱码是编码问题
# 使用 --json 输出避免乱码
k8s-arsenal assess --json

# 或设置终端编码
chcp 65001
```

---

## 性能问题

### 导入慢

```bash
# 首次导入需要加载所有模块
# 后续调用在同一个 Python 进程中会更快
python -c "from k8s_arsenal.core.optimizer import AttackVectorOptimizer"
```

### 大量向量处理

```bash
# 使用分阶段筛选减少处理量
k8s-arsenal optimize --compare --phase persistence --top 10

# 不含高级向量（减少 ~18 条）
k8s-arsenal catalog --no-advanced
```

---

## 常见错误信息

### `AttackPhase(phase)` → ValueError

```
k8s-arsenal catalog --phase wrong_phase
# → 无效的攻击阶段: wrong_phase
```

**解决**: 使用有效的阶段名称：
```
discovery, initial_access, execution, persistence,
privilege_escalation, defense_evasion, credential_access,
lateral_movement, collection, exfiltration, impact
```

### `导入失败: No module named 'k8s_arsenal.core.optimizer'`

**解决**: 
```bash
pip install -e .  # 重新安装以更新 egg-link
python -c "import k8s_arsenal.core"  # 验证
```

### `AttributeError: 'EscapeVector' object has no attribute 'phase'`

**原因**: EscapeVector 和 AttackVector 是不同的数据模型。

**解决**: `_collect_all_attack_vectors()` (不含 EscapeVector) 用于 optimizer，
`_collect_all_vectors()` (含 EscapeVector) 用于 catalog。

---

## 获取帮助

```bash
# 查看所有命令
k8s-arsenal --help

# 查看特定命令帮助
k8s-arsenal assess --help
k8s-arsenal optimize --help
k8s-arsenal playbook --help

# 查看版本
k8s-arsenal --version
```
