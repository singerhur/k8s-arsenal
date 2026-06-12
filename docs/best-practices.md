# K8s Arsenal 最佳实践

## 红队操作 OPSEC

### 1. 评估优先，行动在后

```bash
# 永远先做战场评估
k8s-arsenal assess

# 根据检测强度决定策略
# LOW   → 激进模式，直接上高成功率向量
# HIGH  → 保守模式，优先信息收集 + 隐蔽操作
```

### 2. 分层使用

```bash
# 第一层：信息收集（无侵入）
k8s-arsenal self-check --no-rbac
k8s-arsenal catalog --phase discovery

# 第二层：条件匹配（低风险）
k8s-arsenal escape --check
k8s-arsenal assess

# 第三层：路径规划（离线分析）
k8s-arsenal optimize --compare --stealth
k8s-arsenal playbook --smart

# 第四层：执行（手动，一次一步）
# 按 playbook 输出逐步操作
```

### 3. 隐蔽优先原则

```
高检测环境:
  ✗ 避免: k8s-arsenal catalog --risk critical （高风险向量留在脑子里）
  ✓ 推荐: k8s-arsenal optimize --stealth
  ✓ 推荐: 优先 discovery → credential_access → persistence
  ✗ 避免: execution → exfiltration → impact（noisy 阶段）
```

---

## 工作流推荐

### 快速扫描流程

```
self-check → assess → optimize --compare → playbook --smart
(5 分钟完成全部分析)
```

### 深度分析流程

```
self-check -o profile.json
  → assess --json > assessment.json
  → escape --check
  → catalog --phase all -o full-catalog.json
  → optimize --compare --stealth > ranking.txt
  → playbook --smart
  → export -f html -o full-report.html
```

### 持续集成流程

```bash
# 每周扫描，对比变化
k8s-arsenal self-check -o scan-$(date +%Y%m%d).json
diff scan-20260101.json scan-20260108.json
```

---

## 工具组合

### 与 kubectl 配合

```bash
# 用 kubectl 补充信息
kubectl get pods -A
kubectl auth can-i --list
kubectl get clusterroles --all-namespaces

# 然后用 K8s Arsenal 分析
k8s-arsenal assess
k8s-arsenal catalog --phase privilege_escalation
```

### 与 kube-hunter 配合

```bash
# kube-hunter 扫描外部暴露面
kube-hunter --remote <cluster-ip>

# K8s Arsenal 分析内部攻击面
k8s-arsenal self-check
k8s-arsenal assess
```

### 与 Falco/Sysdig 配合

```bash
# 在 Falco 监控的环境中
# 优先使用 K8s Arsenal 的 evasion 模块
k8s-arsenal catalog --phase defense_evasion
k8s-arsenal optimize --stealth
```

---

## 安全使用

### 离线使用

```bash
# 所有编目功能完全离线可用
k8s-arsenal catalog
k8s-arsenal optimize --compare
k8s-arsenal playbook --smart

# 需要网络的功能
k8s-arsenal recon      # 需要 kubeconfig 或 in-cluster 凭证
k8s-arsenal self-check # 需要 /proc + /var/run 读取
```

### 痕迹管理

```
工具本身不写入磁盘（除显式 -o 参数），但不负责清理：
- kubectl 历史 → ~/.kube/cache
- Python 运行时缓存 → __pycache__/
- 临时文件 → /tmp/

建议在操作完成后：
  rm -rf ~/.kube/cache
  find /tmp -name "*.json" -mmin -60 -delete
```

### 免责声明

本工具仅用于**授权的安全评估**和**红蓝对抗演练**。

在以下场景使用可能违法：
- 未授权的第三方系统
- 未签署渗透测试授权协议的环境
- 生产环境（除非明确授权为红队演练）

使用者需自行承担合规责任。
