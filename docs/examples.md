# K8s Arsenal 使用示例

## 基础场景

### 1. Pod 内自检（通常第一步）

```bash
# 在 K8s Pod 内执行，快速了解当前环境
k8s-arsenal self-check

# 导出 JSON 报告供后续分析
k8s-arsenal self-check -o recon-report.json

# 跳过 RBAC 检查（无 k8s API 访问时）
k8s-arsenal self-check --no-rbac
```

### 2. 战场评估

```bash
# 综合分析环境，获取攻击策略建议
k8s-arsenal assess

# 输出示例：
#   环境指纹: containerized|k8s|privileged|hostPID|docker-sock|caps:CAP_SYS_ADMIN
#   攻击面评分: ████████████████░░░░ 80/100
#   检测强度: LOW
#   环境类型: 靶场/CTF
#   关键弱点: privileged container / mounted docker socket / hostPID enabled

# JSON 输出（可管道给其它工具）
k8s-arsenal assess --json | jq '.assessment.attack_surface_score'
```

### 3. 攻击向量评分排序

```bash
# 查看最优攻击向量
k8s-arsenal optimize --compare

# 隐蔽优先模式（高检测环境）
k8s-arsenal optimize --compare --stealth

# 只看 persistence 阶段
k8s-arsenal optimize --compare --phase persistence --top 5
```

### 4. 生成攻击链

```bash
# 智能评分模式（推荐）
k8s-arsenal playbook --smart

# 经典模板模式
k8s-arsenal playbook --entry "privileged-pod" --target "node-access"

# 指定入口和目标
k8s-arsenal playbook --smart --entry "eks-ssrf" --target "cross-account"
```

### 5. 逃逸检测

```bash
# 检测当前 Pod 的逃逸条件
k8s-arsenal escape --check

# 列出所有已编目逃逸技术
k8s-arsenal escape --list
```

### 6. 技术编目浏览

```bash
# 查看全部攻击技术
k8s-arsenal catalog

# 按阶段筛选
k8s-arsenal catalog --phase privilege_escalation

# 高风险技术
k8s-arsenal catalog --risk critical

# 排除高级 CVE 向量
k8s-arsenal catalog --no-advanced

# 导出 JSON
k8s-arsenal catalog -o catalog.json
```

---

## 红蓝对抗场景

### 场景 A：AWS EKS 集群突破

```bash
# 1. Pod 内自检
k8s-arsenal self-check -o phase1.json

# 2. 战场评估
k8s-arsenal assess

# 3. 检查 IRSA 利用路径
k8s-arsenal catalog --phase credential_access | grep -i aws

# 4. 生成 EKS 攻击链
k8s-arsenal playbook --smart --entry "eks-irsa" --target "cross-account-s3"

# 5. 导出完整报告
k8s-arsenal export -f html -o eks-attack-chain.html
```

### 场景 B：CTF 靶场快速突破

```bash
# 1. 快速评估
k8s-arsenal assess
# → 识别出 target/CTF 环境，攻击面 85/100

# 2. 最快路径
k8s-arsenal optimize --compare | head -5
# → 高成功率向量优先

# 3. 逃逸向量
k8s-arsenal escape --check

# 4. 执行最优链
k8s-arsenal optimize
# → 按链顺序逐步操作
```

### 场景 C：高检测企业环境

```bash
# 1. 评估检测强度
k8s-arsenal assess
# → 检测强度: HIGH，推荐低姿态侦察

# 2. 隐蔽优先优化
k8s-arsenal optimize --compare --stealth
# → 隐蔽性高的向量排前面

# 3. 查看防御逃逸技术
k8s-arsenal catalog --phase defense_evasion
# → 选择适合当前环境的逃逸技术

# 4. 生成低检测链
k8s-arsenal playbook --smart
# → 优先 discovery → credential_access → persistence
#   避免 noisy execution 和 exfiltration
```

---

## 报告导出

```bash
# HTML 报告（含样式，可浏览器打开）
k8s-arsenal export -f html -o report.html

# Markdown 报告（GitHub/GitLab 友好）
k8s-arsenal export -f md -o report.md

# JSON 报告（程序化处理）
k8s-arsenal export -f json -o report.json

# 导出攻击剧本
k8s-arsenal export -f html -o playbook.html --what playbook

# 自定义标题
k8s-arsenal export -f html -o report.html --title "EKS Cluster Attack Surface Report"
```

---

## Python API 使用

```python
from k8s_arsenal.core.engine import AdaptiveEngine
from k8s_arsenal.core.optimizer import AttackVectorOptimizer
from k8s_arsenal.playbook.chains import SmartAttackChain
from k8s_arsenal.models import EnvironmentProfile

# 1. 创建环境画像
profile = EnvironmentProfile(
    is_kubernetes=True,
    is_container=True,
    is_privileged=True,
    host_pid=True,
    mounted_docker_sock=True,
    capabilities=["CAP_SYS_ADMIN"],
)

# 2. 战场评估
engine = AdaptiveEngine()
assessment = engine.assess_battlefield(profile)
print(f"Attack surface: {assessment.attack_surface_score}/100")

# 3. 获取优化器权重
weights = engine.get_weights_for_optimizer()

# 4. 优化攻击链
sc = SmartAttackChain(optimizer_weights=weights)
chain = sc.generate_optimal_chain(max_depth=4)

for sv in chain:
    print(f"  {sv.vector.id}: score={sv.composite_score:.3f}")

# 5. 模拟反馈
sc.adapt_to_feedback(chain[0].vector.id, success=True)
sc.adapt_to_feedback(chain[1].vector.id, success=True, detection_triggered=True)
report = sc.get_progress_report()
```

---

## 集成到 CI/CD

```yaml
# .github/workflows/security-scan.yml
name: K8s Attack Surface Scan

on:
  schedule:
    - cron: '0 6 * * 1'  # 每周一早 6 点

jobs:
  scan:
    runs-on: [self-hosted, kubernetes]
    steps:
      - name: Run K8s Arsenal
        run: |
          pip install k8s-arsenal
          k8s-arsenal assess --json > assessment.json
          k8s-arsenal catalog --risk critical > critical-vectors.txt
          k8s-arsenal export -f html -o scan-report.html

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: k8s-security-scan
          path: scan-report.html
```
