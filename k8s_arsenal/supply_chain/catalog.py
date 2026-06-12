"""供应链攻击编目

收录 Helm Chart 投毒、容器镜像污染、Operator 劫持、GitOps 中毒等技术。
"""

from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel


SUPPLY_CHAIN_VECTORS: list[AttackVector] = [
    AttackVector(
        id="SC-001",
        name="PyPI/依赖混淆投毒 (AI 模型依赖劫持)",
        phase=AttackPhase.INITIAL_ACCESS,
        risk=RiskLevel.HIGH,
        description=(
            "通过恶意 .pth 文件劫持 Python 导入路径。"
            "安装包时在 site-packages 植入加载器，"
            "利用 memfd_create + fork 实现无文件内存执行。"
            "主进程保持正常功能，隐藏恶意行为。"
        ),
        prerequisites=["目标环境使用 pip install", "可访问内部 PyPI 镜像"],
        steps=[
            "创建与内部包同名的恶意 PyPI 包",
            "利用 .pth 文件劫持 import 路径",
            "在 site-packages 植入加载器",
            "加载器在 import 时触发内存执行 ELF 载荷",
            "主进程功能正常，无落盘文件",
        ],
        detection_hints=[
            "异常 .pth 文件",
            "site-packages 中非预期的 .so 文件",
            "memfd 创建事件",
        ],
        references=["Dependency Confusion", "PEP 302"],
    ),
    AttackVector(
        id="SC-002",
        name="Helm Chart gotpl 模板注入",
        phase=AttackPhase.INITIAL_ACCESS,
        risk=RiskLevel.CRITICAL,
        description=(
            "利用 Helm 模板函数在 values.yaml 或 templates 中注入恶意命令。"
            "{{ .Files.Get }} 可读取隐藏文件，{{ lookup }} 可查询集群状态。"
            "Chart 安装时自动执行，无需用户交互。"
        ),
        prerequisites=["目标用户将安装 Helm Chart", "恶意 Chart 可访问"],
        steps=[
            "在 Chart 的 templates/ 中嵌入恶意模板",
            "利用 {{ .Files.Get }} 读取随 Chart 分发的隐藏 payload",
            "通过 post-install hook 执行",
            "hook-delete-policy: before-hook-creation 自动清理",
        ],
        detection_hints=[
            "Chart 模板中的非标准函数调用",
            "异常 hook 执行",
            "templates 中隐藏的 base64 编码数据",
        ],
        references=["Helm Chart Templates", "Helm Hooks"],
    ),
    AttackVector(
        id="SC-003",
        name="Helm Chart 依赖递归污染",
        phase=AttackPhase.INITIAL_ACCESS,
        risk=RiskLevel.HIGH,
        description=(
            "Chart 的子依赖声明再指向其他依赖，形成依赖链。"
            "攻击者只需污染链条最末端的一个小仓库。"
            "用户安装顶层 Chart 时，所有依赖自动拉取。"
        ),
        prerequisites=["目标 Chart 使用了子依赖", "可污染依赖链中任一点"],
        steps=[
            "在依赖链末端仓库推送恶意版本",
            "顶级 Chart 的 dependencies 自动拉取",
            "恶意代码通过多层依赖传递",
            "用户安装顶级 Chart 时静默触发",
        ],
        detection_hints=[
            "依赖链中的异常仓库",
            "非预期版本更新",
            "子依赖的 Chart.yaml 变更",
        ],
        references=["Helm Dependency Management"],
    ),
    AttackVector(
        id="SC-004",
        name="容器镜像重 Tag 攻击",
        phase=AttackPhase.INITIAL_ACCESS,
        risk=RiskLevel.HIGH,
        description=(
            "先推送正常镜像通过 CI 签名和 Digest 记录。"
            "随后强制覆盖同名 tag。"
            "拉取策略为 Always 的 Pod 重启后自动中招。"
            "Digest 列表和签名数据库均不会自动更新。"
        ),
        prerequisites=["可 push 目标镜像仓库", "目标 tag 可覆盖"],
        steps=[
            "推送正常镜像 v1.0.0，等待 CI 签名为 Digest abc123",
            "构造恶意镜像，重新推送覆盖 v1.0.0 tag",
            "Digest 记录仍指向 abc123，实际拉取的是恶意版本",
            "Pod 重启或滚动更新时拉取到恶意镜像",
        ],
        detection_hints=[
            "镜像 tag 与 Digest 不匹配",
            "镜像仓库 push 事件",
            "Pod 启动后行为异常",
        ],
        references=["OCI Distribution Spec"],
    ),
    AttackVector(
        id="SC-005",
        name="多架构镜像拆分投毒",
        phase=AttackPhase.INITIAL_ACCESS,
        risk=RiskLevel.MEDIUM,
        description=(
            "推送同一 tag 的 linux/amd64（正常）和 linux/arm64（恶意）镜像。"
            "docker pull 自动匹配当前架构。"
            "在 amd64 机器上审计时拉取到的是正常版本。"
        ),
        prerequisites=["可 push 多架构镜像到目标仓库"],
        steps=[
            "构建 linux/amd64 为正常版本",
            "构建 linux/arm64 为恶意版本",
            "docker buildx build --platform linux/amd64,linux/arm64 --push",
            "不同架构的节点拉到不同版本",
        ],
        detection_hints=[
            "相同 tag 不同架构的 Digest 差异",
            "特定架构节点上的异常行为",
        ],
        references=["Docker Buildx", "OCI Image Index"],
    ),
    AttackVector(
        id="SC-006",
        name="Operator 投毒（集群 Rootkit）",
        phase=AttackPhase.INITIAL_ACCESS,
        risk=RiskLevel.CRITICAL,
        description=(
            "K8s Operator 的 RBAC 通常极宽（* verbs on * resources）。"
            "劫持 Operator 镜像或 CRD 定义即可获得集群完全控制。"
            "可通过修改 Operator Deployment 或 registry 中间人实现。"
        ),
        prerequisites=["可修改 Operator Deployment", "或可劫持镜像仓库"],
        steps=[
            "修改 Operator 的 Deployment image",
            "恶意 Operator 创建新的 ClusterRoleBinding",
            "等待 Operator 重新部署",
            "通过 Operator 的宽泛权限控制集群",
        ],
        detection_hints=[
            "Operator Deployment 镜像变更",
            "Operator 创建的异常 RBAC 对象",
        ],
        references=["Kubernetes Operator Pattern"],
    ),
    AttackVector(
        id="SC-007",
        name="BuildKit 缓存投毒",
        phase=AttackPhase.INITIAL_ACCESS,
        risk=RiskLevel.MEDIUM,
        description=(
            "CI/CD 中使用 --cache-from 指向攻击者控制的 registry。"
            "BuildKit 直接复用投毒过的 cache layer。"
            "docker build 输出与 Dockerfile 定义不一致。"
            "所有基于该缓存的构建均被污染。"
        ),
        prerequisites=["CI/CD 使用了外部 cache registry", "可控制 cache registry"],
        steps=[
            "控制 CI 使用的 cache registry",
            "推送包含恶意 payload 的 cache layer",
            "BuildKit 拉取 cache 时复用投毒层",
            "构建产物包含非预期代码",
        ],
        detection_hints=[
            "构建日志中的外部 cache 引用",
            "构建产物与 Dockerfile 不匹配",
        ],
        references=["BuildKit cache", "Docker BuildKit"],
    ),
    AttackVector(
        id="SC-008",
        name="GitOps 控制器劫持 (ArgoCD/Flux)",
        phase=AttackPhase.INITIAL_ACCESS,
        risk=RiskLevel.CRITICAL,
        description=(
            "ArgoCD 的 Application SA 通常是 cluster-admin。"
            "修改 GitOps 控制的 Git 仓库 → ArgoCD/Flux 自动 sync → 全集群更新。"
            "ArgoCD 每 3 分钟、Flux 每 60 秒自动检测变更。"
        ),
        prerequisites=["可修改 GitOps 源仓库", "或可伪造 Git webhook"],
        steps=[
            "修改 Git 仓库中的 Application/YAML 定义",
            "静默注入恶意 Sidecar 容器",
            "ArgoCD 自动检测变更并 sync",
            "全集群 Pod 自动注入后门",
        ],
        detection_hints=[
            "Git 仓库非授权变更",
            "GitOps sync 事件中的异常资源定义",
        ],
        references=["ArgoCD Auto-Sync", "Flux Reconciliation"],
    ),
    AttackVector(
        id="SC-009",
        name="容器镜像缓存篡改",
        phase=AttackPhase.PERSISTENCE,
        risk=RiskLevel.CRITICAL,
        description=(
            "逃逸至宿主机后，直接修改 /var/lib/containerd 或 /var/lib/docker 下的镜像层。"
            "镜像拉取时已验证 Digest，但缓存层再次使用时不重新校验。"
            "同节点所有同镜像的新容器全部中毒。镜像扫描完全失效。"
        ),
        prerequisites=["宿主机 root 权限", "逃逸成功"],
        steps=[
            "逃逸至宿主机",
            "定位容器存储路径 /var/lib/containerd",
            "解压镜像层，注入恶意代码或后门",
            "重新打包镜像层",
            "新容器使用缓存时加载恶意版本",
        ],
        detection_hints=[
            "镜像层文件校验和不匹配",
            "运行时行为与镜像扫描结果不一致",
        ],
        references=["Containerd Storage", "OCI Layer Spec"],
    ),
]


def get_supply_chain_by_type(sc_type: str) -> list[AttackVector]:
    """按供应链攻击类型筛选"""
    type_map = {
        "helm": ["Helm", "Chart", "模板"],
        "image": ["镜像", "image", "tag", "BuildKit", "缓存"],
        "operator": ["Operator", "CRD"],
        "gitops": ["GitOps", "ArgoCD", "Flux"],
        "dependency": ["依赖", "PyPI", "递归"],
    }
    if sc_type in type_map:
        keywords = type_map[sc_type]
        return [
            v for v in SUPPLY_CHAIN_VECTORS
            if any(kw in v.name or kw in v.description for kw in keywords)
        ]
    return SUPPLY_CHAIN_VECTORS
