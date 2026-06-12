"""发现技术编目

收录 K8s 集群侦察与资产发现技术，涵盖 API Server 信息收集、RBAC 枚举、网络扫描。
"""

from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel


DISCOVERY_VECTORS: list[AttackVector] = [
    AttackVector(
        id="DIS-001",
        name="API Server 版本与能力探测",
        phase=AttackPhase.DISCOVERY,
        risk=RiskLevel.LOW,
        description=(
            "探测 API Server 版本和启用的 API 组。"
            "版本信息可判断集群是否包含已知漏洞的 patch 版本。"
            "API 组列表揭示集群安装的 CRD 和扩展组件（如 Istio、Cert-Manager）。"
        ),
        prerequisites=["API Server 可访问"],
        steps=[
            "kubectl version --short",
            "kubectl api-versions",
            "kubectl api-resources --verbs=list --namespaced -o name",
            "分析已安装的 API 组和 CRD",
        ],
        detection_hints=[
            "非系统组件查询 api-versions",
            "api-resources 枚举后紧接资源访问",
        ],
        references=["K8s API Discovery"],
    ),
    AttackVector(
        id="DIS-002",
        name="RBAC 权限全量枚举",
        phase=AttackPhase.DISCOVERY,
        risk=RiskLevel.LOW,
        description=(
            "使用 kubectl auth can-i --list 或 SelfSubjectAccessReview API "
            "枚举当前 SA 的所有有效权限。了解可操作哪些资源后，"
            "有针对性地寻找高价值目标（Secret、Deployment、Pod）。"
        ),
        prerequisites=["API Server 访问权限"],
        steps=[
            "kubectl auth can-i --list",
            "逐资源/逐权限发起 SelfSubjectAccessReview",
            "汇总 List/Create/Update/Delete 权限矩阵",
            "识别高价值权限组合（如 create pods + list secrets）",
        ],
        detection_hints=[
            "异常大量的 SelfSubjectAccessReview 请求",
            "auth can-i --list 调用模式",
        ],
        references=["K8s Authorization API"],
    ),
    AttackVector(
        id="DIS-003",
        name="集群网络拓扑探测",
        phase=AttackPhase.DISCOVERY,
        risk=RiskLevel.MEDIUM,
        description=(
            "扫描集群内 Service CIDR 和 Pod CIDR 发现内部服务。"
            "通过 DNS 查询和端口扫描构建集群服务拓扑。"
            "识别暴露的数据库、内部 API、未受保护的服务端点。"
        ),
        prerequisites=["集群内网络访问", "DNS 解析能力"],
        steps=[
            "获取 Service CIDR: kubectl cluster-info dump | grep service-cluster-ip-range",
            "DNS 枚举: nslookup, dig 扫描特定域名",
            "端口扫描内部 Service（如数据库 3306/5432/6379）",
            "构建服务依赖拓扑图",
        ],
        detection_hints=[
            "异常的内部端口扫描流量",
            "大量 DNS 查询请求",
            "非系统 Pod 的网络扫描特征",
        ],
    ),
    AttackVector(
        id="DIS-004",
        name="容器镜像与注册表探测",
        phase=AttackPhase.DISCOVERY,
        risk=RiskLevel.MEDIUM,
        description=(
            "获取集群中运行的容器镜像列表，分析镜像来源、基础镜像和潜在漏洞。"
            "从镜像名称推断私有镜像仓库地址，可用于后续供应链攻击。"
            "分析镜像层信息寻找嵌入的凭证或密钥。"
        ),
        prerequisites=["list pods 权限"],
        steps=[
            "kubectl get pods --all-namespaces -o json",
            "统计镜像来源分布（Docker Hub, ECR, GCR, 私有仓库）",
            "分析镜像标签寻找未打补丁的版本",
            "识别私有仓库地址用于后续供应链攻击",
        ],
        detection_hints=[
            "大量 pod describe 操作",
            "对私有镜像仓库的异常访问",
        ],
    ),
    AttackVector(
        id="DIS-005",
        name="云环境元数据信息收集",
        phase=AttackPhase.DISCOVERY,
        risk=RiskLevel.LOW,
        description=(
            "利用云平台元数据端点收集环境信息：VPC ID、子网、安全组、"
            "实例类型、IAM 角色。此信息帮助判断横向移动目标和云平台利用路径。"
        ),
        prerequisites=["容器可访问 169.254.169.254"],
        steps=[
            "AWS: curl http://169.254.169.254/latest/meta-data/",
            "GCP: curl http://metadata.google.internal/ -H 'Metadata-Flavor: Google'",
            "Azure: curl http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "识别 VPC、子网、IAM 角色、邻近实例",
        ],
        detection_hints=[
            "Pod 网络流量指向云元数据端点",
            "非系统组件查询元数据",
        ],
        references=["AWS EC2 Metadata", "GCP Metadata", "Azure IMDS"],
    ),
    AttackVector(
        id="DIS-006",
        name="控制平面组件识别",
        phase=AttackPhase.DISCOVERY,
        risk=RiskLevel.MEDIUM,
        description=(
            "通过标签和注解识别控制平面节点位置、组件版本和配置。"
            "定位 API Server、etcd、scheduler、controller-manager 节点。"
            "明确攻击目标后，可精确针对特定组件发起攻击。"
        ),
        prerequisites=["list nodes 权限"],
        steps=[
            "kubectl get nodes --show-labels | grep control-plane",
            "kubectl get pods -n kube-system -o wide",
            "检查控制平面组件配置",
            "识别 etcd 端点地址和证书路径",
        ],
        detection_hints=[
            "describe 控制平面 Pod",
            "对 kube-system 命名空间的异常关注",
        ],
    ),
]


def get_discovery_by_target(target: str) -> list[AttackVector]:
    """按目标筛选"""
    target_map = {
        "api": ["API", "api-versions"],
        "rbac": ["RBAC", "SelfSubjectAccessReview"],
        "network": ["网络", "扫描", "DNS"],
        "image": ["镜像", "image", "registry"],
        "cloud": ["Metadata", "元数据", "IMDS"],
        "control": ["控制平面", "control-plane"],
    }
    if target in target_map:
        keywords = target_map[target]
        return [
            v for v in DISCOVERY_VECTORS
            if any(kw.lower() in v.description.lower() for kw in keywords)
        ]
    return DISCOVERY_VECTORS
