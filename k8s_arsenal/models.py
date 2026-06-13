"""核心数据模型

定义攻击向量、信任关系、环境画像等数据结构。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AttackPhase(Enum):
    """攻击链阶段（对齐 MITRE ATT&CK 容器矩阵）"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CloudProvider(Enum):
    """云平台"""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    ALIBABA = "alibaba"
    UNKNOWN = "unknown"


@dataclass
class AttackVector:
    """攻击向量（原子级攻击技术）"""
    id: str
    name: str
    phase: AttackPhase
    risk: RiskLevel
    description: str
    prerequisites: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    detection_hints: list[str] = field(default_factory=list)
    mitre_id: Optional[str] = None
    references: list[str] = field(default_factory=list)
    cve: Optional[str] = None


@dataclass
class TrustEdge:
    """信任关系边（组件间的信任关系）"""
    source: str
    target: str
    relationship: str
    credential_type: Optional[str] = None
    auto_rotated: bool = False
    risk: RiskLevel = RiskLevel.MEDIUM


@dataclass
class AttackPath:
    """攻击路径（由多个攻击向量串联）"""
    id: str
    name: str
    description: str
    vectors: list[AttackVector] = field(default_factory=list)
    trust_chain: list[TrustEdge] = field(default_factory=list)
    difficulty: RiskLevel = RiskLevel.MEDIUM
    estimated_time: str = "unknown"


@dataclass
class AttackGraph:
    """攻击图（语义统一容器）

    统一承载信任关系边、攻击路径、环境节点等关键语义对象，
    提供遍历和查询的统一入口。
    """
    nodes: dict[str, str] = field(default_factory=dict)
    edges: list[TrustEdge] = field(default_factory=list)
    paths: list[AttackPath] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    critical_assets: list[str] = field(default_factory=list)


@dataclass
class SAResult:
    """ServiceAccount 权限分析结果"""
    name: str
    namespace: str
    roles: list[str] = field(default_factory=list)
    cluster_roles: list[str] = field(default_factory=list)
    powerful_permissions: list[str] = field(default_factory=list)
    is_high_risk: bool = False
    risk_detail: str = ""


@dataclass
class EscapeVector:
    """容器逃逸向量"""
    id: str
    name: str
    cve: Optional[str] = None
    required_capabilities: list[str] = field(default_factory=list)
    required_conditions: list[str] = field(default_factory=list)
    description: str = ""
    success_rate: str = "unknown"
    detection_difficulty: str = "medium"
    phase: AttackPhase = AttackPhase.EXECUTION
    risk: RiskLevel = RiskLevel.HIGH


@dataclass
class EnvironmentProfile:
    """环境画像（当前运行环境的攻击面特征）"""
    is_kubernetes: bool = False
    is_container: bool = False
    is_privileged: bool = False
    host_pid: bool = False
    host_network: bool = False
    host_ipc: bool = False
    mounted_docker_sock: bool = False
    capabilities: list[str] = field(default_factory=list)
    cloud_provider: Optional[CloudProvider] = None
    service_account: Optional[str] = None
    namespace: Optional[str] = None
    mounted_containerd_sock: bool = False
    mounted_crio_sock: bool = False
    sensitive_mounts: list[str] = field(default_factory=list)
    escape_vectors: list[EscapeVector] = field(default_factory=list)
    sa_analysis: Optional[SAResult] = None


@dataclass
class NodeInfo:
    """节点信息"""
    name: str
    role: str = "worker"
    internal_ip: str = ""
    pod_cidr: str = ""
    conditions: list[str] = field(default_factory=list)
