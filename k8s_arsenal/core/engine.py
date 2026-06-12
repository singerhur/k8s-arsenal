"""智能适应引擎

针对运行环境进行战场评估：指纹识别、检测机制分析、攻击面画像、策略调整。
基于评估结果动态推荐最优攻击路径和规避策略。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from k8s_arsenal.models import AttackVector, EnvironmentProfile, RiskLevel, CloudProvider


# 环境指纹特征库
_RANGE_SIGNATURES: dict[str, list[str]] = {
    "k8s_ctf": [
        "privileged pod with minimal restrictions",
        "mounted docker socket",
        "hostPID enabled",
        "service account with cluster-admin",
        "node with taint tolerations",
        "exposed kubelet API",
    ],
    "cloud_ctf": [
        "IMDSv1 accessible",
        "instance with iam:PassRole",
        "S3 bucket with public ACL",
        "unrestricted security group",
    ],
    "enterprise": [
        "OPA/Gatekeeper policies",
        "Falco runtime detection",
        "network policies enforced",
        "audit log enabled",
        "pod security standards",
        "image scanning in place",
    ],
}

# 检测机制强度估算规则
_DETECTION_RULES: dict[str, dict[str, Any]] = {
    "falco_installed": {"weight": 0.25, "description": "Falco 运行时异常检测"},
    "opa_enforcing": {"weight": 0.20, "description": "OPA/Gatekeeper 策略强制执行"},
    "audit_log": {"weight": 0.15, "description": "审计日志完整记录"},
    "psp_psa": {"weight": 0.15, "description": "Pod 安全标准"},
    "network_policy": {"weight": 0.10, "description": "网络策略"},
    "image_scanner": {"weight": 0.10, "description": "镜像扫描"},
    "seccomp_enforcing": {"weight": 0.05, "description": "Seccomp 强制策略"},
}


@dataclass
class BattlefieldAssessment:
    """战场评估报告"""

    environment_fingerprint: str = "unknown"
    is_range: bool = False
    detection_level: RiskLevel = RiskLevel.MEDIUM
    attack_surface_score: float = 0.0
    time_pressure: str = "normal"
    recommended_strategy: str = ""
    critical_weaknesses: list[str] = field(default_factory=list)
    evasion_requirements: list[str] = field(default_factory=list)
    risk_factors: list[str] = field(default_factory=list)
    phase_priorities: list[str] = field(default_factory=list)


class AdaptiveEngine:
    """智能适应引擎

    分析当前运行环境，生成战场评估报告，并据此调整攻击策略参数。
    """

    def __init__(self) -> None:
        self._last_assessment: Optional[BattlefieldAssessment] = None

    # ------------------------------------------------------------------
    # 公共 API
    # ------------------------------------------------------------------

    def assess_battlefield(self, profile: EnvironmentProfile) -> BattlefieldAssessment:
        """完整战场评估

        Args:
            profile: 环境画像（由 recon 模块提供）

        Returns:
            BattlefieldAssessment 报告
        """
        fingerprint = self._fingerprint(profile)
        detection = self._assess_detection(profile)
        surface_score = self._analyze_surface(profile)
        pressure = self._evaluate_pressure(profile)
        weaknesses = self._find_weaknesses(profile)

        is_range = self._is_range_environment(fingerprint, weaknesses)

        assessment = BattlefieldAssessment(
            environment_fingerprint=fingerprint,
            is_range=is_range,
            detection_level=detection,
            attack_surface_score=surface_score,
            time_pressure=pressure,
            recommended_strategy=self._recommend_strategy(
                profile, detection, surface_score, is_range, weaknesses
            ),
            critical_weaknesses=weaknesses,
            evasion_requirements=self._derive_evasion_needs(profile, detection),
            risk_factors=self._derive_risk_factors(profile),
            phase_priorities=self._derive_phase_priorities(profile, is_range),
        )

        self._last_assessment = assessment
        return assessment

    def adjust_strategy(self, assessment: Optional[BattlefieldAssessment] = None) -> dict[str, Any]:
        """根据战场评估生成攻击策略参数

        Returns:
            {
                "stealth_level": "low/medium/high",
                "max_chain_depth": int,
                "preferred_phases": [...],
                "avoid_techniques": [...],
                "parallel_targets": [...],
            }
        """
        a = assessment or self._last_assessment
        if a is None:
            return {
                "stealth_level": "medium",
                "max_chain_depth": 4,
                "preferred_phases": [],
                "avoid_techniques": [],
                "parallel_targets": [],
            }

        stealth = "low"
        if a.detection_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            stealth = "high"
        elif a.detection_level == RiskLevel.MEDIUM:
            stealth = "medium"

        max_depth = 3 if a.is_range else 6

        return {
            "stealth_level": stealth,
            "max_chain_depth": max_depth,
            "preferred_phases": a.phase_priorities,
            "avoid_techniques": self._derive_avoid_techniques(a),
            "evasion_requirements": a.evasion_requirements,
            "parallel_targets": a.critical_weaknesses[:3],
        }

    def get_weights_for_optimizer(self) -> dict[str, float]:
        """根据评估结果返回攻击向量优化器的权重配置"""
        a = self._last_assessment
        if a is None:
            return {"success": 0.35, "stealth": 0.30, "speed": 0.15, "impact": 0.20}

        if a.is_range:
            # 靶场环境：速度和成功率优先
            return {"success": 0.40, "stealth": 0.10, "speed": 0.30, "impact": 0.20}

        if a.detection_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            # 高检测环境：隐蔽性优先
            return {"success": 0.20, "stealth": 0.45, "speed": 0.10, "impact": 0.25}

        if a.detection_level == RiskLevel.LOW:
            # 低检测环境：影响力优先
            return {"success": 0.25, "stealth": 0.15, "speed": 0.25, "impact": 0.35}

        return {"success": 0.35, "stealth": 0.30, "speed": 0.15, "impact": 0.20}

    # ------------------------------------------------------------------
    # 内部分析方法
    # ------------------------------------------------------------------

    def _fingerprint(self, profile: EnvironmentProfile) -> str:
        """环境指纹识别"""
        parts: list[str] = []

        # 基础容器化
        if profile.is_container:
            parts.append("containerized")
        if profile.is_kubernetes:
            parts.append("k8s")

        # 特权
        if profile.is_privileged:
            parts.append("privileged")

        # 命名空间隔离
        if profile.host_pid:
            parts.append("hostPID")
        if profile.host_network:
            parts.append("hostNet")
        if profile.host_ipc:
            parts.append("hostIPC")

        # 运行时 socket
        if profile.mounted_docker_sock:
            parts.append("docker-sock")
        if profile.mounted_containerd_sock:
            parts.append("containerd-sock")
        if profile.mounted_crio_sock:
            parts.append("crio-sock")

        # 云平台
        if profile.cloud_provider and profile.cloud_provider != CloudProvider.UNKNOWN:
            parts.append(profile.cloud_provider.value)

        # capabilities
        dangerous_caps = [c for c in profile.capabilities if c in _DANGEROUS_CAPS]
        if dangerous_caps:
            parts.append(f"caps:{'+'.join(sorted(dangerous_caps))}")

        # SA 高权限
        if profile.sa_analysis and profile.sa_analysis.is_high_risk:
            parts.append("high-risk-sa")

        return "|".join(parts) if parts else "bare-metal"

    def _assess_detection(self, profile: EnvironmentProfile) -> RiskLevel:
        """评估检测机制强度"""
        score = 0.0

        # 特权容器通常意味着检测较弱
        if profile.is_privileged:
            score -= 0.15

        # hostPID 暗示低限制环境
        if profile.host_pid:
            score -= 0.10

        # capabilities 多 → 暗示松散的安全配置
        cap_count = len(profile.capabilities)
        if cap_count > 10:
            score -= 0.15
        elif cap_count > 5:
            score -= 0.05

        # 云平台的默认检测水平
        if profile.cloud_provider:
            if profile.cloud_provider == CloudProvider.AWS:
                score += 0.05  # GuardDuty + CloudTrail
            elif profile.cloud_provider == CloudProvider.GCP:
                score += 0.10  # SCC + Audit Logs
            elif profile.cloud_provider == CloudProvider.AZURE:
                score += 0.10  # Defender + Sentinel

        if score <= -0.20:
            return RiskLevel.LOW
        elif score <= 0.0:
            return RiskLevel.MEDIUM
        elif score <= 0.15:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def _analyze_surface(self, profile: EnvironmentProfile) -> float:
        """攻击面分析评分 (0-100)"""
        score = 0.0

        # 特权态大加分
        if profile.is_privileged:
            score += 25

        # 命名空间突破
        if profile.host_pid:
            score += 10
        if profile.host_network:
            score += 8
        if profile.host_ipc:
            score += 5

        # 运行时 socket
        if profile.mounted_docker_sock:
            score += 15
        if profile.mounted_containerd_sock:
            score += 12
        if profile.mounted_crio_sock:
            score += 10

        # 敏感挂载
        if profile.sensitive_mounts:
            score += min(len(profile.sensitive_mounts) * 3, 15)

        # 云元数据可访问
        if profile.cloud_provider and profile.cloud_provider != CloudProvider.UNKNOWN:
            score += 8

        # SA 高权限
        if profile.sa_analysis and profile.sa_analysis.is_high_risk:
            score += 15

        # capabilities
        cap_count = len(profile.capabilities)
        score += min(cap_count * 2, 10)

        return min(score, 100.0)

    def _evaluate_pressure(self, profile: EnvironmentProfile) -> str:
        """时间压力评估"""
        # 基于多种因素综合判断
        signals = 0

        if profile.is_privileged:
            signals += 1  # 高权限 → 可能是快速突破 → 时间充裕
        if profile.host_pid:
            signals += 1
        if profile.mounted_docker_sock:
            signals += 1
        if profile.sa_analysis and profile.sa_analysis.is_high_risk:
            signals += 1

        if signals >= 3:
            return "low"     # 条件良好，时间充裕
        elif signals >= 2:
            return "normal"
        else:
            return "elevated"  # 条件差，需要争分夺秒

    def _find_weaknesses(self, profile: EnvironmentProfile) -> list[str]:
        """识别关键弱点"""
        weaknesses: list[str] = []

        if profile.is_privileged:
            weaknesses.append("privileged container (direct host access)")
        if profile.mounted_docker_sock:
            weaknesses.append("mounted docker socket (container escape via docker CLI)")
        if profile.mounted_containerd_sock:
            weaknesses.append("mounted containerd socket (namespace escape)")
        if profile.mounted_crio_sock:
            weaknesses.append("mounted CRI-O socket (pod manipulation)")
        if profile.host_pid:
            weaknesses.append("hostPID enabled (process namespace escape)")
        if profile.host_network:
            weaknesses.append("hostNetwork enabled (network-level attacks)")
        if profile.sensitive_mounts:
            for m in profile.sensitive_mounts:
                weaknesses.append(f"sensitive mount: {m}")
        if profile.sa_analysis and profile.sa_analysis.is_high_risk:
            weaknesses.append(
                f"high-risk SA: {profile.sa_analysis.name}"
                f" ({', '.join(profile.sa_analysis.powerful_permissions)})"
            )

        cap_warnings = self._assess_capability_weaknesses(profile)
        weaknesses.extend(cap_warnings)

        if not weaknesses:
            weaknesses.append("no obvious weaknesses — requires advanced exploitation")

        return weaknesses

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _is_range_environment(self, fingerprint: str, weaknesses: list[str]) -> bool:
        """判断是否为靶场/CTF 环境"""
        range_indicators = 0

        # 指纹中的关键特征（_fingerprint() 输出为中文）
        if "特权" in fingerprint or "privileged" in fingerprint:
            range_indicators += 1
        if "docker.sock" in fingerprint or "docker-sock" in fingerprint:
            range_indicators += 2
        if "hostPID" in fingerprint:
            range_indicators += 1

        # 过于容易的攻击路径（靶场常见，_find_weaknesses() 输出为中文）
        if any("privileged" in w for w in weaknesses):
            range_indicators += 2
        if any("docker" in w for w in weaknesses):
            range_indicators += 2

        # 极低检测 + 极高攻击面 = 典型靶场模式
        return range_indicators >= 4

    def _recommend_strategy(
        self,
        profile: EnvironmentProfile,
        detection: RiskLevel,
        surface_score: float,
        is_range: bool,
        weaknesses: list[str],
    ) -> str:
        """推荐攻击策略"""
        if is_range:
            return (
                "靶场模式：快速突破优先。直接利用最明显的弱点，"
                "最小化时间投入，最大化得分效率。"
            )

        if surface_score >= 70:
            return (
                "高攻击面：优先利用特权/挂载弱点快速获取节点权限，"
                "然后横向移动建立持久化。"
            )

        if detection in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return (
                "高检测环境：采用低调策略。优先信息收集和权限枚举，"
                "使用低检测风险技术，避免 noisy 操作。"
            )

        return (
            "标准策略：从信息收集开始，逐步提升权限，"
            "在关键节点建立持久化，全程注意痕迹清理。"
        )

    def _derive_evasion_needs(
        self, profile: EnvironmentProfile, detection: RiskLevel
    ) -> list[str]:
        """推导规避需求"""
        needs: list[str] = []

        if detection == RiskLevel.CRITICAL:
            needs.append("日志混淆：修改审计日志时间戳或清空事件")
            needs.append("行为伪装：混入正常 kubelet/controller 流量")
            needs.append("时间分散：将操作分散在数小时内完成")
        elif detection == RiskLevel.HIGH:
            needs.append("操作伪装：使用常见 kubectl 命令模式")
            needs.append("流量混淆：通过 nodePort/LoadBalancer 代理")
        elif detection == RiskLevel.MEDIUM:
            needs.append("最小化 API 调用次数")
        # LOW: 不需要额外规避

        if profile.cloud_provider and profile.cloud_provider != CloudProvider.UNKNOWN:
            needs.append(f"云审计规避：注意 {profile.cloud_provider.value.upper()} CloudTrail/AuditLog")

        return needs

    def _derive_risk_factors(self, profile: EnvironmentProfile) -> list[str]:
        """推导环境风险因素"""
        factors: list[str] = []

        if profile.cloud_provider and profile.cloud_provider != CloudProvider.UNKNOWN:
            factors.append(f"云审计不可控 ({profile.cloud_provider.value})")

        if profile.host_network:
            factors.append("共享宿主机网络 — 流量可被网安设备捕获")

        if not profile.sensitive_mounts and not profile.is_privileged:
            factors.append("攻击面受限 — 逃逸路径有限")

        if profile.sa_analysis and profile.sa_analysis.is_high_risk:
            factors.append("SA 权限过高 — 横向移动风险大（可能触发告警）")

        return factors

    def _derive_phase_priorities(
        self, profile: EnvironmentProfile, is_range: bool
    ) -> list[str]:
        """推导攻击阶段优先级"""
        if is_range:
            return [
                "privilege_escalation",
                "lateral_movement",
                "persistence",
                "impact",
            ]

        phases = ["discovery"]

        if profile.is_privileged or profile.mounted_docker_sock:
            phases.append("execution")
            phases.append("privilege_escalation")

        if profile.sa_analysis and profile.sa_analysis.is_high_risk:
            phases.append("credential_access")
            phases.append("lateral_movement")

        phases.append("persistence")
        phases.append("defense_evasion")

        return phases

    def _derive_avoid_techniques(self, assessment: BattlefieldAssessment) -> list[str]:
        """推导应避免的技术"""
        avoid: list[str] = []

        if assessment.detection_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            avoid.append("noisy network scans")
            avoid.append("massive API enumeration")
            avoid.append("privileged pod creation in monitored namespaces")

        if not assessment.is_range:
            avoid.append("IMDSv1 token request (logged in cloud environments)")

        return avoid

    def _assess_capability_weaknesses(self, profile: EnvironmentProfile) -> list[str]:
        """评估 capabilities 相关的弱点"""
        weaknesses: list[str] = []
        caps = set(profile.capabilities)

        cap_warnings: dict[str, str] = {
            "CAP_SYS_ADMIN": "CAP_SYS_ADMIN: mount, namespace, and module operations",
            "CAP_SYS_PTRACE": "CAP_SYS_PTRACE: process memory injection and code execution",
            "CAP_SYS_MODULE": "CAP_SYS_MODULE: kernel module loading",
            "CAP_NET_ADMIN": "CAP_NET_ADMIN: network configuration and ARP spoofing",
            "CAP_NET_RAW": "CAP_NET_RAW: raw socket creation and packet crafting",
            "CAP_SYS_RAWIO": "CAP_SYS_RAWIO: direct hardware I/O access",
            "CAP_SYS_BOOT": "CAP_SYS_BOOT: system reboot capability",
            "CAP_DAC_OVERRIDE": "CAP_DAC_OVERRIDE: bypass file permission checks",
            "CAP_DAC_READ_SEARCH": "CAP_DAC_READ_SEARCH: bypass directory read/search restrictions",
            "CAP_SETUID": "CAP_SETUID: arbitrary UID manipulation",
            "CAP_SETGID": "CAP_SETGID: arbitrary GID manipulation",
            "CAP_SETPCAP": "CAP_SETPCAP: modify process capability sets",
            "CAP_SETFCAP": "CAP_SETFCAP: set file capabilities",
        }

        for cap, desc in cap_warnings.items():
            if cap in caps:
                weaknesses.append(desc)

        return weaknesses


# 危险 capabilities 列表
_DANGEROUS_CAPS: list[str] = [
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_SYS_MODULE",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_SYS_RAWIO",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_SETFCAP",
]


def run_battlefield_assessment(profile: EnvironmentProfile) -> dict[str, Any]:
    """快捷函数：运行完整战场评估并返回可打印结果"""
    engine = AdaptiveEngine()
    assessment = engine.assess_battlefield(profile)
    strategy = engine.adjust_strategy()

    return {
        "assessment": {
            "fingerprint": assessment.environment_fingerprint,
            "is_range": assessment.is_range,
            "detection_level": assessment.detection_level.value,
            "attack_surface_score": assessment.attack_surface_score,
            "time_pressure": assessment.time_pressure,
            "recommended_strategy": assessment.recommended_strategy,
            "critical_weaknesses": assessment.critical_weaknesses,
            "evasion_requirements": assessment.evasion_requirements,
            "risk_factors": assessment.risk_factors,
        },
        "strategy": strategy,
    }
