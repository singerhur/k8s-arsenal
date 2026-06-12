"""引擎模块测试"""
import pytest
from k8s_arsenal.models import EnvironmentProfile, RiskLevel, CloudProvider, SAResult
from k8s_arsenal.core.engine import (
    AdaptiveEngine, BattlefieldAssessment, run_battlefield_assessment,
)


class TestAdaptiveEngine:
    """AdaptiveEngine 核心测试"""

    def test_init(self):
        engine = AdaptiveEngine()
        assert engine._last_assessment is None

    def test_assess_privileged_ctf(self):
        """特权容器 → 靶场环境"""
        p = EnvironmentProfile(
            is_kubernetes=True, is_container=True,
            is_privileged=True, host_pid=True,
            mounted_docker_sock=True,
            capabilities=["CAP_SYS_ADMIN"],
            cloud_provider=CloudProvider.UNKNOWN,
        )
        engine = AdaptiveEngine()
        a = engine.assess_battlefield(p)

        assert isinstance(a, BattlefieldAssessment)
        assert a.is_range is True
        assert a.attack_surface_score > 50
        assert a.detection_level == RiskLevel.LOW
        assert len(a.critical_weaknesses) > 0

    def test_assess_restricted(self):
        """受限容器 → 高检测环境"""
        p = EnvironmentProfile(
            is_kubernetes=True, is_container=True,
            is_privileged=False,
            cloud_provider=CloudProvider.GCP,
        )
        engine = AdaptiveEngine()
        a = engine.assess_battlefield(p)

        assert a.is_range is False
        assert a.attack_surface_score < 30
        assert a.detection_level in (RiskLevel.HIGH, RiskLevel.MEDIUM)

    def test_adjust_strategy_no_assessment(self):
        """无评估时返回默认策略"""
        engine = AdaptiveEngine()
        s = engine.adjust_strategy()
        assert s["stealth_level"] == "medium"
        assert s["max_chain_depth"] == 4

    def test_adjust_strategy_range(self):
        """靶场环境策略"""
        p = EnvironmentProfile(
            is_kubernetes=True, is_container=True,
            is_privileged=True, mounted_docker_sock=True,
        )
        engine = AdaptiveEngine()
        engine.assess_battlefield(p)
        s = engine.adjust_strategy()

        assert s["stealth_level"] in ("low", "medium")
        assert s["max_chain_depth"] <= 6

    def test_weights_for_range(self):
        """靶场环境 → 速度和成功优先"""
        p = EnvironmentProfile(is_kubernetes=True, is_privileged=True,
                                mounted_docker_sock=True, host_pid=True)
        engine = AdaptiveEngine()
        engine.assess_battlefield(p)
        w = engine.get_weights_for_optimizer()

        assert w["success"] > w["stealth"]
        assert w["speed"] > 0.15

    def test_weights_for_high_detection(self):
        """高检测环境 → 隐蔽优先"""
        p = EnvironmentProfile(is_kubernetes=True,
                                cloud_provider=CloudProvider.GCP)
        engine = AdaptiveEngine()
        engine.assess_battlefield(p)
        w = engine.get_weights_for_optimizer()

        assert w["stealth"] > w["success"]

    def test_fingerprint_privileged(self):
        """特权指纹"""
        p = EnvironmentProfile(is_kubernetes=True, is_container=True,
                                is_privileged=True, host_pid=True,
                                mounted_docker_sock=True,
                                capabilities=["CAP_SYS_ADMIN"],
                                cloud_provider=CloudProvider.AWS)
        engine = AdaptiveEngine()
        fp = engine._fingerprint(p)

        assert "privileged" in fp
        assert "hostPID" in fp
        assert "docker-sock" in fp
        assert "aws" in fp

    def test_fingerprint_bare_metal(self):
        """裸机指纹"""
        p = EnvironmentProfile()
        engine = AdaptiveEngine()
        fp = engine._fingerprint(p)
        assert fp == "bare-metal"

    def test_detection_privileged(self):
        """特权环境 → 低检测"""
        p = EnvironmentProfile(is_privileged=True, host_pid=True)
        engine = AdaptiveEngine()
        level = engine._assess_detection(p)
        assert level == RiskLevel.LOW

    def test_surface_score_privileged(self):
        """特权环境 → 高攻击面"""
        p = EnvironmentProfile(is_privileged=True, host_pid=True,
                                host_network=True, host_ipc=True,
                                mounted_docker_sock=True,
                                capabilities=["CAP_SYS_ADMIN", "CAP_NET_ADMIN",
                                               "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE"])
        engine = AdaptiveEngine()
        score = engine._analyze_surface(p)
        assert score > 70

    def test_surface_score_container(self):
        """普通容器 → 低攻击面"""
        p = EnvironmentProfile(is_container=True, is_kubernetes=True)
        engine = AdaptiveEngine()
        score = engine._analyze_surface(p)
        assert score < 50

    def test_weaknesses_privileged(self):
        """特权容器弱点识别"""
        p = EnvironmentProfile(is_privileged=True, mounted_docker_sock=True,
                                host_pid=True,
                                capabilities=["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"])
        engine = AdaptiveEngine()
        weaknesses = engine._find_weaknesses(p)

        assert any("privileged" in w.lower() for w in weaknesses)
        assert any("docker" in w.lower() for w in weaknesses)
        assert any("hostpid" in w.lower() for w in weaknesses)
        assert any("SYS_ADMIN" in w for w in weaknesses)

    def test_weaknesses_bare(self):
        """裸机 → 无显著弱点"""
        p = EnvironmentProfile()
        engine = AdaptiveEngine()
        weaknesses = engine._find_weaknesses(p)
        assert len(weaknesses) == 1
        assert "no obvious weaknesses" in weaknesses[0].lower()

    def test_run_battlefield_assessment(self):
        """快捷函数返回正确结构"""
        p = EnvironmentProfile(is_kubernetes=True, is_privileged=True)
        result = run_battlefield_assessment(p)

        assert "assessment" in result
        assert "strategy" in result
        assert "fingerprint" in result["assessment"]
        assert "stealth_level" in result["strategy"]

    def test_phase_priorities_range(self):
        """靶场阶段优先级"""
        p = EnvironmentProfile(is_privileged=True, mounted_docker_sock=True)
        engine = AdaptiveEngine()
        engine.assess_battlefield(p)
        priorities = engine._derive_phase_priorities(p, True)

        assert "privilege_escalation" in priorities
        assert "lateral_movement" in priorities

    def test_avoid_techniques_high_detect(self):
        """高检测环境 → 应避免 noisy 技术"""
        p = EnvironmentProfile(cloud_provider=CloudProvider.GCP)
        engine = AdaptiveEngine()
        a = engine.assess_battlefield(p)
        avoid = engine._derive_avoid_techniques(a)

        assert len(avoid) > 0
        assert any("noisy" in x.lower() or "massive" in x.lower() for x in avoid)

    def test_risk_factors_cloud(self):
        """云环境风险因素"""
        p = EnvironmentProfile(is_kubernetes=True, cloud_provider=CloudProvider.AWS)
        engine = AdaptiveEngine()
        a = engine.assess_battlefield(p)
        assert a.risk_factors
