"""Tests for playbook/executor.py

Tests cover PlaybookExecution, PlaybookExecutor, step building, numbering,
script generation, and execution (dry-run).
"""

import json
import subprocess
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from k8s_arsenal.models import EnvironmentProfile, AttackPhase, RiskLevel
from k8s_arsenal.playbook.executor import (
    PlaybookExecution,
    PlaybookExecutor,
    ExecutableStep,
    detect_escape_vectors,
)
from k8s_arsenal.models import AttackVector


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def k8s_profile() -> EnvironmentProfile:
    """标准 K8s 容器环境画像"""
    return EnvironmentProfile(
        is_container=True,
        is_kubernetes=True,
        is_privileged=True,
        host_pid=True,
        host_network=True,
        service_account="default",
        capabilities=["NET_RAW", "SYS_ADMIN", "DAC_OVERRIDE"],
    )


@pytest.fixture
def non_k8s_profile() -> EnvironmentProfile:
    """非 K8s 环境画像（裸机）"""
    return EnvironmentProfile(
        is_container=False,
        is_kubernetes=False,
        is_privileged=False,
        host_pid=False,
        host_network=False,
        service_account=None,
        capabilities=[],
    )


@pytest.fixture
def low_priv_profile() -> EnvironmentProfile:
    """低权限 K8s 容器（非特权、无 hostPID、无 hostNetwork）"""
    return EnvironmentProfile(
        is_container=True,
        is_kubernetes=True,
        is_privileged=False,
        host_pid=False,
        host_network=False,
        service_account="default",
        capabilities=["NET_RAW"],
    )


@pytest.fixture
def executor(k8s_profile: EnvironmentProfile) -> PlaybookExecutor:
    """标准 K8s 环境执行器"""
    return PlaybookExecutor(profile=k8s_profile)


@pytest.fixture
def basic_step() -> ExecutableStep:
    return ExecutableStep(
        step_number=1,
        phase="discovery",
        name="环境侦察",
        description="基本信息收集",
        command="uname -a",
        expected_outcome="内核版本信息",
        risk_level="low",
        detection_risk="low",
    )


@pytest.fixture
def multi_line_step() -> ExecutableStep:
    """包含 heredoc 多行命令的步骤"""
    return ExecutableStep(
        step_number=2,
        phase="persistence",
        name="ConfigMap 注入",
        description="多行命令测试",
        command=(
            "cat << 'EOF' | kubectl apply -f - 2>/dev/null\n"
            "apiVersion: v1\n"
            "kind: ConfigMap\n"
            "metadata:\n"
            "  name: test-cm\n"
            "data:\n"
            "  key: value\n"
            "EOF"
        ),
        expected_outcome="ConfigMap 创建成功",
        risk_level="medium",
        detection_risk="medium",
    )


@pytest.fixture
def step_with_single_quotes() -> ExecutableStep:
    """命令中包含单引号的步骤"""
    return ExecutableStep(
        step_number=3,
        phase="execution",
        name="单引号测试",
        description="单引号在命令中",
        command="echo 'must have root' && ls -la /root",
        expected_outcome="root 目录权限",
        risk_level="medium",
        detection_risk="high",
    )


@pytest.fixture
def sample_steps(basic_step, multi_line_step) -> list[ExecutableStep]:
    return [basic_step, multi_line_step]


@pytest.fixture
def playbook(sample_steps) -> PlaybookExecution:
    return PlaybookExecution(
        name="Test Playbook",
        description="测试用剧本",
        estimated_time="约 30 秒",
        steps=sample_steps,
    )


# ── PlaybookExecution ─────────────────────────────────────────────────

class TestPlaybookExecution:
    def test_total_steps_computed(self, playbook: PlaybookExecution):
        """total_steps 自动计算步骤总数"""
        assert playbook.total_steps == 2

    def test_total_steps_empty(self):
        """空步骤列表返回 0"""
        plan = PlaybookExecution(name="empty", description="", steps=[])
        assert plan.total_steps == 0

    def test_generated_at_default(self, playbook: PlaybookExecution):
        """generated_at 有默认值"""
        assert playbook.generated_at is not None
        assert len(playbook.generated_at) > 0

    def test_to_json(self, playbook: PlaybookExecution):
        """序列化为 JSON"""
        data = playbook.to_json()
        assert data["name"] == "Test Playbook"
        assert data["total_steps"] == 2
        assert len(data["steps"]) == 2
        assert data["steps"][0]["step_number"] == 1

    def test_to_json_roundtrip(self, playbook: PlaybookExecution):
        """JSON 序列化/反序列化不抛异常"""
        data = playbook.to_json()
        json.dumps(data, ensure_ascii=False, indent=2)


# ── PlaybookExecutor ──────────────────────────────────────────────────

class TestPlaybookExecutor:
    def test_init_with_profile(self, executor: PlaybookExecutor, k8s_profile: EnvironmentProfile):
        """构造时传入 profile"""
        assert executor.profile == k8s_profile

    def test_get_env_label_privileged(self, executor: PlaybookExecutor):
        """特权容器的标签"""
        label = executor._get_env_label()
        assert "K8s" in label
        assert "特权" in label
        assert "hostPID" in label
        assert "hostNet" in label

    def test_get_env_label_low_priv(self, low_priv_profile):
        """低权限容器的标签"""
        exe = PlaybookExecutor(profile=low_priv_profile)
        label = exe._get_env_label()
        assert "K8s" in label
        assert "容器内" in label
        assert "特权" not in label
        assert "hostPID" not in label

    def test_get_env_label_unknown(self, non_k8s_profile):
        """非容器环境标签"""
        exe = PlaybookExecutor(profile=non_k8s_profile)
        label = exe._get_env_label()
        assert label == "未知环境"


# ── Step numbering fix ────────────────────────────────────────────────

class TestStepNumbering:
    """验证 P2 修复：step 编号在 generate() 中统一分配，不再重复计算"""

    def test_all_steps_have_sequential_numbers(self, executor: PlaybookExecutor):
        """所有步骤的编号从 1 开始连续递增"""
        plan = executor.generate()
        numbers = [s.step_number for s in plan.steps]
        expected = list(range(1, len(plan.steps) + 1))
        assert numbers == expected, (
            f"Steps should be numbered 1..{len(plan.steps)} but got {numbers}"
        )

    def test_no_duplicate_step_numbers(self, executor: PlaybookExecutor):
        """无重复编号"""
        plan = executor.generate()
        numbers = [s.step_number for s in plan.steps]
        assert len(numbers) == len(set(numbers)), (
            f"Duplicate step numbers found: {numbers}"
        )

    def test_generate_twice_consistent(self, executor: PlaybookExecutor):
        """两次 generate() 编号序列一致"""
        plan1 = executor.generate()
        names1 = [(s.step_number, s.name) for s in plan1.steps]
        plan2 = executor.generate()
        names2 = [(s.step_number, s.name) for s in plan2.steps]
        assert names1 == names2, "两次生成的编号序列不一致"

    @patch("k8s_arsenal.playbook.executor.detect_escape_vectors")
    def test_no_duplicate_detection(self, mock_detect, executor: PlaybookExecutor):
        """_build_* 方法不再重复调用 detect_escape_vectors"""
        mock_detect.return_value = []
        executor.generate()
        assert mock_detect.call_count == 1, (
            f"detect_escape_vectors 应当只调用 1 次，实际 {mock_detect.call_count} 次"
        )

    def test_non_k8s_only_recon_steps(self, non_k8s_profile):
        """非 K8s 环境只有侦察步骤，没有凭证/持久化步骤"""
        exe = PlaybookExecutor(profile=non_k8s_profile)
        plan = exe.generate()
        # 非 K8s 下只生成 recon(discovery) 类步骤
        phases = {s.phase for s in plan.steps}
        assert "credential_access" not in phases
        assert "persistence" not in phases

    def test_stealth_mode_numbers(self, executor: PlaybookExecutor):
        """隐蔽模式下编号也连续"""
        plan = executor.generate(stealth=True)
        numbers = [s.step_number for s in plan.steps]
        expected = list(range(1, len(plan.steps) + 1))
        assert numbers == expected, (
            f"Stealth steps should be 1..{len(plan.steps)} but got {numbers}"
        )

    def test_stealth_adds_cleanup_steps(self, executor: PlaybookExecutor):
        """隐蔽模式在关键步骤后插入清理步骤"""
        normal = executor.generate(stealth=False)
        stealth = executor.generate(stealth=True)
        assert len(stealth.steps) > len(normal.steps), (
            f"隐蔽模式应增加步骤 (normal={len(normal.steps)}, stealth={len(stealth.steps)})"
        )


# ── Step building ─────────────────────────────────────────────────────

class TestStepBuilding:
    def test_build_recon_steps(self, executor: PlaybookExecutor):
        """侦察阶段步骤非空"""
        steps = executor._build_recon_steps()
        assert len(steps) > 0
        # 实际代码中使用 discovery/execution/impact 等阶段名
        phases = {s.phase for s in steps}
        assert len(phases) > 0

    def test_build_escape_returns_list(self, executor: PlaybookExecutor):
        """逃逸步骤总是返回 list"""
        vectors = detect_escape_vectors(executor.profile)
        steps = executor._build_escape_steps(vectors)
        assert isinstance(steps, list)

    def test_build_credential_non_k8s(self, non_k8s_profile):
        """非 K8s 环境凭证步骤为空"""
        exe = PlaybookExecutor(profile=non_k8s_profile)
        steps = exe._build_credential_steps()
        assert len(steps) == 0

    def test_build_persistence_non_k8s(self, non_k8s_profile):
        """非 K8s 环境持久化步骤为空"""
        exe = PlaybookExecutor(profile=non_k8s_profile)
        steps = exe._build_persistence_steps()
        assert len(steps) == 0

    def test_all_phases_covered(self, executor: PlaybookExecutor):
        """generate 覆盖所有关键阶段"""
        plan = executor.generate()
        phases = {s.phase for s in plan.steps}
        assert "discovery" in phases or "recon" in phases
        assert "credential_access" in phases

    def test_each_step_has_command(self, executor: PlaybookExecutor):
        """每个步骤都有非空命令"""
        plan = executor.generate()
        for s in plan.steps:
            assert s.command, f"Step {s.step_number} ({s.name}) 缺少 command"


# ── Shell script generation ──────────────────────────────────────────

class TestShellScript:
    def test_to_shell_script_basic(self, playbook: PlaybookExecution):
        """生成基本 shell 脚本"""
        script = playbook.to_shell_script()
        assert script.startswith("#!/bin/bash")
        assert "set -euo pipefail" in script
        assert "Test Playbook" in script

    def test_echo_preview_single_quotes(self, step_with_single_quotes):
        """包含单引号的命令不破坏 shell 语法"""
        plan = PlaybookExecution(name="test", description="", steps=[step_with_single_quotes])
        script = plan.to_shell_script()
        assert "Command:" in script
        assert "must have root" in script

    def test_heredoc_preserved(self, multi_line_step):
        """heredoc 多行命令被完整保留"""
        plan = PlaybookExecution(name="test", description="", steps=[multi_line_step])
        script = plan.to_shell_script()
        assert "apiVersion: v1" in script
        assert "EOF" in script

    def test_cleanup_included(self, basic_step):
        """包含 cleanup_command 的步骤在脚本中生成清理命令"""
        step = ExecutableStep(
            step_number=1,
            phase="execution",
            name="test",
            description="test",
            command="echo hello",
            expected_outcome="hello",
            risk_level="low",
            detection_risk="low",
            cleanup_command="rm -f /tmp/test",
        )
        plan = PlaybookExecution(name="test", description="", steps=[step])
        script = plan.to_shell_script()
        assert "rm -f /tmp/test" in script

    def test_script_has_begin_end_markers(self, executor: PlaybookExecutor):
        """生成的 shell 脚本包含起始和结束标记"""
        plan = executor.generate()
        script = plan.to_shell_script()
        assert script.startswith("#!/bin/bash")
        assert "=== 剧本执行完毕 ===" in script


# ── Execute (dry-run) ─────────────────────────────────────────────────

class TestExecute:
    def test_dry_run_returns_results(self, executor: PlaybookExecutor):
        """dry_run 返回正确的结果结构"""
        plan = executor.generate()
        results = executor.execute(plan, dry_run=True)
        assert len(results) == len(plan.steps)
        for r in results:
            assert "step" in r
            assert "success" in r
            assert r["success"] is True  # dry_run 总是 success

    def test_dry_run_no_actual_call(self, executor: PlaybookExecutor):
        """dry_run 不执行任何命令"""
        plan = executor.generate()
        with patch.object(subprocess, "check_output") as mock:
            executor.execute(plan, dry_run=True)
            mock.assert_not_called()

    def test_execute_non_k8s_no_error(self, non_k8s_profile):
        """非 K8s 环境执行不报错"""
        exe = PlaybookExecutor(profile=non_k8s_profile)
        plan = exe.generate()
        results = exe.execute(plan, dry_run=True)
        # 非 K8s 环境仍有 recon(discovery) 步骤
        assert len(results) > 0
        assert all(r["success"] for r in results)
