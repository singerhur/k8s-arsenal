"""CLI 入口

K8s Arsenal 命令行工具，提供侦察、逃逸检测、攻击剧本生成等功能。
v0.4.0 — 战场评估 + 攻击向量优化 + PlaybookExecutor。
"""

import json
import sys
from pathlib import Path
from typing import Optional

from k8s_arsenal import __version__

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

from k8s_arsenal.models import AttackPhase, RiskLevel

console = Console()


def _collect_all_vectors():
    """汇集所有模块的攻击向量"""
    from k8s_arsenal.persistence.catalog import PERSISTENCE_VECTORS
    from k8s_arsenal.lateral.movement import LATERAL_VECTORS
    from k8s_arsenal.network.attacks import NETWORK_VECTORS
    from k8s_arsenal.supply_chain.catalog import SUPPLY_CHAIN_VECTORS
    from k8s_arsenal.evasion.catalog import EVASION_VECTORS
    from k8s_arsenal.escape.vectors import ESCAPE_VECTORS
    from k8s_arsenal.advanced.vectors import ADVANCED_VECTORS

    return (
        list(PERSISTENCE_VECTORS)
        + list(LATERAL_VECTORS)
        + list(NETWORK_VECTORS)
        + list(SUPPLY_CHAIN_VECTORS)
        + list(EVASION_VECTORS)
        + list(ESCAPE_VECTORS)
        + list(ADVANCED_VECTORS)
    )


def _collect_all_attack_vectors():
    """汇集所有 AttackVector（不含 EscapeVector）"""
    from k8s_arsenal.persistence.catalog import PERSISTENCE_VECTORS
    from k8s_arsenal.lateral.movement import LATERAL_VECTORS
    from k8s_arsenal.network.attacks import NETWORK_VECTORS
    from k8s_arsenal.supply_chain.catalog import SUPPLY_CHAIN_VECTORS
    from k8s_arsenal.evasion.catalog import EVASION_VECTORS
    from k8s_arsenal.advanced.vectors import ADVANCED_VECTORS

    return (
        list(PERSISTENCE_VECTORS)
        + list(LATERAL_VECTORS)
        + list(NETWORK_VECTORS)
        + list(SUPPLY_CHAIN_VECTORS)
        + list(EVASION_VECTORS)
        + list(ADVANCED_VECTORS)
    )


def _print_analyze_json(result, output: Optional[str] = None) -> None:
    """Serialize AnalysisResult to JSON and print or save."""
    from k8s_arsenal.runtime.engine import AnalysisResult

    cf_data = []
    for cf in result.counterfactuals:
        cf_data.append({
            "edge": list(cf.edge),
            "baseline_state": cf.baseline_state.value,
            "counterfactual_state": cf.counterfactual_state.value,
            "became_safe": cf.became_safe,
            "became_compromised": cf.became_compromised,
            "explanation": cf.explanation,
        })

    data = {
        "entry_identity": result.entry_identity,
        "critical_assets": result.critical_assets,
        "threshold": result.threshold,
        "terminal_state": result.terminal_state.value,
        "final_identity": result.final_identity,
        "identity_chain": result.identity_chain,
        "capabilities": sorted(result.capabilities) if result.capabilities else [],
        "path_count": result.path_count,
        "trace": result.trace,
        "counterfactuals": cf_data,
        "critical_edges": [list(e) for e in result.critical_edges],
        "mcs": {
            "cut_edges": [list(e) for e in result.mcs_cut_edges],
            "strategy": result.mcs_strategy,
            "verified": result.mcs_verified,
            "verification_note": result.mcs_verification_note,
        },
        "classifier": {
            "labels": result.labels,
            "primary_tactic": result.primary_tactic,
        },
        "terminal_explanation": result.terminal_explanation,
        "graph_summary": {
            "nodes": len(result.graph.nodes),
            "edges": len(result.graph.edges),
        },
    }

    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"\n[green]报告已保存至: {output}[/green]")
    else:
        console.print_json(data=data)


@click.group()
@click.version_option(version=__version__, prog_name="k8s-arsenal")
def main():
    """K8s Arsenal - 云原生攻击面分析工具"""
    pass


# ════════════════════════════════════════════════════════════════════
# 🆕 assess — 战场评估
# ════════════════════════════════════════════════════════════════════

@main.command(epilog="""
\b示例:
  k8s-arsenal assess                  # 文本格式输出
  k8s-arsenal assess --json           # JSON 格式输出
  k8s-arsenal assess --kubeconfig ~/.kube/config  # 指定 kubeconfig
""")
@click.option("--json", "as_json", is_flag=True, help="JSON 格式输出")
@click.option("--kubeconfig", type=click.Path(exists=True), help="kubeconfig 文件路径")
def assess(as_json: bool, kubeconfig: Optional[str]):
    """战场评估：环境指纹识别与攻击策略建议

    综合分析当前运行环境，生成攻击面评分、检测强度评估、
    关键弱点列表和推荐攻击策略。自动识别靶场/CTF 与企业环境。

    输出包括：
    - 环境指纹（容器化/特权/云平台等信息组合签名）
    - 攻击面评分（0-100 可视化进度条）
    - 检测强度（LOW/MEDIUM/HIGH/CRITICAL）
    - 关键弱点列表
    - 推荐策略参数（隐蔽级别/最大链深/优先阶段）
    """
    from k8s_arsenal.core.engine import AdaptiveEngine
    from k8s_arsenal.recon.k8s_enum import enumerate_environment

    console.print(Panel.fit("[bold magenta]K8s Arsenal — 战场评估[/bold magenta]"))

    with console.status("[magenta]探测环境并评估中...[/magenta]"):
        profile = enumerate_environment(kubeconfig)
        engine = AdaptiveEngine()
        assessment = engine.assess_battlefield(profile)
        strategy = engine.adjust_strategy()

    if as_json:
        result = {
            "assessment": {
                "fingerprint": assessment.environment_fingerprint,
                "is_range": assessment.is_range,
                "detection_level": assessment.detection_level.value,
                "attack_surface_score": assessment.attack_surface_score,
                "time_pressure": assessment.time_pressure,
                "critical_weaknesses": assessment.critical_weaknesses,
                "evasion_requirements": assessment.evasion_requirements,
                "risk_factors": assessment.risk_factors,
            },
            "strategy": strategy,
        }
        console.print_json(data=result)
        return

    # 丰富输出
    console.print(f"\n[bold]环境指纹:[/bold] [cyan]{assessment.environment_fingerprint}[/cyan]")

    # 攻击面评分条
    score = assessment.attack_surface_score
    bar_color = "green" if score < 40 else "yellow" if score < 70 else "red"
    bar = "█" * int(score / 5) + "░" * (20 - int(score / 5))
    console.print(f"[bold]攻击面评分:[/bold] [{bar_color}]{bar}[/{bar_color}] {score:.0f}/100")

    # 检测强度
    det_color = {"low": "green", "medium": "yellow", "high": "red", "critical": "red"}.get(
        assessment.detection_level.value, "white"
    )
    console.print(f"[bold]检测强度:[/bold] [{det_color}]{assessment.detection_level.value.upper()}[/{det_color}]")

    # 环境类型
    console.print(f"[bold]环境类型:[/bold] {'靶场/CTF' if assessment.is_range else '企业/生产环境'}")
    console.print(f"[bold]时间压力:[/bold] {assessment.time_pressure}")

    # 关键弱点
    if assessment.critical_weaknesses:
        console.print(f"\n[bold red]🔴 关键弱点 ({len(assessment.critical_weaknesses)}):[/bold red]")
        for w in assessment.critical_weaknesses:
            console.print(f"  • {w}")

    # 推荐策略
    console.print(f"\n[bold cyan]💡 推荐策略:[/bold cyan]")
    console.print(f"  {assessment.recommended_strategy}")

    # 策略参数
    console.print(f"\n[bold]策略参数:[/bold]")
    console.print(f"  隐蔽级别: [yellow]{strategy['stealth_level']}[/yellow]")
    console.print(f"  最大链深: {strategy['max_chain_depth']}")
    console.print(f"  优先阶段: {', '.join(strategy.get('preferred_phases', []))}")
    if strategy.get("evasion_requirements"):
        console.print(f"\n[bold yellow]⚡ 规避要求:[/bold yellow]")
        for e in strategy["evasion_requirements"]:
            console.print(f"  • {e}")


# ════════════════════════════════════════════════════════════════════
# 🆕 optimize — 攻击向量优化
# ════════════════════════════════════════════════════════════════════

@main.command()
@click.option("--compare", is_flag=True, help="显示向量评分对比表")
@click.option("--stealth", is_flag=True, help="隐蔽优先模式")
@click.option("--max-depth", default=6, type=int, help="最大攻击链深度 (默认: 6)")
@click.option("--phase", default="all", help="按阶段筛选 (如 discovery, persistence)")
@click.option("--top", default=10, type=int, help="显示 top N 结果 (默认: 10)")
def optimize(compare: bool, stealth: bool, max_depth: int, phase: str, top: int):
    """攻击向量评分排序与最优链生成"""
    from k8s_arsenal.core.optimizer import AttackVectorOptimizer
    from k8s_arsenal.playbook.chains import SmartAttackChain

    console.print(Panel.fit("[bold green]K8s Arsenal — 攻击向量优化器[/bold green]"))

    vectors = _collect_all_attack_vectors()

    if compare:
        # 评分对比表
        console.print(f"\n[bold]攻击向量评分对比[/bold] (前 {top} 名):\n")

        opt = AttackVectorOptimizer()
        if stealth:
            opt.weights = {"success": 0.20, "stealth": 0.45, "speed": 0.10, "impact": 0.25}
            console.print("[dim]权重模式: 隐蔽优先[/dim]")

        scored = opt.prioritize(vectors, top_n=top)

        table = Table(title="向量评分排序")
        table.add_column("#", style="dim")
        table.add_column("ID", style="cyan")
        table.add_column("名称", style="bold")
        table.add_column("阶段", style="magenta")
        table.add_column("综合", style="green")
        table.add_column("成功", style="yellow")
        table.add_column("隐蔽", style="blue")

        for i, sv in enumerate(scored, 1):
            table.add_row(
                str(i), sv.vector.id, sv.vector.name[:25],
                sv.vector.phase.value,
                f"{sv.composite_score:.3f}",
                f"{sv.success_score:.3f}",
                f"{sv.stealth_score:.3f}",
            )
        console.print(table)

    else:
        # 最优链生成
        console.print(f"\n[bold]生成最优攻击链[/bold] (最大深度: {max_depth}):\n")

        sc = SmartAttackChain()
        chain = sc.generate_optimal_chain(
            max_depth=max_depth,
            stealth_priority=stealth,
        )

        if not chain:
            console.print("[yellow]无可用向量生成攻击链[/yellow]")
            return

        # 链可视化
        tree = Tree("🌲 最优攻击链")
        for i, sv in enumerate(chain, 1):
            cve_tag = f" [red][CVE-{sv.vector.cve}][/red]" if sv.vector.cve else ""
            detail = (
                f"风险: {sv.vector.risk.value} | "
                f"评分: {sv.composite_score:.3f} | "
                f"步骤: {len(sv.vector.steps)}{cve_tag}"
            )
            node = tree.add(f"[bold]{i}. {sv.vector.id}[/bold] — {sv.vector.name}")
            tree.add(f"   └─ [dim]{detail}[/dim]")

        console.print(tree)

        # 评分汇总
        total_score = sum(sv.composite_score for sv in chain) / max(len(chain), 1)
        total_stealth = sum(
            sv.stealth_score for sv in chain
        ) / max(len(chain), 1)

        summary = Table(title="链评分汇总")
        summary.add_column("指标", style="cyan")
        summary.add_column("值", style="green")
        summary.add_row("向量数", str(len(chain)))
        summary.add_row("覆盖阶段", str(len({sv.vector.phase for sv in chain})))
        summary.add_row("平均综合评分", f"{total_score:.3f}")
        summary.add_row("平均隐蔽评分", f"{total_stealth:.3f}")
        summary.add_row("总步骤数", str(sum(len(sv.vector.steps) for sv in chain)))
        console.print(summary)

    # 阶段分布
    if phase != "all":
        try:
            p = AttackPhase(phase)
            console.print(f"\n[bold]按阶段筛选: {p.value}[/bold]")
            opt = AttackVectorOptimizer()
            top_phase = opt.get_top_by_phase(vectors, p, n=5)
            for i, sv in enumerate(top_phase, 1):
                console.print(f"  {i}. {sv.vector.id} — {sv.vector.name} (score={sv.composite_score:.3f})")
        except ValueError:
            console.print(f"[red]无效的阶段: {phase}[/red]")


# ════════════════════════════════════════════════════════════════════
# recon — 环境侦察
# ════════════════════════════════════════════════════════════════════

@main.command()
@click.option("--full", is_flag=True, help="执行完整侦察")
@click.option("--rbac", is_flag=True, help="重点分析 RBAC 权限")
@click.option("--output", "-o", type=click.Path(), help="输出 JSON 报告路径")
@click.option("--kubeconfig", type=click.Path(exists=True), help="kubeconfig 文件路径")
def recon(full: bool, rbac: bool, output: Optional[str], kubeconfig: Optional[str]):
    """K8s 环境侦察与攻击面枚举"""
    from k8s_arsenal.recon import k8s_enum, sa_analysis, trust_map

    console.print(Panel.fit("[bold cyan]K8s Arsenal - 环境侦察[/bold cyan]"))

    with console.status("[cyan]探测环境中...[/cyan]"):
        profile = k8s_enum.enumerate_environment(kubeconfig)

    console.print(f"[green]✓[/green] Kubernetes 环境: {profile.is_kubernetes}")
    console.print(f"[green]✓[/green] 容器环境: {profile.is_container}")
    console.print(f"[green]✓[/green] 当前命名空间: {profile.namespace or 'N/A'}")
    console.print(f"[green]✓[/green] ServiceAccount: {profile.service_account or 'N/A'}")

    if profile.is_privileged:
        console.print("[red]⚠[/red] 当前容器以 privileged 模式运行!")
    if profile.host_pid:
        console.print("[red]⚠[/red] hostPID 已启用 - 可访问宿主机进程!")
    if profile.host_network:
        console.print("[yellow]![/yellow] hostNetwork 已启用")
    if profile.mounted_docker_sock:
        console.print("[red]⚠[/red] Docker socket 已挂载!")

    # 能力分析
    if profile.capabilities:
        cap_table = Table(title="Linux Capabilities")
        cap_table.add_column("Capability", style="cyan")
        for cap in profile.capabilities:
            cap_table.add_row(cap)
        console.print(cap_table)

    # SA 权限分析
    if profile.is_kubernetes and (rbac or full):
        console.print("\n[bold]ServiceAccount 权限分析:[/bold]")
        sa_result = sa_analysis.analyze_current_sa(kubeconfig)
        if sa_result:
            profile.sa_analysis = sa_result
            if sa_result.is_high_risk:
                console.print(f"[red]⚠ 高风险 SA: {sa_result.risk_detail}[/red]")
            for perm in sa_result.powerful_permissions:
                console.print(f"  [yellow]• {perm}[/yellow]")

    # 信任拓扑
    if full:
        console.print("\n[bold]信任拓扑:[/bold]")
        edges = trust_map.build_trust_topology(profile, kubeconfig)
        if edges:
            tree = Tree("🏛️ 集群信任关系")
            for edge in edges:
                tree.add(f"[{edge.source}] → [{edge.target}] : {edge.relationship}")
            console.print(tree)

    # 逃逸向量
    from k8s_arsenal.escape.detector import detect_escape_vectors
    vectors = detect_escape_vectors(profile)
    if vectors:
        console.print(f"\n[bold red]🔥 发现 {len(vectors)} 个可能逃逸向量:[/bold red]")
        for v in vectors:
            console.print(f"  • {v.name}: {v.description[:80]}...")

    if output:
        report = {
            "profile": {
                "is_kubernetes": profile.is_kubernetes,
                "is_container": profile.is_container,
                "is_privileged": profile.is_privileged,
                "host_pid": profile.host_pid,
                "host_network": profile.host_network,
                "capabilities": profile.capabilities,
                "service_account": profile.service_account,
                "namespace": profile.namespace,
            },
            "escape_vectors": [
                {"id": v.id, "name": v.name, "description": v.description}
                for v in vectors
            ] if vectors else [],
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        console.print(f"\n[green]报告已保存至: {output}[/green]")


# ════════════════════════════════════════════════════════════════════
# trust-map — 信任拓扑映射
# ════════════════════════════════════════════════════════════════════

@main.command(epilog="""
\b示例:
  k8s-arsenal trust-map                # 显示集群信任拓扑
  k8s-arsenal trust-map --attackable   # 仅显示可被利用的信任边
  k8s-arsenal trust-map --output trust.json  # 导出 JSON
""")
@click.option("--attackable", is_flag=True, help="仅显示可被利用的信任边")
@click.option("--output", "-o", type=click.Path(), help="导出 JSON 报告路径")
def trust_map_cmd(attackable: bool, output: Optional[str]):
    """集群信任拓扑映射分析

    分析 K8s 集群各组件的信任关系，包括证书认证、Token 挂载、
    Socket 通信等，识别高价值攻击路径。
    """
    from k8s_arsenal.recon.k8s_enum import enumerate_environment
    from k8s_arsenal.recon.trust_map import (
        build_trust_topology,
        find_attackable_edges,
        render_trust_map_ascii,
    )

    console.print(Panel.fit("[bold cyan]K8s Arsenal — 信任拓扑映射[/bold cyan]"))

    with console.status("[cyan]分析信任关系中...[/cyan]"):
        profile = enumerate_environment()
        edges = build_trust_topology(profile)

    if attackable:
        edges = find_attackable_edges(edges)
        console.print(f"\n[bold]可被利用的信任边 ({len(edges)}):[/bold]")
    else:
        console.print(f"\n[bold]完整信任拓扑 ({len(edges)} 条边):[/bold]")

    # ASCII 拓扑图
    console.print(render_trust_map_ascii(edges))

    # 表格详情
    table = Table(title="信任边详情")
    table.add_column("源", style="cyan")
    table.add_column("目标", style="yellow")
    table.add_column("关系", style="green")
    table.add_column("凭证类型", style="dim")
    table.add_column("自动轮换", style="magenta")
    table.add_column("风险", style="red")

    for edge in edges:
        table.add_row(
            edge.source,
            edge.target,
            edge.relationship,
            edge.credential_type or "N/A",
            "Yes" if edge.auto_rotated else "No",
            edge.risk.value,
        )
    console.print(table)

    # 环境上下文
    if profile.is_kubernetes:
        console.print(f"\n[dim]环境: Kubernetes | 命名空间: {profile.namespace or 'N/A'} | SA: {profile.service_account or 'N/A'}[/dim]")

    if output:
        data = [
            {
                "source": e.source,
                "target": e.target,
                "relationship": e.relationship,
                "credential_type": e.credential_type,
                "auto_rotated": e.auto_rotated,
                "risk": e.risk.value,
            }
            for e in edges
        ]
        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"\n[green]信任拓扑已导出至: {output}[/green]")


# ════════════════════════════════════════════════════════════════════
# escape — 容器逃逸检测
# ════════════════════════════════════════════════════════════════════

@main.command()
@click.option("--check", is_flag=True, help="检测当前环境逃逸条件")
@click.option("--list", "list_all", is_flag=True, help="列出所有已编目的逃逸技术")
def escape(check: bool, list_all: bool):
    """容器逃逸条件检测与技术编目"""
    from k8s_arsenal.escape.vectors import ESCAPE_VECTORS
    from k8s_arsenal.recon.k8s_enum import enumerate_environment

    if check:
        console.print(Panel.fit("[bold red]容器逃逸条件检测[/bold red]"))
        profile = enumerate_environment()
        from k8s_arsenal.escape.detector import detect_escape_vectors
        vectors = detect_escape_vectors(profile)

        if vectors:
            console.print(f"\n[red]发现 {len(vectors)} 个可能逃逸路径:[/red]")
            for v in vectors:
                console.print(Panel(
                    f"[bold]{v.name}[/bold]\n"
                    f"{v.description}\n\n"
                    f"[dim]必要条件: {', '.join(v.required_conditions)}[/dim]",
                    title=f"[red]{v.id}[/red]"
                ))
        else:
            console.print("[green]当前环境未发现已知逃逸向量[/green]")

    if list_all:
        table = Table(title="容器逃逸技术编目")
        table.add_column("ID", style="cyan")
        table.add_column("名称", style="bold")
        table.add_column("必要条件", style="yellow")
        table.add_column("检测难度", style="green")

        for v in ESCAPE_VECTORS:
            table.add_row(
                v.id, v.name,
                ", ".join(v.required_conditions[:3]),
                v.detection_difficulty
            )
        console.print(table)


# ════════════════════════════════════════════════════════════════════
# catalog — 技术编目浏览
# ════════════════════════════════════════════════════════════════════

@main.command()
@click.option("--phase", default="all", help="攻击阶段筛选")
@click.option("--risk", default="all", help="风险等级筛选")
@click.option("--include-advanced/--no-advanced", default=True,
              help="是否包含高级 CVE 向量 (默认: 包含)")
@click.option("--output", "-o", type=click.Path(), help="导出 JSON")
def catalog(phase: str, risk: str, include_advanced: bool, output: Optional[str]):
    """浏览攻击技术编目（含高级 CVE 向量）"""
    all_vectors = _collect_all_vectors()

    if not include_advanced:
        from k8s_arsenal.advanced.vectors import ADVANCED_VECTORS
        adv_ids = {v.id for v in ADVANCED_VECTORS}
        all_vectors = [v for v in all_vectors if v.id not in adv_ids]

    if phase != "all":
        # 工具内阶段名 → MITRE ATT&CK 阶段名 映射
        _PHASE_ALIASES = {
            "escape": "privilege_escalation",
            "recon": "discovery",
            "侦查": "discovery",
            "逃逸": "privilege_escalation",
            "提权": "privilege_escalation",
            "凭证": "credential_access",
            "横向": "lateral_movement",
            "防御规避": "defense_evasion",
            "持久化": "persistence",
            "执行": "execution",
            "影响": "impact",
        }
        mapped = _PHASE_ALIASES.get(phase, phase)
        try:
            p = AttackPhase(mapped)
            all_vectors = [v for v in all_vectors if v.phase == p]
        except ValueError:
            console.print(f"[red]无效的攻击阶段: {phase}[/red]")
            console.print("[dim]可用阶段: all, " + ", ".join(m.value for m in AttackPhase) + "[/dim]")
            return

    if risk != "all":
        try:
            r = RiskLevel(risk)
            all_vectors = [v for v in all_vectors if v.risk == r]
        except ValueError:
            console.print(f"[red]无效的风险等级: {risk}[/red]")
            return

    table = Table(title=f"攻击技术编目 (共 {len(all_vectors)} 项)")
    table.add_column("ID", style="cyan")
    table.add_column("名称", style="bold")
    table.add_column("阶段", style="magenta")
    table.add_column("风险", style="red")
    table.add_column("简述")

    for v in all_vectors:
        table.add_row(v.id, v.name, v.phase.value, v.risk.value, v.description[:60])

    console.print(table)

    if output:
        data = [
            {
                "id": v.id, "name": v.name,
                "phase": v.phase.value, "risk": v.risk.value,
                "description": v.description,
                "prerequisites": v.prerequisites,
                "steps": v.steps,
                "detection_hints": v.detection_hints,
            }
            for v in all_vectors
        ]
        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"\n[green]编目已导出至: {output}[/green]")


# ════════════════════════════════════════════════════════════════════
# playbook — 攻击剧本生成
# ════════════════════════════════════════════════════════════════════

@main.command()
@click.option("--entry", default="low-privilege-sa", help="入口条件")
@click.option("--target", default="cluster-admin", help="目标权限")
@click.option("--smart/--classic", default=True, help="使用智能评分链(默认: 是)")
@click.option("--run", is_flag=True, help="⚠️ 自动执行攻击剧本（会修改集群！先用 --list-commands 预览）")
@click.option("--dry-run", is_flag=True, help="预览模式：模拟执行，不实际修改集群")
@click.option("--stealth", is_flag=True, help="隐蔽优先模式（关键步骤后插入清理）")
@click.option("--list-commands", is_flag=True, help="仅显示可执行命令，不生成分析")
@click.option("--output", "-o", type=click.Path(), help="保存到文件 (.txt / .sh / .json)")
def playbook(entry, target, smart, run, dry_run, stealth, list_commands, output):
    """生成攻击剧本（攻击链规划）

    v0.4: 新增 --run ⚠️ 自动执行（会修改集群！）、--list-commands 显示命令、--stealth 隐蔽模式
    """
    from k8s_arsenal.playbook.chains import AttackChainBuilder, SmartAttackChain
    from k8s_arsenal.playbook.templates import CHAIN_TEMPLATES
    from k8s_arsenal.playbook.executor import PlaybookExecutor
    from k8s_arsenal.recon.k8s_enum import enumerate_environment

    console.print(Panel.fit("[bold red]攻击剧本生成器[/bold red]"))
    console.print(f"入口条件: [cyan]{entry}[/cyan]")
    console.print(f"目标权限: [yellow]{target}[/yellow]")
    console.print(f"模式: [magenta]{'智能评分' if smart else '经典模板'}[/magenta]")

    # v0.4: 可执行剧本模式
    if list_commands or run or dry_run:
        console.print(f"  [yellow]可执行模式: {'自动执行' if run else '预览(模拟)' if dry_run else '仅显示命令'}[/yellow]")
        if dry_run:
            console.print("  [bold yellow]⚠️ 预览模式: 模拟执行，不实际修改集群[/bold yellow]")
        if stealth:
            console.print("  [cyan]隐蔽模式: 已开启[/cyan]")

        with console.status("[cyan]探测环境中...[/cyan]"):
            profile = enumerate_environment()

        executor = PlaybookExecutor(profile)
        plan = executor.generate(stealth=stealth)

        if output:
            from pathlib import Path
            ext = Path(output).suffix.lower()
            with open(output, "w", encoding="utf-8") as f:
                if ext == ".json":
                    import json
                    json.dump(plan.to_json(), f, indent=2, ensure_ascii=False)
                elif ext == ".sh":
                    f.write(plan.to_shell_script())
                else:
                    f.write(plan.to_text())
            console.print(f"[green]已保存至: {output}[/green]")

        if run or dry_run:
            if dry_run:
                console.print("[bold yellow]\n预览模式: 模拟执行（不会修改集群）...[/bold yellow]")
            else:
                console.print("[bold yellow]\n开始执行攻击剧本...[/bold yellow]")
                console.print("[dim]按 Ctrl+C 可中断执行[/dim]\n")
            results = executor.execute(plan, dry_run=dry_run)
            successes = sum(1 for r in results if r["success"])
            console.print(f"\n[bold]执行结果: {successes}/{len(results)} 步成功[/bold]")
            if dry_run:
                console.print("[cyan]提示: 使用 --run 实际执行（⚠️ 会修改集群）[/cyan]")
        else:
            console.print(plan.to_text())
        return

    # v0.3: 传统的评分链模式
    if smart:
        sc = SmartAttackChain()
        smart_chain = sc.generate_optimal_chain(max_depth=6)

        if smart_chain:
            console.print(f"\n[bold green]最优攻击链 ({len(smart_chain)} 步):[/bold green]\n")
            tree = Tree("攻击链")
            for i, sv in enumerate(smart_chain, 1):
                cve_tag = f" [red][CVE-{sv.vector.cve}][/red]" if sv.vector.cve else ""
                node = tree.add(
                    f"[bold]{i}. {sv.vector.id}[/bold] --- {sv.vector.name}"
                    f" [dim]({sv.vector.phase.value}) score={sv.composite_score:.3f}[/dim]{cve_tag}"
                )
                tree.add(f"    `-- [dim]{sv.vector.description[:80]}...[/dim]")
            console.print(tree)
        else:
            console.print("[yellow]无可用攻击链，回退至经典模式[/yellow]")
            smart = False

    if not smart:
        builder = AttackChainBuilder()
        chains = builder.build(entry_condition=entry, target=target)

        if not chains:
            console.print("[yellow]无直接攻击链，尝试组合路径..[/yellow]")
            chains = builder.build_composite(entry_condition=entry, target=target)

        for i, chain in enumerate(chains, 1):
            console.print(Panel(
                f"[bold]攻击链{i}: {chain.name}[/bold]\n"
                f"{chain.description}\n\n"
                f"难度: [{chain.difficulty.value}]\n"
                f"预计时间: {chain.estimated_time}\n\n"
                f"[dim]步骤: {' -> '.join(v.name for v in chain.vectors)}[/dim]",
                title=f"{chain.id}"
            ))

    console.print(f"\n[dim]共{len(CHAIN_TEMPLATES)} 个预置攻击链模板可用[/dim]")
    console.print("\n[cyan]提示:[/cyan] 使用 [bold]--list-commands[/bold] 查看可执行的攻击命令")
    console.print("  [dim]k8s-arsenal playbook --list-commands[/dim]")
    console.print("  [dim]k8s-arsenal playbook --list-commands --stealth[/dim]")
    console.print("  [dim]k8s-arsenal playbook --list-commands -o attack.sh[/dim]")


# ════════════════════════════════════════════════════════════════════
# analyze — 攻击图完整分析 (v0.5+ 六层管道)
# ════════════════════════════════════════════════════════════════════

@main.command(epilog="""
\b示例:
  k8s-arsenal analyze                              # 自动检测入口点和关键资产
  k8s-arsenal analyze --entry kube-apiserver --target etcd
  k8s-arsenal analyze --full-pipeline --json       # 六层完整分析 + JSON 输出
  k8s-arsenal analyze --threshold host              # 使用 host 攻击阈值
  k8s-arsenal analyze --quick                       # 快速模式 (仅 G+S+T)
  k8s-arsenal analyze -o report.json               # 保存报告
""")
@click.option("--entry", default="", help="入口节点 (默认: 自动检测)")
@click.option("--target", "targets", multiple=True, help="关键资产节点 (可多次指定)")
@click.option("--full-pipeline/--quick", default=True, help="完整六层分析(默认) vs 快速评估")
@click.option("--threshold", default="standard",
              type=click.Choice(["standard", "host", "rbac_escalation", "any_host", "any_impersonate"]),
              help="攻击阈值 (默认: standard)")
@click.option("--json", "as_json", is_flag=True, help="JSON 格式输出")
@click.option("--output", "-o", type=click.Path(), help="输出报告路径")
def analyze(entry: str, targets: tuple, full_pipeline: bool,
            threshold: str, as_json: bool, output: Optional[str]):
    """攻击图完整分析 — G → S → T → Δ → MCS → Label 六层管道

    基于信任拓扑构建攻击图，运行完整的六层分析管道：

    G   — 图可达性（BFS 路径搜索）
    S   — 状态演化（身份 + 能力累积）
    T   — 终端语义（SAFE / PARTIAL / COMPROMISED）
    Δ   — 单边反事实（因果依赖性分析）
    MCS — 最小割集（组合因果关系）
    Label — 攻击战术分类（5 种战术投影）

    这是 v0.5+ runtime 管道的 CLI 入口。
    """
    from k8s_arsenal.recon.k8s_enum import enumerate_environment
    from k8s_arsenal.recon.trust_map import build_trust_topology
    from k8s_arsenal.runtime.engine import AttackGraphEngine, AnalysisResult

    console.print(Panel.fit("[bold cyan]K8s Arsenal — 攻击图完整分析[/bold cyan]"))
    console.print(f"[dim]管道: G → S → T → Δ → MCS → Label[/dim]")

    with console.status("[cyan]分析信任拓扑并运行攻击图管道...[/cyan]"):
        # 1. 构建信任拓扑
        profile = enumerate_environment()
        trust_edges = build_trust_topology(profile)

        # 2. 创建引擎
        engine = AttackGraphEngine.from_trust_map(trust_edges)

        # 3. 运行完整管道
        result = engine.analyze(
            entry_identity=entry or engine.entry_identity,
            critical_assets=list(targets) if targets else None,
            compromise_threshold=threshold,
            run_counterfactuals=full_pipeline,
            run_mcs=full_pipeline,
            run_classifier=full_pipeline,
            verify_mcs=full_pipeline,
        )

    if as_json:
        _print_analyze_json(result, output)
        return

    # ---- Rich 格式输出 ------------------------------------------------

    # 攻击图概览
    console.print(f"\n[bold]攻击图概览:[/bold]")
    console.print(f"  节点: {len(result.graph.nodes)}")
    console.print(f"  边: {len(result.graph.edges)}")
    console.print(f"  入口点: {result.entry_identity}")
    console.print(f"  关键资产: {', '.join(result.critical_assets) if result.critical_assets else '(auto)'}")
    console.print(f"  阈值: {result.threshold}")

    # 终端状态 (T)
    state_color = {
        "safe": "green",
        "partial": "yellow",
        "compromised": "red",
    }.get(result.terminal_state.value, "white")
    console.print(f"\n[bold]终端状态 (T):[/bold] [{state_color}]{result.terminal_state.value.upper()}[/{state_color}]")

    # 身份链
    if result.identity_chain:
        chain_str = " → ".join(result.identity_chain)
        console.print(f"[bold]身份链:[/bold] [cyan]{chain_str}[/cyan]")

    # 能力集
    if result.capabilities:
        caps_str = ", ".join(sorted(result.capabilities))
        console.print(f"[bold]能力集:[/bold] [yellow]{caps_str}[/yellow]")
    else:
        console.print(f"[bold]能力集:[/bold] [dim](无危险能力)[/dim]")

    # 轨迹摘要
    if result.trace:
        console.print(f"\n[bold]攻击轨迹 ({len(result.trace)} 步):[/bold]")
        for i, step in enumerate(result.trace, 1):
            et = step.get("edge_type", "?")
            ident = step.get("identity", "?")
            node = step.get("node", "?")
            caps = ", ".join(step.get("capabilities", [])) or "-"
            console.print(f"  {i}. {node} | identity={ident} | edge={et} | caps=[{caps}]")

    # 反事实分析 (Δ)
    if result.counterfactuals:
        console.print(f"\n[bold]反事实分析 (Δ): {len(result.counterfactuals)} 条边[/bold]")
        critical = [cf for cf in result.counterfactuals if cf.became_safe]
        if critical:
            console.print(f"  [red]关键边 ({len(critical)}):[/red]")
            for cf in critical:
                src, tgt, rel = cf.edge
                console.print(f"    • {src} → {tgt} ({rel}): {cf.explanation[:100]}")
        else:
            console.print(f"  [green]无关键边 — 所有边移除后仍有替代路径[/green]")

    # 最小割集 (MCS)
    if result.mcs_cut_edges:
        console.print(f"\n[bold]最小割集 (MCS): {len(result.mcs_cut_edges)} 条边[/bold]")
        console.print(f"  策略: [cyan]{result.mcs_strategy}[/cyan]")
        for cut in result.mcs_cut_edges:
            src, tgt, rel = cut
            console.print(f"    • [{src}] → [{tgt}] ({rel})")
        if result.mcs_verified is not None:
            verify_color = "green" if result.mcs_verified else "red"
            verify_icon = "✓" if result.mcs_verified else "✗"
            console.print(f"  MCS 验证: [{verify_color}]{verify_icon} {result.mcs_verification_note}[/{verify_color}]")

    # 攻击战术分类 (Label)
    if result.primary_tactic:
        console.print(f"\n[bold]攻击战术 (Label):[/bold] [magenta]{result.primary_tactic}[/magenta]")

    # 详细说明
    console.print(f"\n[bold dim]分析详情:[/bold dim]")
    console.print(f"[dim]{result.terminal_explanation}[/dim]")

    # 输出报告
    if output:
        _print_analyze_json(result, output)


@main.command()
@click.option("--format", "-f", "fmt", default="html",
              type=click.Choice(["json", "md", "html"]),
              help="导出格式 (默认: html)")
@click.option("--output", "-o", required=True, type=click.Path(),
              help="输出文件路径")
@click.option("--what", default="catalog",
              type=click.Choice(["catalog", "playbook"]),
              help="导出内容 (默认: catalog)")
@click.option("--title", default="K8s Arsenal Attack Vector Catalog",
              help="报告标题")
def export(fmt: str, output: str, what: str, title: str):
    """多格式导出攻击向量编目/剧本"""
    from k8s_arsenal.utils.export import export_catalog, export_playbook
    from k8s_arsenal.playbook.templates import CHAIN_TEMPLATES

    console.print(Panel.fit(f"[bold cyan]导出 [{fmt.upper()}] → {output}[/bold cyan]"))

    if what == "catalog":
        all_vectors = _collect_all_vectors()
        export_catalog(all_vectors, output, fmt=fmt, title=title)
        console.print(f"[green]✓[/green] 已导出 {len(all_vectors)} 个攻击向量 → {output}")
    elif what == "playbook":
        export_playbook(CHAIN_TEMPLATES, output, fmt=fmt)
        console.print(f"[green]✓[/green] 已导出 {len(CHAIN_TEMPLATES)} 个攻击剧本 → {output}")


# ════════════════════════════════════════════════════════════════════
# self-check — Pod 内自检
# ════════════════════════════════════════════════════════════════════

@main.command()
@click.option("--output", "-o", type=click.Path(),
              help="JSON 报告输出路径")
@click.option("--rbac/--no-rbac", default=True,
              help="是否检查 RBAC 权限 (需要 k8s client, 默认: 是)")
def self_check(output: Optional[str], rbac: bool):
    """Pod 内自治攻击面扫描 (集群内自检)"""
    from k8s_arsenal.utils.self_check import PodSelfChecker, print_self_check

    console.print(Panel.fit("[bold yellow]K8s Arsenal — Pod 自检[/bold yellow]"))

    checker = PodSelfChecker()
    report = checker.check(use_k8s_api=rbac)
    print_self_check(report)

    if output:
        import json as _json
        data = {
            "timestamp": report.timestamp,
            "namespace": report.namespace,
            "pod_name": report.pod_name,
            "service_account": report.service_account,
            "node_name": report.node_name,
            "risk_score": report.risk_score,
            "results": [
                {
                    "category": r.category,
                    "name": r.name,
                    "status": r.status,
                    "risk": r.risk.value if hasattr(r.risk, "value") else str(r.risk),
                    "detail": r.detail,
                    "remediation": r.remediation,
                }
                for r in report.results
            ],
        }
        with open(output, "w", encoding="utf-8") as f:
            _json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"[green]报告已保存至: {output}[/green]")


# ════════════════════════════════════════════════════════════════════
# interactive — 交互式菜单
# ════════════════════════════════════════════════════════════════════

@main.command()
@click.pass_context
def interactive(ctx):
    """交互式菜单模式（问答式引导）"""
    console.print(Panel.fit(
        "[bold magenta]K8s Arsenal — 交互式模式[/bold magenta]\n"
        "[dim]输入编号选择操作，Ctrl+C 退出[/dim]"
    ))

    while True:
        console.print("\n[bold]可用操作:[/bold]")
        console.print("  [cyan]1.[/cyan] 战场评估 (assess)")
        console.print("  [cyan]2.[/cyan] 攻击向量评分排序 (optimize --compare)")
        console.print("  [cyan]3.[/cyan] 生成最优攻击链 (optimize)")
        console.print("  [cyan]4.[/cyan] 生成攻击剧本 (playbook --smart)")
        console.print("  [cyan]5.[/cyan] 环境侦察 (recon)")
        console.print("  [cyan]6.[/cyan] 逃逸检测 (escape --check)")
        console.print("  [cyan]7.[/cyan] 浏览技术编目 (catalog)")
        console.print("  [cyan]8.[/cyan] 查看使用示例")
        console.print("  [cyan]9.[/cyan] 信任拓扑映射 (trust-map)")
        console.print("  [cyan]10.[/cyan] 攻击图完整分析 (analyze)")
        console.print("  [cyan]0.[/cyan] 退出")

        try:
            choice = click.prompt("\n请选择", type=int, default=0, show_default=False)
        except click.Abort:
            break

        if choice == 0:
            console.print("[dim]退出交互式模式[/dim]")
            break
        elif choice == 1:
            ctx.invoke(assess)
        elif choice == 2:
            stealth = click.confirm("使用隐蔽优先模式?", default=False)
            top_n = click.prompt("显示前几名?", type=int, default=10)
            ctx.invoke(optimize, compare=True, stealth=stealth, top=top_n)
        elif choice == 3:
            stealth = click.confirm("使用隐蔽优先模式?", default=False)
            max_depth = click.prompt("最大链深度?", type=int, default=6)
            ctx.invoke(optimize, stealth=stealth, max_depth=max_depth)
        elif choice == 4:
            entry = click.prompt("入口条件", default="low-privilege-sa")
            target = click.prompt("目标权限", default="cluster-admin")
            ctx.invoke(playbook, entry=entry, target=target, smart=True)
        elif choice == 5:
            full = click.confirm("完整侦察?", default=False)
            ctx.invoke(recon, full=full)
        elif choice == 6:
            ctx.invoke(escape, check=True, list_all=False)
        elif choice == 7:
            phase = click.prompt("阶段筛选 (all=全部)", default="all")
            ctx.invoke(catalog, phase=phase, risk="all")
        elif choice == 9:
            attackable = click.confirm("仅显示可被利用的边?", default=False)
            ctx.invoke(trust_map_cmd, attackable=attackable)
        elif choice == 10:
            entry = click.prompt("入口节点 (留空自动检测)", default="")
            targets_input = click.prompt("关键资产 (逗号分隔)", default="")
            targets = tuple(t.strip() for t in targets_input.split(",") if t.strip())
            full_pipeline = click.confirm("完整六层分析?", default=True)
            ctx.invoke(analyze, entry=entry, targets=targets, full_pipeline=full_pipeline, threshold="standard", as_json=False, output=None)
        elif choice == 8:
            console.print("\n[bold]K8s Arsenal 使用示例:[/bold]")
            console.print(
                "[dim]详细文档: docs/examples.md[/dim]\n\n"
                "[cyan]快速扫描:[/cyan]\n"
                "  k8s-arsenal self-check\n"
                "  k8s-arsenal assess\n"
                "  k8s-arsenal optimize --compare\n\n"
                "[cyan]攻击链:[/cyan]\n"
                "  k8s-arsenal playbook --smart\n"
                "  k8s-arsenal playbook --entry privileged-pod --target node-access\n\n"
                "[cyan]导出:[/cyan]\n"
                "  k8s-arsenal export -f html -o report.html\n"
                "  k8s-arsenal export -f json -o catalog.json\n\n"
                "[cyan]Python API:[/cyan]\n"
                "  from k8s_arsenal.core.engine import AdaptiveEngine\n"
                "  from k8s_arsenal.core.optimizer import AttackVectorOptimizer\n"
            )
        else:
            console.print("[red]无效选择，请重新输入[/red]")


if __name__ == "__main__":
    main()
