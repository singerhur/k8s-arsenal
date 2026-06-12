"""多格式导出模块

支持将攻击向量编目、攻击剧本等导出为 JSON、HTML、Markdown 格式。
"""

import json
from datetime import datetime
from typing import Optional, Any

from k8s_arsenal.models import AttackVector, AttackPath, AttackPhase, RiskLevel


# ── 风险颜色映射 ────────────────────────────────────────────
RISK_COLORS = {
    RiskLevel.CRITICAL: "#d73a49",
    RiskLevel.HIGH: "#f66a0a",
    RiskLevel.MEDIUM: "#dbab09",
    RiskLevel.LOW: "#28a745",
    RiskLevel.INFO: "#0366d6",
}

RISK_EMOJI = {
    RiskLevel.CRITICAL: "\U0001f480",  # skull
    RiskLevel.HIGH: "\u26a0\ufe0f",
    RiskLevel.MEDIUM: "\u2139\ufe0f",
    RiskLevel.LOW: "\u2705",
    RiskLevel.INFO: "\U0001f4cc",
}

PHASE_CATEGORIES = {
    AttackPhase.INITIAL_ACCESS: "Initial Access",
    AttackPhase.EXECUTION: "Execution",
    AttackPhase.PERSISTENCE: "Persistence",
    AttackPhase.PRIVILEGE_ESCALATION: "Privilege Escalation",
    AttackPhase.DEFENSE_EVASION: "Defense Evasion",
    AttackPhase.CREDENTIAL_ACCESS: "Credential Access",
    AttackPhase.DISCOVERY: "Discovery",
    AttackPhase.LATERAL_MOVEMENT: "Lateral Movement",
    AttackPhase.COLLECTION: "Collection",
    AttackPhase.EXFILTRATION: "Exfiltration",
    AttackPhase.IMPACT: "Impact",
}


def vectors_to_json(vectors: list[AttackVector], indent: int = 2) -> str:
    """攻击向量 → JSON"""
    data: dict[str, Any] = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_vectors": len(vectors),
        "by_phase": {},
        "by_risk": {},
        "vectors": [],
    }

    for v in vectors:
        entry = {
            "id": v.id,
            "name": v.name,
            "phase": v.phase.value if hasattr(v.phase, "value") else str(v.phase),
            "risk": v.risk.value if hasattr(v.risk, "value") else str(v.risk),
            "description": v.description,
            "prerequisites": v.prerequisites,
            "steps": v.steps,
            "detection_hints": v.detection_hints,
        }
        if hasattr(v, "cve") and v.cve:
            entry["cve"] = v.cve
        if hasattr(v, "references") and v.references:
            entry["references"] = v.references

        data["vectors"].append(entry)
        phase_key = entry["phase"]
        data["by_phase"].setdefault(phase_key, [])
        data["by_phase"][phase_key].append(entry["id"])
        risk_key = entry["risk"]
        data["by_risk"].setdefault(risk_key, 0)
        data["by_risk"][risk_key] += 1

    return json.dumps(data, indent=indent, ensure_ascii=False)


def vectors_to_markdown(vectors: list[AttackVector], title: str = "Attack Vector Catalog") -> str:
    """攻击向量 → Markdown"""
    lines = [
        f"# {title}",
        f"",
        f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}*",
        f"",
        f"**Total Vectors:** {len(vectors)}",
        f"",
        "---",
        "",
    ]

    # 按阶段分组
    by_phase: dict[str, list[AttackVector]] = {}
    for v in vectors:
        phase_name = PHASE_CATEGORIES.get(v.phase, v.phase.value if hasattr(v.phase, "value") else str(v.phase))
        by_phase.setdefault(phase_name, []).append(v)

    # 目录
    lines.append("## Table of Contents")
    lines.append("")
    for phase_name in PHASE_CATEGORIES.values():
        if phase_name in by_phase:
            lines.append(f"- [{phase_name}](#{phase_name.lower().replace(' ', '-')}) ({len(by_phase[phase_name])} vectors)")
    lines.append("")
    lines.append("---")
    lines.append("")

    for phase_name in PHASE_CATEGORIES.values():
        if phase_name not in by_phase:
            continue
        lines.append(f"## {phase_name}")
        lines.append("")

        for v in by_phase[phase_name]:
            emoji = RISK_EMOJI.get(v.risk, "")
            lines.append(f"### {emoji} {v.id}: {v.name}")
            lines.append("")
            lines.append(f"**Risk:** {v.risk.value if hasattr(v.risk, 'value') else v.risk}")
            lines.append(f"**Phase:** {phase_name}")
            if hasattr(v, "cve") and v.cve:
                lines.append(f"**CVE:** {v.cve}")
            lines.append("")
            lines.append(v.description)
            lines.append("")

            if v.prerequisites:
                lines.append("**Prerequisites:**")
                for p in v.prerequisites:
                    lines.append(f"- {p}")
                lines.append("")

            if v.steps:
                lines.append("**Attack Steps:**")
                for i, s in enumerate(v.steps, 1):
                    lines.append(f"{i}. {s}")
                lines.append("")

            if v.detection_hints:
                lines.append("**Detection Hints:**")
                for h in v.detection_hints:
                    lines.append(f"- {h}")
                lines.append("")

            if hasattr(v, "references") and v.references:
                lines.append("**References:**")
                for r in v.references:
                    lines.append(f"- {r}")
                lines.append("")

            lines.append("---")
            lines.append("")
    return "\n".join(lines)


def vectors_to_html(
    vectors: list[AttackVector],
    title: str = "K8s Arsenal — Attack Vector Catalog",
    standalone: bool = True,
) -> str:
    """攻击向量 → HTML 报告"""

    styles = """
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               max-width: 1100px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; }
        h1 { color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }
        h2 { color: #f0883e; margin-top: 30px; }
        h3 { color: #e6edf3; margin-top: 25px; border-left: 3px solid #30363d; padding-left: 12px; }
        .meta { color: #8b949e; font-size: 0.9em; }
        .vector { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                  padding: 16px; margin: 12px 0; }
        .risk-critical { border-left: 4px solid #d73a49; }
        .risk-high { border-left: 4px solid #f66a0a; }
        .risk-medium { border-left: 4px solid #dbab09; }
        .risk-low { border-left: 4px solid #28a745; }
        .risk-info { border-left: 4px solid #0366d6; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
                 font-size: 0.8em; font-weight: 600; }
        .badge-risk-critical { background: #d73a49; color: #fff; }
        .badge-risk-high { background: #f66a0a; color: #fff; }
        .badge-risk-medium { background: #dbab09; color: #000; }
        .badge-risk-low { background: #28a745; color: #fff; }
        .badge-risk-info { background: #0366d6; color: #fff; }
        .badge-phase { background: #30363d; color: #c9d1d9; margin-left: 6px; }
        .badge-cve { background: #6f42c1; color: #fff; margin-left: 6px; }
        ul { margin: 8px 0; padding-left: 20px; }
        li { margin: 4px 0; }
        .toc { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
               padding: 16px; margin: 20px 0; }
        .toc ul { list-style: none; padding-left: 0; }
        .toc li { margin: 8px 0; }
        .toc a { color: #58a6ff; text-decoration: none; }
        .toc a:hover { text-decoration: underline; }
        .detail-item { margin: 6px 0; }
        .detail-label { color: #8b949e; font-weight: 600; }
        hr { border: 0; border-top: 1px solid #30363d; margin: 30px 0; }
        .stats { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                     padding: 12px 20px; text-align: center; min-width: 100px; }
        .stat-num { font-size: 2em; font-weight: 700; color: #58a6ff; }
        .stat-label { color: #8b949e; font-size: 0.85em; }
    </style>
    """

    risk_stats: dict[str, int] = {}
    phase_stats: dict[str, int] = {}
    for v in vectors:
        rk = v.risk.value if hasattr(v.risk, "value") else str(v.risk)
        pk = v.phase.value if hasattr(v.phase, "value") else str(v.phase)
        risk_stats[rk] = risk_stats.get(rk, 0) + 1
        phase_stats[pk] = phase_stats.get(pk, 0) + 1

    stats_html = f"""
    <div class="stats">
        <div class="stat-card"><div class="stat-num">{len(vectors)}</div><div class="stat-label">Total Vectors</div></div>
    </div>
    """

    # TOC
    toc_items = []
    by_phase: dict[str, list[AttackVector]] = {}
    for v in vectors:
        phase_name = PHASE_CATEGORIES.get(v.phase, v.phase.value if hasattr(v.phase, "value") else str(v.phase))
        by_phase.setdefault(phase_name, []).append(v)

    for phase_name in PHASE_CATEGORIES.values():
        if phase_name in by_phase:
            toc_items.append(
                f'<li><a href="#{phase_name.lower().replace(" ", "-")}">'
                f'{phase_name}</a> ({len(by_phase[phase_name])})</li>'
            )

    toc_html = f'<div class="toc"><strong>Table of Contents</strong><ul>{"".join(toc_items)}</ul></div>'

    # Vectors
    vector_html_parts = []
    for phase_name in PHASE_CATEGORIES.values():
        if phase_name not in by_phase:
            continue

        vector_html_parts.append(
            f'<h2 id="{phase_name.lower().replace(" ", "-")}">{phase_name}</h2>'
        )

        for v in by_phase[phase_name]:
            risk_val = v.risk.value if hasattr(v.risk, "value") else str(v.risk)
            risk_class = f"risk-{risk_val.lower()}" if risk_val.lower() in ("critical", "high", "medium", "low", "info") else "risk-medium"
            badge_class = f"badge-risk-{risk_val.lower()}" if risk_val.lower() in ("critical", "high", "medium", "low", "info") else "badge-risk-medium"

            cve_badge = ""
            if hasattr(v, "cve") and v.cve:
                cve_badge = f'<span class="badge badge-cve">{v.cve}</span>'

            prereqs = "".join(f"<li>{p}</li>" for p in v.prerequisites) if v.prerequisites else "<li>None</li>"
            steps = "".join(f"<li>{s}</li>" for s in v.steps) if v.steps else "<li>None</li>"
            detections = "".join(f"<li>{h}</li>" for h in v.detection_hints) if v.detection_hints else "<li>None</li>"

            refs = ""
            if hasattr(v, "references") and v.references:
                refs = '<p class="detail-item"><span class="detail-label">References:</span><br/>' + \
                       "<br/>".join(f"- {r}" for r in v.references) + "</p>"

            vector_html_parts.append(f"""
            <div class="vector {risk_class}">
                <h3>
                    {RISK_EMOJI.get(v.risk, "")} {v.id}: {v.name}
                    <span class="badge {badge_class}">{risk_val}</span>
                    <span class="badge badge-phase">{phase_name}</span>
                    {cve_badge}
                </h3>
                <p>{v.description}</p>
                <p class="detail-item"><span class="detail-label">Prerequisites:</span></p>
                <ul>{prereqs}</ul>
                <p class="detail-item"><span class="detail-label">Attack Steps:</span></p>
                <ol>{steps}</ol>
                <p class="detail-item"><span class="detail-label">Detection Hints:</span></p>
                <ul>{detections}</ul>
                {refs}
            </div>
            """)

    body = f"""
    {stats_html}
    {toc_html}
    {"".join(vector_html_parts)}
    <hr/>
    <p class="meta">Generated by K8s Arsenal — {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    """

    if standalone:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    {styles}
</head>
<body>
    <h1>{title}</h1>
    {body}
</body>
</html>"""
    return body


def playbook_to_json(playbooks: list[AttackPath], indent: int = 2) -> str:
    """攻击剧本 → JSON"""
    data = []
    for pb in playbooks:
        entry = {
            "id": pb.id,
            "name": pb.name,
            "description": pb.description,
            "difficulty": pb.difficulty.value if hasattr(pb.difficulty, "value") else str(pb.difficulty),
            "estimated_time": pb.estimated_time,
            "vector_count": len(pb.vectors),
            "vectors": [
                {
                    "id": v.id,
                    "name": v.name,
                    "phase": v.phase.value if hasattr(v.phase, "value") else str(v.phase),
                    "description": v.description,
                }
                for v in pb.vectors
            ],
        }
        data.append(entry)
    return json.dumps(data, indent=indent, ensure_ascii=False)


def playbook_to_markdown(playbooks: list[AttackPath]) -> str:
    """攻击剧本 → Markdown"""
    lines = [
        "# Attack Playbooks",
        "",
        f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}*",
        "",
    ]

    for pb in playbooks:
        lines.append(f"## {pb.id}: {pb.name}")
        lines.append("")
        lines.append(f"**Difficulty:** {pb.difficulty.value if hasattr(pb.difficulty, 'value') else pb.difficulty}")
        lines.append(f"**Estimated Time:** {pb.estimated_time}")
        lines.append("")
        lines.append(pb.description)
        lines.append("")

        lines.append("### Attack Chain")
        lines.append("")
        lines.append("| # | Phase | Vector |")
        lines.append("|---|-------|--------|")
        for i, v in enumerate(pb.vectors, 1):
            phase = PHASE_CATEGORIES.get(v.phase, v.phase.value if hasattr(v.phase, "value") else str(v.phase))
            lines.append(f"| {i} | {phase} | {v.name} |")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def export_catalog(
    vectors: list[AttackVector],
    output_path: str,
    fmt: str = "json",
    title: str = "K8s Arsenal Attack Vector Catalog",
):
    """导出向量编目到文件

    Args:
        vectors: 攻击向量列表
        output_path: 输出文件路径
        fmt: 格式 (json, md, html)
        title: 标题
    """
    writers = {
        "json": lambda: vectors_to_json(vectors),
        "md": lambda: vectors_to_markdown(vectors, title),
        "html": lambda: vectors_to_html(vectors, title),
    }

    writer = writers.get(fmt)
    if not writer:
        raise ValueError(f"Unsupported format: {fmt}. Use json, md, or html.")

    content = writer()
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path


def export_playbook(
    playbooks: list[AttackPath],
    output_path: str,
    fmt: str = "json",
):
    """导出攻击剧本到文件"""
    writers = {
        "json": lambda: playbook_to_json(playbooks),
        "md": lambda: playbook_to_markdown(playbooks),
    }

    writer = writers.get(fmt)
    if not writer:
        raise ValueError(f"Unsupported format: {fmt}. Use json or md.")

    content = writer()
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path
