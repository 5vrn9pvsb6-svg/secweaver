"""Convert SecWeaver structured JSON skill outputs into human-readable Markdown reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

Renderer = Callable[[dict[str, Any]], str]

DEMO_JSON_NAMES = {
    "completeness": "demo-completeness-output.json",
    "alert": "demo-alert-output.json",
    "traceability": "demo-traceability-output.json",
    "risk": "demo-risk-output.json",
}


def _heading(title: str, level: int = 1) -> str:
    return f"{'#' * level} {title}"


def _bullet(label: str, value: Any) -> str:
    if value is None or value == "":
        return ""
    return f"- **{label}**: {value}"


def _section_header(title: str, *, level: int = 2) -> list[str]:
    return ["", _heading(title, level), ""]


def _list_items(items: list[Any]) -> list[str]:
    if not items:
        return ["- _(none)_"]
    return [f"- {item}" for item in items]


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return ["_(none)_"]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def _format_scenarios(scenario: Any) -> str:
    if isinstance(scenario, list):
        return ", ".join(str(item) for item in scenario)
    return str(scenario or "")


def _format_evidence_map(evidence: Any) -> list[str]:
    if not isinstance(evidence, dict):
        return []
    lines: list[str] = []
    for key, refs in evidence.items():
        if isinstance(refs, list):
            lines.append(f"- **{key}**: {', '.join(str(ref) for ref in refs) or '_(none)_'}")
    return lines


def render_completeness(payload: dict[str, Any]) -> str:
    params = payload.get("investigation_params") or {}
    lines = [
        _heading("Data Source Completeness Report"),
        "",
        _bullet("Scenario", _format_scenarios(payload.get("scenario"))),
        _bullet("Scenario summary", payload.get("scenario_summary")),
        _bullet("Overall verdict", payload.get("overall_verdict")),
        _bullet("Confidence", payload.get("confidence")),
        _bullet("Can trace", payload.get("can_trace")),
        _bullet("Can confirm breach", payload.get("can_confirm_breach")),
        _bullet("Recommended next skill", payload.get("next_skill")),
        "",
        payload.get("summary", ""),
    ]
    lines.extend(
        _section_header("Investigation parameters")
        + [
            _bullet("Attacker IP", params.get("attacker_ip")),
            _bullet("Time range", f"{params.get('time_start')} ~ {params.get('time_end')}"),
            _bullet("Hosts", ", ".join(params.get("hosts") or [])),
        ]
    )

    requirement_rows: list[list[str]] = []
    for item in payload.get("requirements_evaluated") or []:
        requirement_rows.append(
            [
                str(item.get("priority") or ""),
                str(item.get("label") or ""),
                str(item.get("status") or ""),
                f"`{item.get('asset_id')}`" if item.get("asset_id") else "",
            ]
        )
    lines.extend(_section_header("Requirement evaluation"))
    lines.extend(_table(["Priority", "Requirement", "Status", "Asset"], requirement_rows))

    missing = payload.get("missing_critical") or []
    if missing:
        lines.extend(_section_header("Critical gaps") + _list_items(missing))

    recommendations = payload.get("recommendations") or []
    if recommendations:
        lines.extend(_section_header("Onboarding recommendations") + _list_items(recommendations))

    return "\n".join(line for line in lines if line is not None).rstrip() + "\n"


def render_alert(payload: dict[str, Any]) -> str:
    payload_analysis = payload.get("payload_analysis") or {}
    lines = [
        _heading("Alert Confirmation Report"),
        "",
        _bullet("Alert ID", payload.get("alert_id")),
        _bullet("Scenario", payload.get("scenario")),
        _bullet("Alert verdict", payload.get("alert_verdict")),
        _bullet("Attack type", payload.get("attack_type_label") or payload.get("attack_type")),
        _bullet("Attack outcome", payload.get("attack_outcome")),
        _bullet("Attack success", payload.get("attack_success")),
        _bullet("Confidence", payload.get("confidence")),
        _bullet("WAF action", payload.get("waf_action")),
        _bullet("Recommended action", payload.get("recommended_action_label") or payload.get("recommended_action")),
        _bullet("Next skill", payload.get("next_skill")),
        "",
        payload.get("summary", ""),
    ]
    lines.extend(
        _section_header("Payload analysis")
        + [
            _bullet("Has payload", payload_analysis.get("has_payload")),
            _bullet("Payload snippet", payload_analysis.get("payload_snippet")),
            _bullet("Technique", payload_analysis.get("technique")),
            _bullet("Validity", payload_analysis.get("validity")),
            _bullet("Notes", payload_analysis.get("notes")),
        ]
    )
    lines.extend(_section_header("Evidence summary") + _format_evidence_map(payload.get("evidence")))

    join_rows: list[list[str]] = []
    for edge in (payload.get("join_edges") or [])[:20]:
        keys = edge.get("match_keys") or {}
        key_text = ", ".join(f"{k}={v}" for k, v in keys.items())
        join_rows.append(
            [
                str(edge.get("join_id") or ""),
                str(edge.get("left_ref") or ""),
                str(edge.get("right_ref") or ""),
                key_text,
                str(edge.get("confidence") or ""),
            ]
        )
    lines.extend(_section_header("Join edges"))
    lines.extend(_table(["Join ID", "Left evidence", "Right evidence", "Match keys", "Confidence"], join_rows))

    gaps = payload.get("data_gaps_impact") or []
    if gaps:
        lines.extend(_section_header("Data gap impact") + _list_items(gaps))

    if payload.get("next_skill_reason"):
        lines.extend(_section_header("Next step") + [payload["next_skill_reason"]])

    return "\n".join(line for line in lines if line is not None).rstrip() + "\n"


def render_traceability(payload: dict[str, Any]) -> str:
    import sys
    from pathlib import Path

    scripts = Path(__file__).resolve().parent / "skills" / "traceability-analysis" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    from trace_report_markdown import render_traceability_report

    locale = payload.get("report_locale") or "en"
    return render_traceability_report(payload, locale=locale)


def render_risk(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") or {}
    lines = [
        _heading("Risk Identification Report"),
        "",
        _bullet("Scenario", payload.get("scenario")),
        _bullet("Overall verdict", payload.get("overall_verdict")),
        _bullet("Coverage level", payload.get("coverage_level")),
        _bullet("Events scanned", summary.get("total_events_scanned")),
        _bullet("Risk items", summary.get("risk_items")),
        _bullet("P0", summary.get("p0")),
    ]

    if payload.get("user_reminders"):
        lines.extend(_section_header("Data source reminders"))
        for reminder in payload["user_reminders"]:
            lines.append(f"- {reminder}")
        lines.append("")

    if payload.get("data_gaps"):
        lines.extend(_section_header("Data gaps") + _list_items(payload["data_gaps"]))

    risk_rows: list[list[str]] = []
    for item in payload.get("risk_items") or []:
        risk_rows.append(
            [
                str(item.get("severity") or ""),
                str(item.get("risk_module") or ""),
                str(item.get("host") or ""),
                str(item.get("summary") or ""),
            ]
        )
    lines.extend(_section_header("Top risks"))
    lines.extend(_table(["Severity", "Module", "Host", "Summary"], risk_rows))

    if payload.get("recommended_next_skills"):
        lines.extend(_section_header("Recommended next skills"))
        for rec in payload["recommended_next_skills"]:
            lines.append(f"- `{rec.get('skill')}`: {rec.get('reason')}")

    return "\n".join(line for line in lines if line is not None).rstrip() + "\n"


def render_generic(payload: dict[str, Any]) -> str:
    lines = [
        _heading("SecWeaver Structured Output Report"),
        "",
        _bullet("Type", payload.get("alert_type") or payload.get("skill") or "unknown"),
        _bullet("Verdict", payload.get("overall_verdict") or payload.get("alert_verdict")),
        _bullet("Confidence", payload.get("confidence")),
        "",
        str(payload.get("summary") or ""),
        "",
        "## JSON summary",
        "",
        "```json",
        json.dumps(
            {
                key: payload[key]
                for key in ("alert_type", "skill", "scenario", "overall_verdict", "alert_verdict", "confidence", "summary")
                if key in payload
            },
            ensure_ascii=False,
            indent=2,
        ),
        "```",
    ]
    return "\n".join(lines).rstrip() + "\n"


RENDERERS: dict[str, Renderer] = {
    "data_source_completeness": render_completeness,
    "alert_confirmation": render_alert,
    "traceability_analysis": render_traceability,
    "risk-identification": render_risk,
}


def detect_report_type(payload: dict[str, Any]) -> str:
    alert_type = payload.get("alert_type")
    if isinstance(alert_type, str) and alert_type in RENDERERS:
        return alert_type
    skill = payload.get("skill")
    if isinstance(skill, str) and skill in RENDERERS:
        return skill
    return "generic"


def render_markdown(payload: dict[str, Any]) -> str:
    report_type = detect_report_type(payload)
    if report_type == "generic":
        return render_generic(payload)
    return RENDERERS[report_type](payload)


def json_output_path_to_markdown(path: Path) -> Path:
    if path.suffix.lower() == ".json":
        return path.with_suffix(".md")
    return path.with_name(f"{path.name}.md")


def render_markdown_file(input_path: Path) -> str:
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    return render_markdown(payload)


def write_markdown_file(input_path: Path, output_path: Path | None = None) -> Path:
    output = output_path or json_output_path_to_markdown(input_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown_file(input_path), encoding="utf-8")
    return output


def render_investigation_bundle(directory: Path) -> str:
    sections: list[str] = [
        _heading("SecWeaver Investigation Bundle Report"),
        "",
        "This report is auto-generated from offline demo JSON outputs: completeness precheck, alert confirmation, traceability analysis, and risk identification.",
        "",
        "---",
    ]
    titles = {
        "completeness": "1. Data source completeness",
        "alert": "2. Alert confirmation",
        "traceability": "3. Attack chain traceability",
        "risk": "4. Host risk identification",
    }
    for key, filename in DEMO_JSON_NAMES.items():
        input_path = directory / filename
        if not input_path.is_file():
            continue
        payload = json.loads(input_path.read_text(encoding="utf-8"))
        sections.extend(["", _heading(titles[key], 2), ""])
        sections.append(render_markdown(payload).strip())
        sections.append("")
        sections.append("---")
    return "\n".join(sections).rstrip() + "\n"


def write_demo_markdown_reports(directory: Path) -> list[Path]:
    outputs: list[Path] = []
    for filename in DEMO_JSON_NAMES.values():
        input_path = directory / filename
        if input_path.is_file():
            outputs.append(write_markdown_file(input_path))
    return outputs
