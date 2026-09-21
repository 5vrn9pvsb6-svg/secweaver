"""Verdict, confidence, blocked-result, and report helpers."""

from __future__ import annotations

from typing import Any

from heuristic_rules import policy_block, resolve_verdict_from_policy  # noqa: E402


def simplify_evidence_item(event: dict[str, Any]) -> dict[str, Any]:
    """Expose correlation-critical fields in the report evidence index.

    The index is a report-facing summary, not the raw evidence archive. It
    must nevertheless retain SSH result, rule, source, and message fields so
    an analyst can verify a confirmed lateral login without reopening a raw
    connector response.
    """
    summary = {
        "bundle": event.get("_bundle"),
        "timestamp": event.get("timestamp"),
        "host": event.get("host"),
    }
    for field in (
        "host_ip",
        "src_ip",
        "source_ip",
        "user",
        "result",
        "event_type",
        "rule_id",
        "rule_name",
        "message",
        "raw_behavior",
    ):
        value = event.get(field)
        if value not in (None, ""):
            summary[field] = value
    return summary


def gate_precheck(precheck: dict | None) -> tuple[bool, str, float]:
    if not precheck:
        return True, "", 1.0
    if precheck.get("next_skill_blocked"):
        return False, precheck.get("block_reason") or "数据源完整性预检未通过", float(precheck.get("confidence") or 0)
    verdict = precheck.get("overall_verdict", "")
    if verdict in ("not_traceable", "alert_triage_only"):
        return False, f"overall_verdict={verdict}", float(precheck.get("confidence") or 0)
    confidence = precheck.get("confidence")
    ceiling = float(1.0 if confidence is None else confidence)
    return True, "", ceiling


def determine_verdict(
    initial: dict | None,
    execution: list[dict],
    lateral: list[dict],
    blocked: bool,
    has_exec: bool,
) -> str:
    return resolve_verdict_from_policy(
        {
            "blocked": blocked,
            "has_initial": initial is not None,
            "has_execution": bool(execution),
            "has_lateral": bool(lateral),
            "has_exec": has_exec,
        }
    )


def compute_confidence(chain: list[dict], ceiling: float) -> float:
    defaults = policy_block("confidence_defaults")
    stage_fallback = float(defaults.get("stage_fallback") or 0.7)
    empty_cap = float(defaults.get("empty_chain_cap") or 0.4)
    if not chain:
        return min(empty_cap, ceiling)
    avg = sum(c.get("confidence", stage_fallback) for c in chain) / len(chain)
    return round(min(ceiling, avg), 2)


def recommended_actions(impacted: list[dict], verdict: str) -> list[str]:
    actions = []
    if verdict in ("confirmed_intrusion_chain", "likely_intrusion_chain", "initial_access_only"):
        hosts = [a["host"] for a in impacted if a.get("role") == "initial_compromise"]
        if hosts:
            actions.append(f"立即隔离初始受害主机: {', '.join(hosts)}")
        lateral = [a["host"] for a in impacted if a.get("role") == "lateral_target"]
        if lateral:
            actions.append(f"排查并隔离横向目标（至少）: {', '.join(lateral)}")
        actions.append("保全 WEB 与 SSH 相关日志，冻结当前时间窗证据")
        actions.append("重置横向涉及主机上的可疑账号密码，检查 SSH 密钥")
    elif verdict == "scanning_or_attempt_only":
        actions.append("持续观察该 IP，检查 WAF 规则与封禁策略")
    else:
        actions.append("先补全数据源后重新溯源，参见数据源完整性分析建议")
    return actions


def _blocked_result(
    *,
    scenarios: list[str],
    ceiling: float,
    gate_reason: str,
    data_gaps: list[str],
    index: dict[str, dict],
    contract: dict[str, Any] | None = None,
) -> dict:
    base: dict[str, Any] = {
        "alert_type": "traceability_analysis",
        "scenario": scenarios,
        "overall_verdict": "insufficient_evidence",
        "confidence": min(0.35, ceiling),
        "confidence_ceiling": ceiling,
        "blocked": True,
        "block_reason": gate_reason,
        "summary": f"数据源预检未通过，无法开展可靠溯源：{gate_reason}",
        "initial_access": None,
        "attack_chain": [],
        "lateral_movement_graph": {"nodes": [], "edges": []},
        "impacted_assets": [],
        "lateral_findings": {"confirmed": [], "suspected": [], "unknown": []},
        "timeline": [],
        "hypotheses": [],
        "data_gaps_impact": data_gaps,
        "correlation": {"join_edges": [], "data_gaps": [], "join_coverage": {}},
        "join_edges": [],
        "join_coverage": {},
        "recommended_actions": recommended_actions([], "insufficient_evidence"),
        "evidence_index": {
            ref: simplify_evidence_item(ev)
            for ref, ev in index.items()
        },
    }
    if contract:
        base["correlation_anchor_pattern"] = contract.get("correlation_anchor_pattern")
        base["correlation_anchor_patterns"] = contract.get("anchor_pattern_ids")
        base["correlation_contract"] = contract.get("correlation_contract")
        base["anchor_patterns"] = contract.get("anchor_patterns")
    return base


def trace_markdown_report(result: dict[str, Any], *, locale: str | None = None) -> str:
    from trace_report_markdown import render_traceability_report  # noqa: E402

    resolved_locale = locale or result.get("report_locale") or "en"
    return render_traceability_report(result, locale=resolved_locale)
