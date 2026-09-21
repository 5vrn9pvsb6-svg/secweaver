#!/usr/bin/env python3
"""SecWeaver 风险识别 — 编排层确定性研判脚本。"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPTS_DIR.parent
REPO_ROOT = SCRIPTS_DIR.parents[3]
SCENARIOS_PATH = SKILL_ROOT / "scenarios.json"
DATA_ACCESS_PATH = SCRIPTS_DIR.parents[1] / "_shared" / "data-access"

sys.path.insert(0, str(SCRIPTS_DIR))
from time_utils import in_time_window, parse_ts  # noqa: E402
from exec_rules import (  # noqa: E402
    SEVERITY_RANK,
    action_for as exec_action,
    build_exec_summary,
    configure_exec_rules,
    confidence_for as exec_confidence,
    match_exec_rules,
    required_fields_ok as exec_fields_ok,
    verdict_for as exec_verdict,
)
from connect_rules import (  # noqa: E402
    action_for as connect_action,
    build_connect_summary,
    configure_connect_rules,
    confidence_for as connect_confidence,
    match_connect_rules,
    required_fields_ok as connect_fields_ok,
    verdict_for as connect_verdict,
)
from dns_rules import assess_dns_events, configure_dns_rules, filter_dns_events  # noqa: E402
from persistence_rules import (  # noqa: E402
    assess_persistence_events,
    configure_persistence_rules,
    filter_persistence_events,
)
from source_risk_map import _source_available, evaluate_source_coverage  # noqa: E402
from behavior_policy import DEFAULT_POLICY_PATH, apply_behavior_policy  # noqa: E402
from incident_aggregator import aggregate_incidents, incidents_from_params  # noqa: E402
from ssh_rules import assess_ssh_bruteforce, configure_ssh_rules, filter_ssh_events_for_hosts  # noqa: E402
from syslog_rules import assess_syslog_events, configure_syslog_rules, filter_syslog_events  # noqa: E402
from rule_loader import configure_rules_dir, rule_file, rules_dir as get_rules_dir  # noqa: E402
from attck_map import apply_mitre_attack, configure_attck_map, format_mitre_attack_short, get_attck_map  # noqa: E402
from whitelist import (  # noqa: E402
    DEFAULT_WHITELIST_PATH,
    apply_whitelist,
    resolve_whitelist_config,
    whitelist_disabled,
)

GENERIC_HOST_VALUES = {"localhost", "localhost.localdomain", "null", "unknown"}


def report_path(path: Path | str) -> str:
    """Serialize repository paths without leaking a developer checkout location."""
    candidate = Path(path)
    try:
        return candidate.resolve().relative_to(REPO_ROOT).as_posix()
    except (OSError, ValueError):
        return candidate.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def load_scenarios(path: Path) -> dict[str, Any]:
    return load_json(path)


def scenario_modules(scenario: str, catalog: dict[str, Any], explicit: list[str] | None) -> list[str]:
    if explicit:
        return explicit
    meta = catalog.get("scenarios", {}).get(scenario, {})
    return list(meta.get("risk_modules") or ["exec", "connect"])


def confidence_ceiling(precheck: dict[str, Any] | None) -> float:
    if not precheck:
        return 1.0
    confidence = precheck.get("confidence")
    ceiling = float(1.0 if confidence is None else confidence)
    verdict = precheck.get("overall_verdict") or ""
    if precheck.get("next_skill_blocked"):
        return min(ceiling, 0.5)
    if verdict == "not_traceable":
        return min(ceiling, 0.5)
    if verdict == "partial_traceable":
        return min(ceiling, 0.85)
    return ceiling


def hard_blocked(precheck: dict[str, Any] | None, bundles: dict[str, list]) -> tuple[bool, str | None]:
    if not precheck or not precheck.get("next_skill_blocked"):
        return False, None
    if not (bundles.get("host_exec") or bundles.get("host_persistence")):
        return True, "completeness blocked and host_exec/host_persistence evidence missing"
    return False, None


def event_timestamp(ev: dict[str, Any]) -> str | None:
    for key in ("timestamp", "time"):
        value = ev.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _host_candidates(ev: dict[str, Any]) -> set[str]:
    candidates: set[str] = set()
    generic: set[str] = set()
    for value in (
        ev.get("_victim_host"),
        ev.get("host"),
        ev.get("host_name"),
        ev.get("hostname"),
        ev.get("host_ip"),
        ev.get("log_source"),
        ev.get("__source__"),
    ):
        if value in (None, ""):
            continue
        text = str(value)
        if text.lower() in GENERIC_HOST_VALUES:
            generic.add(text)
        else:
            candidates.add(text)
    return candidates or generic


def host_matches(ev: dict[str, Any], params: dict[str, Any]) -> bool:
    event_hosts = _host_candidates(ev)
    expected_hosts = {
        str(value)
        for value in (params.get("host"), params.get("host_name"), params.get("host_ip"))
        if value not in (None, "")
    }
    if expected_hosts and event_hosts.isdisjoint(expected_hosts):
        return False
    hosts = params.get("hosts") or []
    if hosts and event_hosts.isdisjoint({str(h) for h in hosts}):
        return False
    return True


def listener_port_matches(ev: dict[str, Any], ports: list[int]) -> bool:
    if not ports:
        return True
    lp = ev.get("listener_port")
    if lp is None:
        return True
    expected: set[int] = set()
    for port in ports:
        try:
            expected.add(int(port))
        except (TypeError, ValueError):
            continue
    if not expected:
        return True
    try:
        return int(lp) in expected
    except (TypeError, ValueError):
        return True


def filter_events(events: list[dict], params: dict[str, Any]) -> list[dict]:
    ports = params.get("listener_ports") or []
    out = []
    for ev in events:
        if not host_matches(ev, params):
            continue
        if not in_time_window(event_timestamp(ev), params.get("time_start"), params.get("time_end")):
            continue
        if not listener_port_matches(ev, ports):
            continue
        out.append(ev)
    return out


def make_risk_id(ev: dict[str, Any], module: str, seq: int) -> str:
    parts = [
        module,
        str(ev.get("host") or ev.get("host_ip") or ""),
        str(event_timestamp(ev) or ""),
        str(ev.get("audit_id") or ev.get("evidence_id") or seq),
    ]
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:10]
    return f"risk-{digest}"


def severity_at_least(severity: str, floor: str) -> bool:
    return SEVERITY_RANK.get(severity, 9) <= SEVERITY_RANK.get(floor, 9)


def related_in_window(
    anchor: dict[str, Any],
    events: list[dict[str, Any]],
    *,
    window_sec: int = 300,
) -> list[dict[str, Any]]:
    anchor_hosts = _host_candidates(anchor)
    lp = anchor.get("listener_pid") or anchor.get("listener_port")
    ts0 = parse_ts(event_timestamp(anchor))
    if ts0 is None:
        return []
    out = []
    for ev in events:
        event_hosts = _host_candidates(ev)
        if anchor_hosts or event_hosts:
            if not anchor_hosts or not event_hosts or anchor_hosts.isdisjoint(event_hosts):
                continue
        else:
            continue
        elp = ev.get("listener_pid") or ev.get("listener_port")
        if lp is not None and elp is not None and str(elp) != str(lp):
            continue
        ts = parse_ts(event_timestamp(ev))
        if ts is None:
            continue
        if abs((ts - ts0).total_seconds()) <= window_sec:
            out.append(ev)
    return out


def assess_exec_module(
    events: list[dict[str, Any]],
    *,
    connects: list[dict[str, Any]],
    file_ops: list[dict[str, Any]],
    persistence_events: list[dict[str, Any]] | None = None,
    ceiling: float,
    severity_floor: str,
    warnings: list[str],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for i, ev in enumerate(events):
        ok, missing = exec_fields_ok(ev)
        if not ok:
            warnings.append(f"skip exec missing {missing}: {ev.get('evidence_id', i)}")
            continue
        rel_conn = related_in_window(ev, connects)
        rel_file = related_in_window(ev, file_ops)
        rel_persistence = related_in_window(ev, list(persistence_events or []), window_sec=600)
        severity, matched, tags = match_exec_rules(
            ev,
            has_connect=bool(rel_conn),
            has_file_op=bool(rel_file or rel_persistence),
        )
        if not severity_at_least(severity, severity_floor):
            continue
        in_chain = bool(rel_conn or rel_file or rel_persistence)
        item = {
            "risk_id": make_risk_id(ev, "exec", i + 1),
            "risk_module": "exec",
            "alert_type": "high_risk_command",
            "severity": severity,
            "confidence": exec_confidence(severity, matched, ceiling, in_chain),
            "verdict": exec_verdict(severity, matched),
            "host": ev.get("host") or ev.get("host_ip"),
            "timestamp": event_timestamp(ev),
            "listener_port": ev.get("listener_port"),
            "listener_process": ev.get("listener_process"),
            "listener_pid": ev.get("listener_pid"),
            "pid": ev.get("pid"),
            "ppid": ev.get("ppid"),
            "exe": ev.get("exe"),
            "command": ev.get("command"),
            "cwd": ev.get("cwd"),
            "matched_rules": matched,
            "risk_tags": tags,
            "recommended_action": exec_action(severity),
            "summary": build_exec_summary(ev, severity, matched),
            "evidence_refs": [ev.get("evidence_id")] if ev.get("evidence_id") else [],
        }
        items.append(item)
    return items


def assess_connect_module(
    events: list[dict[str, Any]],
    *,
    exec_events: list[dict[str, Any]],
    ceiling: float,
    severity_floor: str,
    warnings: list[str],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for i, ev in enumerate(events):
        ok, missing = connect_fields_ok(ev)
        if not ok:
            warnings.append(f"skip connect missing {missing}: {ev.get('evidence_id', i)}")
            continue
        rel_exec = related_in_window(ev, exec_events)
        texts = []
        for ex in rel_exec:
            cmd = ex.get("command")
            if isinstance(cmd, list):
                texts.append(" ".join(str(c) for c in cmd))
            else:
                texts.append(str(cmd or ex.get("comm") or ""))
        severity, matched, tags = match_connect_rules(
            ev,
            related_exec_texts=texts,
        )
        if not severity_at_least(severity, severity_floor):
            continue
        item = {
            "risk_id": make_risk_id(ev, "connect", i + 1),
            "risk_module": "connect",
            "alert_type": "high_risk_connect",
            "severity": severity,
            "confidence": connect_confidence(severity, matched, ceiling, bool(rel_exec)),
            "verdict": connect_verdict(severity, matched),
            "host": ev.get("host") or ev.get("host_ip"),
            "timestamp": event_timestamp(ev),
            "listener_port": ev.get("listener_port"),
            "listener_process": ev.get("listener_process"),
            "listener_pid": ev.get("listener_pid"),
            "dst_ip": ev.get("dst_ip"),
            "dst_port": ev.get("dst_port"),
            "matched_rules": matched,
            "risk_tags": tags,
            "recommended_action": connect_action(severity),
            "summary": build_connect_summary(ev, severity, matched),
            "evidence_refs": [ev.get("evidence_id")] if ev.get("evidence_id") else [],
        }
        items.append(item)
    return items


def dedupe_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, ...], dict[str, Any]] = {}
    for it in items:
        refs = it.get("evidence_refs") or []
        sig = (
            str(it.get("risk_module")),
            str(it.get("host")),
            str(refs[0] if refs else it.get("timestamp") or ""),
            str(it.get("listener_pid") or it.get("listener_port") or ""),
        )
        existing = merged.get(sig)
        if existing is None:
            merged[sig] = dict(it)
            continue
        existing_rank = SEVERITY_RANK.get(str(existing.get("severity") or "P3"), 99)
        new_rank = SEVERITY_RANK.get(str(it.get("severity") or "P3"), 99)
        keep, drop = (it, existing) if new_rank < existing_rank else (existing, it)
        combined_rules = list(dict.fromkeys(list(keep.get("matched_rules") or []) + list(drop.get("matched_rules") or [])))
        keep = dict(keep)
        keep["matched_rules"] = combined_rules
        merged[sig] = keep
    return list(merged.values())


def overall_verdict(items: list[dict[str, Any]], *, scanned: int, blocked: bool) -> str:
    if blocked and not items:
        return "insufficient_data"
    if not items:
        return "no_risk_detected"
    alerting = [
        it
        for it in items
        if it.get("alert_required", True) and not it.get("alert_suppressed")
    ]
    if any(it.get("severity") in ("P0", "P1") for it in alerting):
        return "high_risk_detected"
    if alerting:
        return "low_risk_only"
    if any(it.get("severity") in ("P0", "P1", "P2") for it in items):
        return "low_risk_only"
    return "no_risk_detected"


def recommended_next(items: list[dict[str, Any]], bundles: dict[str, list]) -> list[dict[str, str]]:
    """Optional downstream hints (not traceability — use traceability-analysis separately)."""
    recs: list[dict[str, str]] = []
    alerting = [
        it
        for it in items
        if it.get("alert_required", True) and not it.get("alert_suppressed")
    ]
    p0 = sum(1 for it in alerting if it.get("severity") == "P0")
    if p0 >= 1 and bundles.get("waf_alert"):
        recs.append({"skill": "alert-confirmation", "reason": "存在主机高危行为且同窗有 WAF 告警，建议互证"})
    return recs


def markdown_report(result: dict[str, Any]) -> str:
    lines = [
        "# Risk Identification Report",
        "",
        f"- **Scenario**: {result.get('scenario')}",
        f"- **Verdict**: {result.get('overall_verdict')}",
        f"- **Coverage**: {result.get('coverage_level', 'unknown')}",
        f"- **Events scanned**: {result.get('summary', {}).get('total_events_scanned', 0)}",
        f"- **Risk items**: {result.get('summary', {}).get('risk_items', 0)} "
        f"(P0={result.get('summary', {}).get('p0', 0)}, "
        f"P1={result.get('summary', {}).get('p1', 0)}, "
        f"alerting={result.get('summary', {}).get('alert_required', 0)})",
        f"- **Top incidents**: {result.get('summary', {}).get('top_incidents', 0)}",
        "",
    ]
    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    from fetch_summary import format_fetch_summary_markdown  # noqa: E402

    if result.get("fetch_summary"):
        lines.append(format_fetch_summary_markdown(result["fetch_summary"]))
        lines.append("")
    if result.get("user_reminders"):
        lines.append("## Data source reminders")
        for rem in result["user_reminders"]:
            lines.append(f"- {rem}")
        lines.append("")
    if result.get("data_source_status"):
        lines.append("## Data source status")
        for key, st in result["data_source_status"].items():
            if st.get("status") == "present_not_used":
                continue
            lines.append(
                f"- **{st.get('label', key)}** (`{key}`): {st.get('status')} "
                f"events={st.get('event_count', 0)}"
            )
        lines.append("")
    unavailable = (result.get("risk_coverage") or {}).get("unavailable_rules") or []
    missing_src = [u for u in unavailable if u.get("missing_sources")]
    if missing_src:
        lines.append("## Risks not detectable due to missing sources")
        for u in missing_src[:12]:
            lines.append(f"- {u.get('label')} (`{u.get('rule_id')}`): {u.get('reason')}")
        lines.append("")
    if result.get("data_gaps"):
        lines.append("## Data gaps")
        for gap in result["data_gaps"]:
            lines.append(f"- {gap}")
        lines.append("")
    if result.get("policy_hits"):
        lines.append("## Behavior policy hits")
        for hit in result["policy_hits"][:10]:
            lines.append(
                f"- `{hit.get('rule_id')}` [{hit.get('tier')}] {hit.get('action')}: "
                f"{hit.get('reason')} risk={hit.get('risk_id')} "
                f"{hit.get('original_severity')}→{hit.get('final_severity')}"
            )
        lines.append("")
    if result.get("whitelist_hits"):
        lines.append("## Whitelist hits")
        for hit in result["whitelist_hits"][:10]:
            lines.append(
                f"- `{hit.get('rule_id')}` {hit.get('action')}: {hit.get('reason')} "
                f"risk={hit.get('risk_id')}"
            )
        lines.append("")
    if result.get("top_incidents"):
        lines.append("## Top incidents")
        for inc in result["top_incidents"]:
            count = inc.get("event_count", 1)
            repeat = f" x{count}" if count and count > 1 else ""
            lines.append(
                f"- **{inc.get('severity')}** [{inc.get('risk_module')}] "
                f"`{inc.get('policy_rule_id')}` {inc.get('host')}{repeat} — {inc.get('summary')}"
            )
            attck = format_mitre_attack_short(inc.get("mitre_attack"))
            if attck:
                lines.append(f"  - ATT&CK: {attck}")
        lines.append("")
    elif result.get("risk_items"):
        lines.append("## Top risks")
        for it in result.get("risk_items", [])[:10]:
            lines.append(
                f"- **{it.get('severity')}** [{it.get('risk_module')}] {it.get('host')} — {it.get('summary')}"
            )
            attck = format_mitre_attack_short(it.get("mitre_attack"))
            if attck:
                lines.append(f"  - ATT&CK: {attck}")
        lines.append("")
    if result.get("recommended_next_skills"):
        lines.append("")
        lines.append("## Recommended next skills")
        for r in result["recommended_next_skills"]:
            lines.append(f"- `{r.get('skill')}`: {r.get('reason')}")
    return "\n".join(lines)


def configure_detection_rules(payload: dict[str, Any]) -> dict[str, Any]:
    """Load ops-editable JSON rule packs (optional paths in payload.detection_rules)."""
    cfg = payload.get("detection_rules") or {}
    if cfg.get("rules_dir"):
        configure_rules_dir(cfg["rules_dir"])
    exec_path = cfg.get("exec")
    connect_path = cfg.get("connect")
    dns_path = cfg.get("dns")
    ssh_path = cfg.get("ssh")
    syslog_path = cfg.get("syslog")
    persistence_path = cfg.get("persistence")
    attck_path = cfg.get("attck")
    configure_exec_rules(exec_path)
    configure_connect_rules(connect_path)
    configure_dns_rules(dns_path)
    configure_persistence_rules(persistence_path)
    configure_ssh_rules(ssh_path)
    configure_syslog_rules(syslog_path)
    configure_attck_map(attck_path)
    return {
        "rules_dir": report_path(get_rules_dir()),
        "exec": report_path(exec_path or rule_file("exec-rules.json")),
        "connect": report_path(connect_path or rule_file("connect-rules.json")),
        "dns": report_path(dns_path or rule_file("dns-rules.json")),
        "persistence": report_path(persistence_path or rule_file("persistence-rules.json")),
        "ssh": report_path(ssh_path or rule_file("ssh-rules.json")),
        "syslog": report_path(syslog_path or rule_file("syslog-rules.json")),
        "attck": report_path(attck_path or rule_file("attck-map.json")),
    }


def dedupe_source_bundles(bundles: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Deduplicate native replays before thresholds, retaining the first reference.

    Legacy exports can have distinct generated evidence IDs for the same source
    record. Preserve every discarded reference in the audit mapping; never merge
    anonymous events on weak host/time keys. Work on new lists, not caller data.
    """
    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    from normalizer import source_event_digest

    out, audit = {}, {}
    for kind, events in bundles.items():
        retained, seen, aliases = [], {}, []
        for event in events:
            key = source_event_digest({"asset_type": kind}, event)
            if key and key in seen:
                aliases.append({"retained_evidence_id": seen[key].get("evidence_id"),
                                "duplicate_evidence_id": event.get("evidence_id")})
                continue
            if key:
                seen[key] = event
            retained.append(event)
        out[kind] = retained
        audit[kind] = {"input_count": len(events), "retained_count": len(retained),
                       "duplicates_removed": len(aliases), "aliases": aliases}
    return out, audit


def assess(payload: dict[str, Any], catalog: dict[str, Any]) -> dict[str, Any]:
    """Assess source-unique events and current query integrity before policy."""
    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    from fetch_summary import attach_fetch_summary

    # Reconcile stale pre-fetch state in offline exports without mutating input.
    payload = attach_fetch_summary(dict(payload))
    detection_rules_meta = configure_detection_rules(payload)
    scenario = payload.get("scenario") or "S5"
    params = payload.get("params") or {}
    severity_floor = params.get("severity_floor") or "P3"
    user_rules = payload.get("user_rules") or {}
    precheck = payload.get("completeness_precheck")
    ceiling = confidence_ceiling(precheck)
    modules = scenario_modules(scenario, catalog, payload.get("risk_modules"))

    bundles, evidence_deduplication = dedupe_source_bundles(payload.get("evidence_bundles") or {})
    blocked, block_reason = hard_blocked(precheck, bundles)
    warnings: list[str] = []
    deprecated_whitelist_keys = [
        key for key in ("whitelist_ports", "whitelist_exe_prefixes", "dst_cidrs") if key in user_rules
    ]
    if deprecated_whitelist_keys:
        warnings.append(
            "user_rules 白名单字段 "
            + ", ".join(deprecated_whitelist_keys)
            + " 已废弃，请统一维护 src/skills/risk-identification/whitelist.json"
        )
    precheck_gaps: list[str] = list(precheck.get("data_gaps") or [] if precheck else [])

    exec_raw = filter_events(list(bundles.get("host_exec") or []), params)
    connect_raw = filter_events(list(bundles.get("host_connect") or []), params)
    dns_raw = filter_dns_events(list(bundles.get("dns_log") or []), params)
    file_raw = filter_events(list(bundles.get("host_file_op") or []), params)
    persistence_raw = filter_persistence_events(list(bundles.get("host_persistence") or []), params)
    ssh_raw = filter_ssh_events_for_hosts(bundles, params)
    syslog_raw = filter_syslog_events(list(bundles.get("syslog_risk_alert") or []), params)

    coverage = evaluate_source_coverage(
        bundles,
        scenario=scenario,
        modules=modules,
        raw_counts={
            "host_exec": len(exec_raw),
            "host_connect": len(connect_raw),
            "dns_log": len(dns_raw),
            "host_file_op": len(file_raw),
            "host_persistence": len(persistence_raw),
            "ssh_auth": len(ssh_raw),
            "syslog_risk_alert": len(syslog_raw),
            "waf_alert": len(bundles.get("waf_alert") or []),
        },
    )
    data_gaps: list[str] = precheck_gaps + coverage["data_gaps"]
    user_reminders: list[str] = list(coverage["user_reminders"])

    if blocked:
        if block_reason and block_reason not in data_gaps:
            data_gaps.append(block_reason)
        blocked_result = {
            "skill": "risk-identification",
            "scenario": scenario,
            "overall_verdict": "insufficient_data",
            "coverage_level": "insufficient",
            "params": params,
            "summary": {"total_events_scanned": 0, "risk_items": 0, "p0": 0, "p1": 0, "p2": 0, "p3": 0},
            "risk_items": [],
            "data_gaps": data_gaps,
            "user_reminders": user_reminders,
            "data_source_status": coverage["data_source_status"],
            "risk_coverage": coverage["risk_coverage"],
            "scenario_requirements": coverage["scenario_requirements"],
            "risk_modules_run": [],
            "warnings": warnings,
            "recommended_next_skills": [],
        }
        if str(DATA_ACCESS_PATH) not in sys.path:
            sys.path.insert(0, str(DATA_ACCESS_PATH))
        from fetch_summary import enrich_result_with_fetch_summary  # noqa: E402

        enrich_result_with_fetch_summary(blocked_result, payload)
        blocked_result["markdown_report"] = markdown_report(blocked_result)
        return blocked_result

    scanned = len(exec_raw) + len(connect_raw) + len(dns_raw) + len(persistence_raw) + len(ssh_raw) + len(syslog_raw)

    items: list[dict[str, Any]] = []
    ssh_brute_waves: list[dict[str, Any]] = []
    modules_run: list[str] = []

    exec_source_ok = _source_available(coverage["data_source_status"], "host_exec")
    connect_source_ok = _source_available(coverage["data_source_status"], "host_connect")
    dns_source_ok = _source_available(coverage["data_source_status"], "dns_log")
    persistence_source_ok = _source_available(coverage["data_source_status"], "host_persistence")
    ssh_source_ok = _source_available(coverage["data_source_status"], "ssh_auth")
    syslog_source_ok = _source_available(coverage["data_source_status"], "syslog_risk_alert")

    if "exec" in modules:
        if exec_source_ok:
            modules_run.append("exec")
            items.extend(
                assess_exec_module(
                    exec_raw,
                    connects=connect_raw,
                    file_ops=file_raw,
                    persistence_events=persistence_raw,
                    ceiling=ceiling,
                    severity_floor=severity_floor,
                    warnings=warnings,
                )
            )
        elif "exec" in modules and not any("exec 模块未运行" in r for r in user_reminders):
            user_reminders.append(
                "exec 模块未运行：host_exec 缺失或时间窗内无事件，命令类风险全部漏检"
            )

    if "connect" in modules:
        if connect_source_ok:
            modules_run.append("connect")
            items.extend(
                assess_connect_module(
                    connect_raw,
                    exec_events=exec_raw,
                    ceiling=ceiling,
                    severity_floor=severity_floor,
                    warnings=warnings,
                )
            )
        elif "connect" in modules and not any("connect 模块未运行" in r for r in user_reminders):
            user_reminders.append(
                "connect 模块未运行：host_connect 缺失或时间窗内无事件，外连类风险全部漏检"
            )

    if "dns" in modules:
        if dns_source_ok or connect_raw:
            modules_run.append("dns")
            if not dns_source_ok and connect_raw and not any("DNS 查询画像" in r for r in user_reminders):
                user_reminders.append(
                    "dns 模块仅运行 DoH/DoT 外连检查：dns_log 缺失或时间窗内无查询事件，"
                    "NXDOMAIN/DGA/非常见 TLD/DNS 隧道画像不可用"
                )
            items.extend(
                assess_dns_events(
                    dns_raw,
                    connect_events=connect_raw,
                    ceiling=ceiling,
                    severity_floor=severity_floor,
                    warnings=warnings,
                )
            )
        elif not any("dns 模块未运行" in r for r in user_reminders):
            user_reminders.append(
                "dns 模块未运行：dns_log 与可用于 DoH/DoT 检查的 host_connect 均缺失，"
                "NXDOMAIN/DGA/非常见 TLD/DNS 隧道画像无法检测"
            )

    if "persistence" in modules:
        if persistence_source_ok:
            modules_run.append("persistence")
            items.extend(
                assess_persistence_events(
                    persistence_raw,
                    ceiling=ceiling,
                    severity_floor=severity_floor,
                    warnings=warnings,
                )
            )
        elif not any("persistence 模块未运行" in r for r in user_reminders):
            user_reminders.append(
                "persistence 模块未运行：host_persistence 缺失或时间窗内无事件，"
                "cron/systemd/authorized_keys 等持久化变更无法检测"
            )

    if "ssh" in modules:
        if ssh_source_ok or ssh_raw:
            modules_run.append("ssh")
            brute_threshold = int((params.get("ssh_brute_threshold") or 10))
            brute_window = int((params.get("ssh_brute_window_sec") or 300))
            ssh_items, ssh_brute_waves = assess_ssh_bruteforce(
                ssh_raw,
                ceiling=ceiling,
                severity_floor=severity_floor,
                window_sec=brute_window,
                threshold=brute_threshold,
            )
            items.extend(ssh_items)
        elif "ssh" in modules and not any("ssh 模块未运行" in r for r in user_reminders):
            user_reminders.append(
                "ssh 模块未运行：ssh_auth（tigersec-sys-messages）缺失或时间窗内无认证失败事件，"
                "SSH 暴力破解无法检测"
            )

    if "syslog" in modules:
        if syslog_source_ok or syslog_raw:
            modules_run.append("syslog")
            items.extend(
                assess_syslog_events(
                    syslog_raw,
                    ceiling=ceiling,
                    severity_floor=severity_floor,
                    warnings=warnings,
                )
            )
        elif not any("syslog 模块未运行" in r for r in user_reminders):
            user_reminders.append(
                "syslog 模块未运行：syslog_risk_alert 缺失或时间窗内无事件，"
                "sudo/建号/防火墙等 syslog 风险无法检测"
            )

    items = dedupe_items(items)

    policy_cfg = payload.get("behavior_policy") or {}
    policy_enabled = policy_cfg.get("enabled", True)
    policy_path_raw = policy_cfg.get("path")
    policy_path = Path(policy_path_raw) if policy_path_raw else DEFAULT_POLICY_PATH
    rules_path_raw = policy_cfg.get("rules_path")
    rules_path = Path(rules_path_raw) if rules_path_raw else None
    items, policy_hits, policy_meta = apply_behavior_policy(
        items,
        policy_path=policy_path,
        rules_path=rules_path,
        enabled=policy_enabled,
    )

    whitelist_hits: list[dict[str, Any]] = []
    whitelist_meta: dict[str, Any] = {
        "enabled": not whitelist_disabled(payload, policy_cfg),
        "applied": False,
        "path": report_path(DEFAULT_WHITELIST_PATH),
        "hits": 0,
    }
    if whitelist_meta["enabled"]:
        whitelist_config = resolve_whitelist_config(payload, policy_cfg)
        if whitelist_config is not None and (whitelist_config.get("defaults") or {}).get("enabled", True):
            whitelist_meta["applied"] = True
            items, whitelist_hits = apply_whitelist(items, whitelist_config)
            whitelist_meta["hits"] = len(whitelist_hits)

    apply_mitre_attack(items, get_attck_map())

    incident_top_n, incident_alerting_only = incidents_from_params(params)
    top_incidents = aggregate_incidents(
        items,
        top_n=incident_top_n,
        alerting_only=incident_alerting_only,
    )
    verdict = overall_verdict(items, scanned=scanned, blocked=False)
    coverage_level = coverage["coverage_level"]
    if verdict == "no_risk_detected" and coverage_level == "insufficient":
        verdict = "insufficient_data"

    sev_counts = Counter(it.get("severity") for it in items)
    tag_counts = Counter(tag for it in items for tag in it.get("risk_tags") or [])
    attck_counts = Counter(
        tid for it in items for tid in (it.get("mitre_attack") or {}).get("technique_ids") or []
    )

    alert_required_count = sum(
        1 for it in items if it.get("alert_required", True) and not it.get("alert_suppressed")
    )
    alert_suppressed_count = sum(1 for it in items if it.get("alert_suppressed"))

    result = {
        "skill": "risk-identification",
        "scenario": scenario,
        "overall_verdict": verdict,
        "coverage_level": coverage_level,
        "params": params,
        "summary": {
            "total_events_scanned": scanned,
            "risk_items": len(items),
            "p0": sev_counts.get("P0", 0),
            "p1": sev_counts.get("P1", 0),
            "p2": sev_counts.get("P2", 0),
            "p3": sev_counts.get("P3", 0),
            "alert_required": alert_required_count,
            "alert_suppressed": alert_suppressed_count,
            "policy_hits": len(policy_hits),
            "top_incidents": len(top_incidents),
            "ssh_brute_waves": len(ssh_brute_waves),
            "top_hosts": list({it.get("host") for it in items if it.get("host")})[:5],
            "top_risk_tags": [t for t, _ in tag_counts.most_common(5)],
            "top_mitre_techniques": [t for t, _ in attck_counts.most_common(8)],
        },
        "risk_items": items,
        "evidence_deduplication": evidence_deduplication,
        "behavior_policy": policy_meta,
        "whitelist": whitelist_meta,
        "detection_rules": detection_rules_meta,
        "policy_hits": policy_hits,
        "top_incidents": top_incidents,
        "ssh_brute_waves": ssh_brute_waves,
        "whitelist_hits": whitelist_hits,
        "data_gaps": data_gaps,
        "user_reminders": user_reminders,
        "data_source_status": coverage["data_source_status"],
        "risk_coverage": coverage["risk_coverage"],
        "scenario_requirements": coverage["scenario_requirements"],
        "risk_modules_run": modules_run,
        "warnings": warnings,
        "completeness_precheck": precheck,
        "recommended_next_skills": recommended_next(items, bundles),
    }
    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    from fetch_summary import enrich_result_with_fetch_summary  # noqa: E402

    enrich_result_with_fetch_summary(result, payload)
    result["markdown_report"] = markdown_report(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="SecWeaver 风险识别")
    parser.add_argument("-i", "--input", help="输入 JSON 文件")
    parser.add_argument("-o", "--output", help="输出 JSON 文件")
    parser.add_argument("--scenarios", default=str(SCENARIOS_PATH))
    parser.add_argument(
        "--behavior-policy",
        default=str(DEFAULT_POLICY_PATH),
        help="behavior-policy.md 路径（自然语言告警策略）",
    )
    parser.add_argument(
        "--behavior-policy-rules",
        help="behavior-policy.rules.json 路径（CLI 策略规则包）",
    )
    parser.add_argument(
        "--no-behavior-policy",
        action="store_true",
        help="跳过 behavior-policy 告警层",
    )
    parser.add_argument(
        "--no-whitelist",
        action="store_true",
        help="跳过 whitelist.json 环境白名单层（默认开启）",
    )
    parser.add_argument(
        "--legacy-whitelist",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    # Payload adaptation belongs to the upper runtime, not the fetch layer.
    sys.path.insert(0, str(DATA_ACCESS_PATH.parent))
    from skill_runtime.contracts import ensure_skill_envelope  # noqa: E402
    from skill_runtime.inputs import add_bundle_arguments, build_risk_payload, load_input_payload  # noqa: E402

    add_bundle_arguments(parser, "risk")
    args = parser.parse_args()

    catalog = load_scenarios(Path(args.scenarios))
    try:
        payload = load_input_payload(args, "risk", build_risk_payload)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 1

    policy_cfg = dict(payload.get("behavior_policy") or {})
    if args.no_behavior_policy:
        policy_cfg["enabled"] = False
    if args.behavior_policy:
        policy_cfg.setdefault("path", args.behavior_policy)
    if args.behavior_policy_rules:
        policy_cfg.setdefault("rules_path", args.behavior_policy_rules)
    if args.no_whitelist:
        policy_cfg["no_whitelist"] = True
    if policy_cfg:
        payload["behavior_policy"] = policy_cfg

    result = assess(payload, catalog)
    ensure_skill_envelope(result, "risk-identification")
    out = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
