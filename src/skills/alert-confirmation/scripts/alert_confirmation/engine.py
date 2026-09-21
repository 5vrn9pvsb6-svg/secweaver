"""Alert-confirmation analysis orchestration."""

from __future__ import annotations

import sys
from collections import Counter
from typing import Any

from .common import text_blob
from .gateway import find_gateway_access_coverage, find_gateway_success_hint, scan_gateway_misses
from .layer1 import detect_attack_type, layer1_verdict, upgrade_layer1_verdict
from .paths import DATA_ACCESS_PATH
from .report import batch_summary, count_repeats
from .success import (
    apply_ip_block_guard,
    build_analyst_questions,
    build_summary,
    compute_confidence,
    effective_confidence_ceiling,
    find_campaign_success,
    find_d2_success,
    has_d2_data,
    layer2_outcome,
    recommended_action,
    confirmation_mode,
)
from .url_match import _alert_request_method


def _resolve_attacker_ip(alerts: list[dict], params: dict | None) -> str | None:
    for key in ("attacker_ip", "src_ip", "ip", "client_ip"):
        value = (params or {}).get(key)
        if value not in (None, "", "-"):
            return str(value)
    counter: Counter[str] = Counter()
    for alert in alerts:
        value = alert.get("src_ip") or alert.get("ip") or alert.get("client_ip")
        if value not in (None, "", "-"):
            counter[str(value)] += 1
    if counter:
        return counter.most_common(1)[0][0]
    return None


def _provided_attacker_ip_profile(payload: dict, params: dict | None, attacker_ip: str | None) -> dict | None:
    profile = payload.get("attacker_ip_profile") or (params or {}).get("attacker_ip_profile")
    if not isinstance(profile, dict):
        return None
    out = dict(profile)
    if attacker_ip:
        out.setdefault("ip", attacker_ip)
    if "verified" not in out:
        online = out.get("online_lookup") or {}
        out["verified"] = online.get("status") == "success"
    return out


def _build_attacker_ip_profile(
    payload: dict,
    alerts: list[dict],
    evidence: dict,
    params: dict | None,
) -> dict | None:
    attacker_ip = _resolve_attacker_ip(alerts, params)
    provided = _provided_attacker_ip_profile(payload, params, attacker_ip)
    if provided:
        return provided
    if not attacker_ip or (params or {}).get("resolve_attacker_ip_profile") is False:
        return None

    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    try:
        from attacker_ip_intel import build_attacker_ip_profile
    except Exception:
        return None

    bundles = dict(evidence)
    bundles["waf_alert"] = list(alerts)
    online_intel = payload.get("ip_intel_online")
    if online_intel is None:
        online_intel = (params or {}).get("ip_intel_online") is True
    try:
        profile = build_attacker_ip_profile(
            attacker_ip,
            bundles,
            params,
            online_lookup=bool(online_intel),
        )
    except Exception as exc:
        return {
            "ip": attacker_ip,
            "scope": "unknown",
            "online_lookup": {"status": "lookup_failed", "error": str(exc)},
            "attributes": [],
            "summary": None,
        }
    if profile and profile.get("online_lookup") is None:
        profile["online_lookup"] = {
            "status": "not_attempted",
            "reason": "ip_intel_online_not_enabled",
        }
    return profile


def confirm_alert(
    alert: dict,
    evidence: dict,
    precheck: dict | None,
    attack_catalog: dict,
    fp_catalog: dict,
    repeat_count: int = 1,
    scenario: str = "S4",
    params: dict | None = None,
    gateway_miss_scan: dict[str, Any] | None = None,
    campaign_success: dict[str, Any] | None = None,
    attacker_ip_profile: dict[str, Any] | None = None,
) -> dict:
    mode = confirmation_mode(precheck)
    text = text_blob(alert)
    rule_name = alert.get("rule_name") or ""

    attack_type, attack_label, matched, technique = detect_attack_type(text, rule_name, attack_catalog)
    alert_verdict, payload_analysis = layer1_verdict(alert, text, attack_type, matched, fp_catalog)

    if payload_analysis.get("technique") not in ("unknown", "benign_business", "generic_rule", "scanner_probe"):
        payload_analysis["technique"] = technique if technique != "unknown" else payload_analysis.get("technique")

    success_refs, supporting_refs, success_indicator = find_d2_success(
        alert, evidence, attack_catalog, params=params, attack_type=attack_type
    )
    attack_outcome, attack_success = layer2_outcome(
        alert_verdict, alert, evidence, success_refs, mode, attack_catalog
    )

    alert_verdict, attack_type, attack_label, matched, payload_analysis, layer1_upgrade = upgrade_layer1_verdict(
        alert_verdict,
        attack_type,
        attack_label,
        matched,
        payload_analysis,
        attack_outcome=attack_outcome,
        success_refs=success_refs,
        success_indicator=success_indicator,
        gateway_miss_scan=gateway_miss_scan,
        catalog=attack_catalog,
    )

    ceiling = effective_confidence_ceiling(
        precheck,
        attack_outcome,
        success_refs,
        alert_verdict,
        attack_catalog,
    )

    gateway_hint = find_gateway_success_hint(
        alert,
        evidence,
        attack_type=attack_type,
        alert_verdict=alert_verdict,
        attack_success=attack_success,
        catalog=attack_catalog,
        params=params,
    )
    gateway_coverage = find_gateway_access_coverage(alert, evidence, params=params)

    data_gaps: list[str] = list((precheck or {}).get("data_gaps") or [])
    if gateway_coverage.get("status") == "missing":
        data_gaps.append(gateway_coverage.get("message") or "WAF 有告警但缺少对应网关访问日志，需补数据")
    if not has_d2_data(evidence):
        data_gaps.append("无 host_exec/connect/file_op/host_persistence，无法确认是否打穿或留驻")
    if not (alert.get("payload") or "").strip():
        data_gaps.append("告警缺少 payload 字段")

    conf = compute_confidence(alert_verdict, attack_outcome, payload_analysis.get("validity", ""), ceiling)
    rec_action, rec_label = recommended_action(
        alert_verdict,
        attack_outcome,
        repeat_count,
        attack_catalog,
        gateway_hint=gateway_hint,
    )

    next_skill = None
    next_reason = ""
    if attack_outcome == "success_confirmed":
        next_skill = "traceability_analysis"
        next_reason = "已确认攻击成功，建议启动溯源分析"
    elif not has_d2_data(evidence) and alert_verdict in ("confirmed_attack", "suspicious"):
        next_reason = "建议接入 host_exec/host_persistence 或先运行数据源完整性分析"

    alert_id = alert.get("alert_id") or alert.get("id") or "unknown"
    method = _alert_request_method(alert)
    matched_rules = []
    if matched:
        matched_rules.append(f"{attack_type}_pattern_match")
    if layer1_upgrade:
        matched_rules.append(f"layer1_upgrade:{layer1_upgrade.get('reason')}")
    if alert_verdict == "false_positive":
        matched_rules.append("fp_pattern")

    if attack_outcome == "success_confirmed":
        rec_action = "escalate_investigate"
        rec_label = "升级调查，建议隔离受害主机"
    rec_action, rec_label, ip_action_guard = apply_ip_block_guard(
        rec_action,
        rec_label,
        attacker_ip_profile,
    )

    join_edges: list[dict] = []
    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    try:
        from correlation_engine import correlate_bundles, find_join_pairs, parse_ts

        bundles = dict(evidence)
        bundles.setdefault("waf_alert", [alert])
        anchor_ts = parse_ts(alert.get("timestamp"))
        for join_id in (
            "d2_exec_connect_same_listener",
            "d2_exec_file_same_host",
            "d2_exec_persistence_same_host",
            "web_access_to_host_exec",
            "web_access_to_host_persistence",
            "waf_to_host_persistence_direct",
        ):
            join_edges.extend(find_join_pairs(join_id, bundles, anchor_ts=anchor_ts, limit=20))
        if not join_edges:
            corr = correlate_bundles(
                bundles,
                anchor_pattern_id="S4_alert_confirmation",
                params={"attacker_ip": alert.get("src_ip"), "alert_time": alert.get("timestamp")},
            )
            join_edges = corr.get("join_edges") or []
    except Exception:
        join_edges = []

    analyst_questions = build_analyst_questions(
        alert_verdict, attack_outcome, has_d2_data(evidence), gateway_hint=gateway_hint
    )
    if gateway_coverage.get("status") == "missing":
        analyst_questions.append("请补充对应时间段的网关访问日志，至少包含 src_ip、url/request_uri、method、timestamp、status/upstream_status 字段")
    if ip_action_guard and ip_action_guard.get("downgraded"):
        analyst_questions.append("封禁/拉黑前请确认攻击源 IP 是否为 NAT、移动网络、代理/VPN、CDN 或其他共享出口，避免误伤正常用户")

    return {
        "alert_type": "alert_confirmation",
        "alert_id": alert_id,
        "scenario": scenario,
        "timestamp": alert.get("timestamp") or alert.get("time") or alert.get("__time__"),
        "src_ip": alert.get("src_ip") or alert.get("ip"),
        "target_ip": alert.get("target_ip") or alert.get("upstream_addr") or (params or {}).get("target_ip"),
        "host": alert.get("host"),
        "url": alert.get("url"),
        "method": method or "GET",
        "rule_id": alert.get("rule_id"),
        "rule_name": alert.get("rule_name"),
        "confirmation_mode": mode,
        "alert_verdict": alert_verdict,
        "attack_type": attack_type,
        "attack_type_label": attack_label,
        "payload_analysis": payload_analysis,
        "layer1_upgrade": layer1_upgrade,
        "attack_outcome": attack_outcome,
        "attack_success": attack_success,
        "confidence": conf,
        "confidence_ceiling": ceiling,
        "waf_action": alert.get("action"),
        "summary": build_summary(
            alert_verdict,
            attack_label,
            attack_outcome,
            payload_analysis.get("notes", ""),
            alert.get("action") or "",
            gateway_hint=gateway_hint,
        ),
        "gateway_success_hint": gateway_hint,
        "gateway_access_coverage": gateway_coverage,
        "gateway_miss_scan": gateway_miss_scan,
        "alert_success": {
            "scope": "alert",
            "attack_success": attack_success,
            "attack_outcome": attack_outcome,
            "evidence_refs": success_refs,
            "indicator": success_indicator,
        },
        "campaign_success": campaign_success,
        "attacker_ip_profile": attacker_ip_profile,
        "ip_action_guard": ip_action_guard,
        "evidence": {
            "alert": [alert_id],
            "supporting": supporting_refs,
            "success_proof": success_refs,
            "gateway_hint": (gateway_hint or {}).get("evidence_refs") or [],
            "false_positive_indicators": [payload_analysis.get("notes")] if alert_verdict == "false_positive" else [],
        },
        "matched_rules": matched_rules,
        "recommended_action": rec_action,
        "recommended_action_label": rec_label,
        "next_skill": next_skill,
        "next_skill_reason": next_reason,
        "data_gaps_impact": list(dict.fromkeys(data_gaps)),
        "join_edges": join_edges,
        "analyst_questions": list(dict.fromkeys(analyst_questions)),
    }


def analyze(payload: dict, attack_catalog: dict, fp_catalog: dict) -> dict | list:
    """Triage alerts and independently scan gateway evidence for missed alerts.

    Zero primary alerts is a valid observation, not a successful attack verdict
    or a transport error. Preserve an empty batch so the CLI can attach query
    statistics and gateway-only findings without inventing a primary alert.
    """
    precheck = payload.get("completeness_precheck")
    evidence = payload.get("correlated_evidence") or {}
    alerts = payload.get("primary_alerts") or []
    scenario = payload.get("scenario") or "S4"
    params = payload.get("params") or {}

    gateway_miss_scan = scan_gateway_misses(alerts, evidence, attack_catalog, params=params)
    attacker_ip_profile = _build_attacker_ip_profile(payload, alerts, evidence, params)
    campaign_success = find_campaign_success(
        evidence,
        attack_catalog,
        params=params,
        gateway_miss_scan=gateway_miss_scan,
    )
    repeats = count_repeats(alerts)
    results = []
    for alert in alerts:
        key = f"{alert.get('src_ip')}|{alert.get('rule_id')}"
        results.append(
            confirm_alert(
                alert,
                evidence,
                precheck,
                attack_catalog,
                fp_catalog,
                repeat_count=repeats.get(key, 1),
                scenario=scenario,
                params=params,
                gateway_miss_scan=gateway_miss_scan,
                campaign_success=campaign_success,
                attacker_ip_profile=attacker_ip_profile,
            )
        )

    if not results or payload.get("batch_mode") or len(results) > 1:
        return {
            **({"status": "no_primary_alerts", "attack_outcome": "not_applicable",
                "summary": "No primary alerts to triage; inspect query gaps and gateway findings before drawing conclusions."} if not results else {}),
            "results": results,
            "batch_summary": batch_summary(results, gateway_miss_scan),
            "gateway_miss_scan": gateway_miss_scan,
            "campaign_success": campaign_success,
            "attacker_ip_profile": attacker_ip_profile,
        }
    single = results[0]
    single["gateway_miss_scan"] = gateway_miss_scan
    single["campaign_success"] = campaign_success
    single["attacker_ip_profile"] = attacker_ip_profile
    return single
