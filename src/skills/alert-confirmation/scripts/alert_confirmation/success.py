"""Layer 2 success confirmation, confidence, action, and analyst prompts."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from .common import (
    _ts_epoch,
    alert_timestamp,
    attack_success_window,
    cmd_text,
    event_in_investigation_window,
    event_timestamp,
    host_matches_victim,
    in_correlation_window,
    investigation_time_bounds,
    victim_host_keys,
)
from .gateway import gateway_hint_recommended_action
from .layer1 import _layer1_upgrade_config
from .url_match import _normalize_http_status, _url_text, waf_alert_matches_request

_SHARED_EXIT_KEYWORDS = (
    "nat",
    "cg-nat",
    "cgnat",
    "共享",
    "shared",
    "移动网络",
    "mobile",
    "代理/vpn",
    "代理",
    "vpn",
    "proxy",
    "cdn",
    "云防护",
)

D2_EVIDENCE_KEYS = ("host_exec", "host_connect", "host_file_op", "host_persistence")


def find_d2_success(
    alert: dict,
    evidence: dict,
    catalog: dict,
    before_min: int | None = None,
    after_min: int | None = None,
    params: dict | None = None,
    attack_type: str = "unknown",
) -> tuple[list[str], list[str], str | None]:
    if before_min is None or after_min is None:
        default_before, default_after = attack_success_window()
        before_min = default_before if before_min is None else before_min
        after_min = default_after if after_min is None else after_min
    alert_ts = alert_timestamp(alert)
    web_logs = list(evidence.get("web_access_log") or [])
    success_web_contexts = _matching_success_web_events(alert, evidence, params, catalog)
    require_web_context = bool(web_logs)
    victim_keys = victim_host_keys(alert, params) | _web_target_keys(success_web_contexts)
    inv_start, inv_end = investigation_time_bounds(params)
    success_refs: list[str] = []
    supporting_refs: list[str] = []
    indicator: str | None = None
    indicators = catalog.get("success_indicators", {})

    def in_scope(ts: datetime | None, ev: dict | None = None) -> bool:
        if ts is None:
            return False
        if require_web_context:
            return _event_near_web_context(ev or {}, success_web_contexts, before_min, after_min)
        ts_epoch = _ts_epoch(ts)
        if ts_epoch is None:
            return False
        if alert_ts and in_correlation_window(ts, alert_ts, before_min, after_min):
            return True
        start_epoch = _ts_epoch(inv_start)
        end_epoch = _ts_epoch(inv_end)
        if start_epoch is not None and end_epoch is not None and start_epoch <= ts_epoch <= end_epoch:
            return True
        return False

    for ev in evidence.get("host_exec") or []:
        if not host_matches_victim(ev, victim_keys):
            continue
        ts = event_timestamp(ev)
        if not in_scope(ts, ev):
            continue
        text = cmd_text(ev).lower()
        ref = ev.get("evidence_id") or ev.get("_ref") or "exec-unknown"
        supporting_refs.append(ref)
        for category, keys in indicators.get("host_exec", {}).items():
            if any(str(k).lower() in text for k in keys):
                if not _indicator_compatible("host_exec", category, attack_type):
                    continue
                success_refs.append(ref)
                indicator = f"host_exec:{category}"
                break

    for ev in evidence.get("host_connect") or []:
        if not host_matches_victim(ev, victim_keys):
            continue
        ts = event_timestamp(ev)
        if not in_scope(ts, ev):
            continue
        ref = ev.get("evidence_id") or ev.get("_ref") or "connect-unknown"
        supporting_refs.append(ref)
        port = _int_or_none(ev.get("dst_port"))
        ports = {_int_or_none(p) for p in indicators.get("host_connect", {}).get("ports", [])}
        if port is not None and port in ports and _indicator_compatible("host_connect", "outbound", attack_type):
            success_refs.append(ref)
            indicator = indicator or "host_connect:outbound"

    for ev in evidence.get("host_file_op") or []:
        if not host_matches_victim(ev, victim_keys):
            continue
        ts = event_timestamp(ev)
        if not in_scope(ts, ev):
            continue
        path = _file_op_text(ev)
        ref = ev.get("evidence_id") or ev.get("_ref") or "file-unknown"
        supporting_refs.append(ref)
        file_category = _host_file_indicator(ev, indicators.get("host_file_op", {}))
        if file_category and _indicator_compatible("host_file_op", file_category, attack_type):
            success_refs.append(ref)
            indicator = indicator or f"host_file_op:{file_category}"

    for ev in evidence.get("host_persistence") or []:
        if not host_matches_victim(ev, victim_keys):
            continue
        ts = event_timestamp(ev)
        if not in_scope(ts, ev):
            continue
        ref = ev.get("evidence_id") or ev.get("_ref") or "persistence-unknown"
        supporting_refs.append(ref)
        category = _host_persistence_indicator(ev, indicators.get("host_persistence", {}))
        if category and _indicator_compatible("host_persistence", category, attack_type):
            success_refs.append(ref)
            indicator = indicator or f"host_persistence:{category}"

    for ev in evidence.get("web_access_log") or []:
        if alert.get("src_ip") and ev.get("src_ip") != alert.get("src_ip"):
            continue
        ts = event_timestamp(ev)
        if alert_ts and not in_correlation_window(ts, alert_ts, 10, 10):
            continue
        ref = ev.get("evidence_id") or ev.get("_ref") or "web-unknown"
        supporting_refs.append(ref)

    return list(dict.fromkeys(success_refs)), list(dict.fromkeys(supporting_refs)), indicator


def find_campaign_success(
    evidence: dict,
    catalog: dict,
    params: dict | None = None,
    gateway_miss_scan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Activity-level success signal, separate from per-alert success."""
    indicators = catalog.get("success_indicators", {})
    victim_keys, attribution = _campaign_d2_attribution(evidence, params)
    d2_present = any(evidence.get(key) for key in D2_EVIDENCE_KEYS)
    success_refs: list[str] = []
    supporting_refs: list[str] = []
    uncorrelated_refs: list[str] = []
    indicator_hits: list[str] = []

    def in_scope(ev: dict) -> bool:
        return event_in_investigation_window(ev, params)

    def correlated(ev: dict) -> bool:
        if not victim_keys:
            return False
        return host_matches_victim(ev, victim_keys)

    if d2_present and not victim_keys:
        uncorrelated_refs.extend(_scoped_d2_refs(evidence, params))

    for ev in evidence.get("host_exec") or []:
        if not in_scope(ev):
            continue
        if not correlated(ev):
            continue
        text = cmd_text(ev).lower()
        ref = ev.get("evidence_id") or ev.get("_ref") or "exec-unknown"
        supporting_refs.append(ref)
        for category, keys in indicators.get("host_exec", {}).items():
            if any(str(k).lower() in text for k in keys):
                success_refs.append(ref)
                indicator_hits.append(f"host_exec:{category}")
                break

    for ev in evidence.get("host_connect") or []:
        if not in_scope(ev):
            continue
        if not correlated(ev):
            continue
        ref = ev.get("evidence_id") or ev.get("_ref") or "connect-unknown"
        supporting_refs.append(ref)
        port = _int_or_none(ev.get("dst_port"))
        ports = {_int_or_none(p) for p in indicators.get("host_connect", {}).get("ports", [])}
        if port is not None and port in ports:
            success_refs.append(ref)
            indicator_hits.append("host_connect:outbound")

    for ev in evidence.get("host_file_op") or []:
        if not in_scope(ev):
            continue
        if not correlated(ev):
            continue
        ref = ev.get("evidence_id") or ev.get("_ref") or "file-unknown"
        supporting_refs.append(ref)
        category = _host_file_indicator(ev, indicators.get("host_file_op", {}))
        if category:
            success_refs.append(ref)
            indicator_hits.append(f"host_file_op:{category}")

    for ev in evidence.get("host_persistence") or []:
        if not in_scope(ev):
            continue
        if not correlated(ev):
            continue
        ref = ev.get("evidence_id") or ev.get("_ref") or "persistence-unknown"
        supporting_refs.append(ref)
        category = _host_persistence_indicator(ev, indicators.get("host_persistence", {}))
        if category:
            success_refs.append(ref)
            indicator_hits.append(f"host_persistence:{category}")

    miss_items = (gateway_miss_scan or {}).get("items") or []
    related_misses = [
        item.get("evidence_ref")
        for item in miss_items
        if item.get("evidence_ref") and item.get("severity") in {"critical", "high"}
    ]
    confirmed = bool(success_refs)
    uncorrelated_unique = list(dict.fromkeys(uncorrelated_refs))
    return {
        "scope": "campaign",
        "attack_success": confirmed,
        "attack_outcome": "success_confirmed" if confirmed else "success_unknown",
        "evidence_refs": list(dict.fromkeys(success_refs)),
        "supporting_refs": list(dict.fromkeys(supporting_refs)),
        "uncorrelated_d2_refs": uncorrelated_unique[:50],
        "uncorrelated_d2_count": len(uncorrelated_unique),
        "related_gateway_miss_refs": list(dict.fromkeys(related_misses)),
        "indicators": list(dict.fromkeys(indicator_hits)),
        "attribution": attribution,
        "recommended_action": "escalate_investigate" if confirmed else "log_and_monitor",
        "next_skill": "traceability_analysis" if confirmed else None,
        "note": (
            "D2 主机证据缺少 target_ip/upstream_addr 关联，已按未关联处理"
            if d2_present and not victim_keys
            else "活动级成功信号，不等同于每条 WAF 告警均已打穿"
        ),
    }


def _int_or_none(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _web_reached_upstream(ev: dict) -> bool:
    status = _normalize_http_status(ev.get("status"))
    upstream_status = _normalize_http_status(ev.get("upstream_status"))
    success_statuses = {200, 201, 204, 302}
    if status not in success_statuses:
        return False
    if upstream_status is not None and upstream_status not in success_statuses:
        return False
    return bool(_web_upstream_target_keys(ev))


def _matching_success_web_events(alert: dict, evidence: dict, params: dict | None, catalog: dict) -> list[dict]:
    matched: list[dict] = []
    alert_ts = alert_timestamp(alert)
    blocked_actions = {str(a).lower() for a in catalog.get("blocked_actions") or []}
    for ev in evidence.get("web_access_log") or []:
        if alert.get("src_ip") and ev.get("src_ip") != alert.get("src_ip"):
            continue
        ts = event_timestamp(ev)
        if alert_ts:
            if not in_correlation_window(ts, alert_ts, 10, 10):
                continue
        elif not event_in_investigation_window(ev, params):
            continue
        if not _alert_success_context_matches(alert, ev, blocked_actions):
            continue
        if not _web_reached_upstream(ev):
            continue
        matched.append(ev)
    return matched


def _alert_success_context_matches(alert: dict, web_ev: dict, blocked_actions: set[str]) -> bool:
    action = str(alert.get("action") or "").lower()
    if action not in blocked_actions:
        return waf_alert_matches_request(alert, web_ev)
    alert_ts = alert_timestamp(alert)
    web_ts = event_timestamp(web_ev)
    alert_epoch = _ts_epoch(alert_ts)
    web_epoch = _ts_epoch(web_ts)
    if alert_epoch is None or web_epoch is None or abs(alert_epoch - web_epoch) > 5:
        return False
    return _raw_path_query(alert.get("url") or alert.get("payload") or "") == _raw_path_query(
        web_ev.get("url") or web_ev.get("request_uri") or ""
    )


def _raw_path_query(value: str) -> str:
    raw = str(value or "").strip()
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.path or ""
        if parsed.query:
            raw = f"{raw}?{parsed.query}"
    return raw.lower().replace("+", " ")


def _web_target_keys(events: list[dict]) -> set[str]:
    keys: set[str] = set()
    for ev in events:
        for field in ("target_ip", "upstream_addr", "host", "_victim_host"):
            keys.update(_target_key_values(ev.get(field)))
    return keys


def _web_upstream_target_keys(ev: dict) -> set[str]:
    keys: set[str] = set()
    for field in ("target_ip", "upstream_addr"):
        keys.update(_target_key_values(ev.get(field)))
    return keys


def _campaign_d2_attribution(evidence: dict, params: dict | None) -> tuple[set[str], dict[str, Any]]:
    """Return D2 victim keys only when host evidence can be field-correlated."""
    param_keys: set[str] = set()
    for field in ("target_ip", "host_ip", "victim_ip", "_victim_host"):
        param_keys.update(_target_key_values((params or {}).get(field)))

    web_keys: set[str] = set()
    scoped_web_count = 0
    upstream_web_count = 0
    attacker_ip = str((params or {}).get("attacker_ip") or "").strip()
    for ev in evidence.get("web_access_log") or []:
        if not event_in_investigation_window(ev, params):
            continue
        if attacker_ip:
            ev_src = str(ev.get("src_ip") or ev.get("remote_addr") or "").strip()
            if ev_src and ev_src != attacker_ip:
                continue
        scoped_web_count += 1
        if not _web_reached_upstream(ev):
            continue
        upstream_web_count += 1
        web_keys.update(_web_upstream_target_keys(ev))

    victim_keys = param_keys | web_keys
    if victim_keys:
        return victim_keys, {
            "d2_correlation": "field_correlated",
            "target_keys": sorted(victim_keys),
            "sources": {
                "params_target": bool(param_keys),
                "gateway_upstream_target": bool(web_keys),
            },
            "scoped_gateway_events": scoped_web_count,
            "upstream_gateway_events": upstream_web_count,
        }

    if scoped_web_count:
        reason = "no_gateway_upstream_target"
    else:
        reason = "no_target_field"
    return set(), {
        "d2_correlation": "uncorrelated",
        "target_keys": [],
        "reason": reason,
        "scoped_gateway_events": scoped_web_count,
        "upstream_gateway_events": upstream_web_count,
    }


def _target_key_values(value: Any) -> set[str]:
    if value is None:
        return set()
    text = str(value).strip()
    if not text or text.lower() in {"-", "null", "none", "unknown"}:
        return set()

    keys: set[str] = set()
    for raw_part in text.split(","):
        part = raw_part.strip()
        if not part or part.lower() in {"-", "null", "none", "unknown"}:
            continue
        keys.add(part)
        if "://" in part:
            parsed = urlparse(part)
            if parsed.hostname:
                keys.add(parsed.hostname)
        elif part.count(":") == 1:
            host, port = part.rsplit(":", 1)
            if host and port.isdigit():
                keys.add(host)
    return keys


def _scoped_d2_refs(evidence: dict, params: dict | None) -> list[str]:
    refs: list[str] = []
    defaults = {
        "host_exec": "exec-unknown",
        "host_connect": "connect-unknown",
        "host_file_op": "file-unknown",
        "host_persistence": "persistence-unknown",
    }
    for key, default_ref in defaults.items():
        for ev in evidence.get(key) or []:
            if event_in_investigation_window(ev, params):
                refs.append(ev.get("evidence_id") or ev.get("_ref") or default_ref)
    return refs


def _event_near_web_context(ev: dict, web_contexts: list[dict], before_min: int, after_min: int) -> bool:
    if not web_contexts:
        return False
    ev_ts = event_timestamp(ev)
    if ev_ts is None:
        return False
    for web_ev in web_contexts:
        if not host_matches_victim(ev, _web_target_keys([web_ev])):
            continue
        if in_correlation_window(ev_ts, event_timestamp(web_ev), before_min, after_min):
            return True
    return False


def _indicator_compatible(source: str, category: str, attack_type: str) -> bool:
    normalized = attack_type or "unknown"
    if normalized in {"unknown", "scanner_fingerprint"}:
        return True
    if source == "host_connect":
        return normalized in {"rce", "webshell", "ssrf"}
    if source == "host_file_op":
        return normalized in {"rce", "webshell", "path_traversal"}
    if source == "host_persistence":
        return normalized in {"rce", "webshell", "unknown", "scanner_fingerprint"}
    if source == "host_exec":
        if normalized == "sqli":
            return category == "database"
        if normalized == "path_traversal":
            return category in {"file_read", "sensitive_file_read"}
        if normalized in {"rce", "webshell"}:
            return category in {"shell", "download", "webshell_cmd", "file_read", "sensitive_file_read"}
        if normalized == "ssrf":
            return category in {"download", "shell"}
    return False


def _file_op_text(ev: dict) -> str:
    parts: list[str] = []
    for key in ("path", "file_path", "target_path", "filename"):
        val = ev.get(key)
        if val:
            parts.append(str(val))
    raw_paths = ev.get("file_paths")
    if isinstance(raw_paths, list):
        parts.extend(str(p) for p in raw_paths)
    elif isinstance(raw_paths, str) and raw_paths.strip():
        text = raw_paths.strip()
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, list):
            parts.extend(str(p) for p in decoded)
        else:
            parts.append(text)
    for key in ("file_action", "operation", "op", "action", "comm", "command_line"):
        val = ev.get(key)
        if val:
            parts.append(str(val))
    return _url_text(" ".join(parts))


def _host_file_indicator(ev: dict, config: dict) -> str | None:
    text = _file_op_text(ev)
    action = str(ev.get("file_action") or ev.get("operation") or ev.get("op") or ev.get("action") or "").lower()
    if action and action in {str(a).lower() for a in config.get("actions", [])}:
        return "sensitive_file_read"
    for pattern in config.get("paths", []):
        if str(pattern).lower() in text:
            if "etc/passwd" in text or "etc/shadow" in text or "read_sensitive_file" in text:
                return "sensitive_file_read"
            return "file_read"
    return None


def _host_persistence_text(ev: dict) -> str:
    parts: list[str] = []
    for key in ("path", "persistence_type", "category", "action", "process", "exe", "command", "message"):
        val = ev.get(key)
        if isinstance(val, list):
            parts.append(" ".join(str(x) for x in val))
        elif val:
            parts.append(str(val))
    return _url_text(" ".join(parts))


def _host_persistence_indicator(ev: dict, config: dict) -> str | None:
    text = _host_persistence_text(ev)
    ptype = str(ev.get("persistence_type") or ev.get("category") or "").lower()
    for value in config.get("types", []):
        needle = str(value).lower()
        if needle and needle in ptype:
            return needle
    for pattern in config.get("paths", []):
        if str(pattern).lower() in text:
            return "persistence_change"
    if str(ev.get("event_type") or "").lower() == "persistence_change":
        return "persistence_change"
    return None


def has_d2_data(evidence: dict) -> bool:
    for key in D2_EVIDENCE_KEYS:
        if evidence.get(key):
            return True
    return False


def layer2_outcome(
    alert_verdict: str,
    alert: dict,
    evidence: dict,
    success_refs: list[str],
    mode: str,
    catalog: dict,
) -> tuple[str, bool]:
    if alert_verdict == "false_positive":
        return "not_applicable", False

    if alert_verdict not in ("suspicious", "scanning_or_probe", "confirmed_attack"):
        return "success_unknown", False

    action = (alert.get("action") or "").lower()
    blocked_actions = [a.lower() for a in catalog.get("blocked_actions", [])]

    if mode == "triage_only":
        return "success_unknown", False

    if success_refs:
        return "success_confirmed", True

    if action in blocked_actions and alert_verdict == "confirmed_attack":
        return "blocked", False

    if not has_d2_data(evidence):
        return "success_unknown", False

    if has_d2_data(evidence):
        return "attempt_failed", False

    return "success_unknown", False


def confirmation_mode(precheck: dict | None) -> str:
    if not precheck:
        return "full"
    if precheck.get("overall_verdict") == "alert_triage_only":
        return "triage_only"
    return "full"


def confidence_ceiling(precheck: dict | None) -> float:
    if not precheck:
        return 1.0
    confidence = precheck.get("confidence")
    return float(1.0 if confidence is None else confidence)


def effective_confidence_ceiling(
    precheck: dict | None,
    attack_outcome: str,
    success_refs: list[str],
    alert_verdict: str,
    catalog: dict,
) -> float:
    ceiling = confidence_ceiling(precheck)
    config = _layer1_upgrade_config(catalog)
    if attack_outcome == "success_confirmed" and success_refs:
        return max(ceiling, float(config.get("d2_success_confidence_floor") or 0.88))
    if alert_verdict == "confirmed_attack":
        return max(ceiling, float(config.get("confirmed_attack_confidence_floor") or 0.75))
    return ceiling


def compute_confidence(alert_verdict: str, attack_outcome: str, payload_validity: str, ceiling: float) -> float:
    base = 0.6
    if alert_verdict == "confirmed_attack":
        base = 0.88 if payload_validity == "valid" else 0.72
    elif alert_verdict == "false_positive":
        base = 0.82
    elif alert_verdict == "suspicious":
        base = 0.58
    elif alert_verdict == "scanning_or_probe":
        base = 0.7

    if attack_outcome == "success_confirmed":
        base = min(0.95, base + 0.08)
    elif attack_outcome == "success_unknown":
        base = min(base, 0.68)
    elif attack_outcome == "blocked":
        base = min(0.88, base + 0.02)

    return round(min(ceiling, base), 2)


def recommended_action(
    alert_verdict: str,
    attack_outcome: str,
    repeat_count: int,
    catalog: dict,
    gateway_hint: dict | None = None,
) -> tuple[str, str]:
    amap = catalog.get("recommended_action_map", {})
    if alert_verdict == "false_positive":
        m = amap.get("false_positive", {})
        return m.get("action", "close_as_fp"), m.get("label", "关闭告警")
    if attack_outcome == "success_confirmed":
        m = amap.get("confirmed_success", {})
        action = m.get("action", "escalate_investigate")
        label = m.get("label", "升级调查")
        return action, label
    if alert_verdict == "confirmed_attack" and repeat_count >= 3:
        m = amap.get("confirmed_repeat", {})
        return m.get("action", "block_ip"), m.get("label", "建议封禁 IP")
    if alert_verdict == "confirmed_attack" and attack_outcome == "blocked":
        hint_action = gateway_hint_recommended_action(gateway_hint, catalog)
        if gateway_hint and gateway_hint.get("level") == "likely" and hint_action:
            return hint_action
        m = amap.get("confirmed_blocked", {})
        return m.get("action", "log_and_monitor"), m.get("label", "记录并观察")
    if alert_verdict == "scanning_or_probe":
        m = amap.get("scanning_or_probe", {})
        return m.get("action", "log_only"), m.get("label", "仅记录")
    if alert_verdict == "suspicious":
        hint_action = gateway_hint_recommended_action(gateway_hint, catalog)
        if hint_action:
            return hint_action
        m = amap.get("suspicious_no_d2", {})
        return m.get("action", "manual_review_30m"), m.get("label", "人工复核")
    hint_action = gateway_hint_recommended_action(gateway_hint, catalog)
    if gateway_hint and gateway_hint.get("level") == "likely" and hint_action:
        return hint_action
    m = amap.get("suspicious_blocked", {})
    return m.get("action", "log_and_monitor"), m.get("label", "记录并观察")


def _profile_texts(profile: dict[str, Any] | None) -> list[str]:
    if not profile:
        return []
    texts: list[str] = []
    for attr in profile.get("attributes") or []:
        texts.append(str(attr))
    if profile.get("summary"):
        texts.append(str(profile["summary"]))
    online = profile.get("online_lookup") or {}
    for key in ("isp", "org", "as", "asn", "as_owner", "provider", "network"):
        if online.get(key):
            texts.append(str(online[key]))
    for tag in online.get("tags") or []:
        texts.append(str(tag))
    return texts


def evaluate_ip_block_guard(attacker_ip_profile: dict[str, Any] | None) -> dict[str, Any]:
    """Decide whether a block_ip recommendation needs IP/NAT review first."""
    if not attacker_ip_profile:
        return {
            "checked": False,
            "downgraded": True,
            "reason": "ip_profile_missing",
            "reason_label": "缺少攻击源 IP 属性，封禁前需先确认是否 NAT/共享出口",
            "risk_indicators": ["ip_profile_missing"],
            "attributes": [],
            "online_status": None,
        }

    online = attacker_ip_profile.get("online_lookup") or {}
    attrs = [str(a) for a in attacker_ip_profile.get("attributes") or []]
    texts = [t.lower() for t in _profile_texts(attacker_ip_profile)]
    risk_indicators: list[str] = []

    if attacker_ip_profile.get("scope") == "private" or any("内网地址" in a for a in attrs):
        risk_indicators.append("private_or_internal_ip")
    if online.get("mobile"):
        risk_indicators.append("mobile_network_possible_cgnat")
    if online.get("proxy"):
        risk_indicators.append("proxy_or_vpn")
    for keyword in _SHARED_EXIT_KEYWORDS:
        if any(keyword.lower() in text for text in texts):
            risk_indicators.append(keyword)

    risk_indicators = list(dict.fromkeys(risk_indicators))
    if risk_indicators:
        return {
            "checked": True,
            "downgraded": True,
            "reason": "shared_or_nat_exit_risk",
            "reason_label": "攻击源 IP 疑似 NAT/共享出口/代理，封禁前需人工确认影响范围",
            "risk_indicators": risk_indicators,
            "attributes": attrs,
            "online_status": online.get("status"),
            "online_provider": online.get("provider"),
        }

    nat_fields_verified = any(
        key in online and online.get(key) is not None
        for key in ("mobile", "proxy", "hosting", "vpn", "tor", "anonymous")
    )
    verified = bool(attacker_ip_profile.get("verified")) or (
        online.get("status") == "success" and nat_fields_verified
    )
    if not verified:
        reason = "ip_nat_fields_missing" if online.get("status") == "success" else "ip_profile_not_verified"
        return {
            "checked": True,
            "downgraded": True,
            "reason": reason,
            "reason_label": "攻击源 IP 的 NAT/共享出口字段未完成核验，封禁前需先排除误伤风险",
            "risk_indicators": [reason],
            "attributes": attrs,
            "online_status": online.get("status"),
            "online_provider": online.get("provider"),
        }

    return {
        "checked": True,
        "downgraded": False,
        "reason": "no_shared_exit_indicator",
        "reason_label": "IP 属性已核验，未见 NAT/共享出口风险迹象",
        "risk_indicators": [],
        "attributes": attrs,
        "online_status": online.get("status"),
        "online_provider": online.get("provider"),
    }


def apply_ip_block_guard(
    action: str,
    label: str,
    attacker_ip_profile: dict[str, Any] | None,
) -> tuple[str, str, dict[str, Any] | None]:
    if action != "block_ip":
        return action, label, None

    guard = evaluate_ip_block_guard(attacker_ip_profile)
    guard["original_action"] = action
    guard["original_label"] = label
    if guard.get("downgraded"):
        guard["final_action"] = "manual_review_30m"
        guard["final_label"] = "封禁前复核源 IP 属性/NAT"
        return "manual_review_30m", guard["final_label"], guard

    guard["final_action"] = action
    guard["final_label"] = "建议封禁源 IP（已核验非 NAT/共享出口）"
    return action, guard["final_label"], guard


def build_summary(
    alert_verdict: str,
    attack_type_label: str,
    attack_outcome: str,
    payload_notes: str,
    action: str,
    gateway_hint: dict | None = None,
) -> str:
    verdict_cn = {
        "false_positive": "误报",
        "scanning_or_probe": "扫描/探测",
        "suspicious": "可疑告警",
        "confirmed_attack": "真实攻击",
    }.get(alert_verdict, alert_verdict)

    outcome_cn = {
        "not_applicable": "",
        "blocked": "WAF 已拦截",
        "attempt_failed": "攻击未确认成功",
        "success_confirmed": "攻击已成功",
        "success_unknown": "无法确认是否攻击成功",
    }.get(attack_outcome, "")

    parts = [f"{verdict_cn}（{attack_type_label}）"]
    if payload_notes:
        parts.append(payload_notes)
    if outcome_cn:
        parts.append(outcome_cn)
    if gateway_hint:
        hint_cn = {
            "likely": "网关层疑似应用成功（需人工复核）",
            "possible": "网关层可疑响应（建议查访问日志）",
        }.get(gateway_hint.get("level") or "", gateway_hint.get("reason_label") or "")
        if hint_cn:
            parts.append(hint_cn)
    if action:
        parts.append(f"WAF 动作: {action}")
    return "；".join(parts) + "。"


def build_analyst_questions(
    verdict: str,
    outcome: str,
    has_d2: bool,
    gateway_hint: dict | None = None,
) -> list[str]:
    qs = []
    if verdict == "suspicious":
        qs.append("能否补充完整 request body / payload？")
    if outcome == "success_unknown" and not has_d2:
        qs.append("WEB 服务器是否已部署 audit-port-execmon？")
    if verdict == "confirmed_attack" and outcome == "blocked":
        qs.append("同源 IP 是否有重复告警需封禁？")
    if gateway_hint:
        qs.append("网关访问日志是否显示 upstream 200 / 大响应体？请核对业务影响范围")
        if gateway_hint.get("reason") == "waf_block_bypass_backend_200":
            qs.append("WAF 显示拦截但网关 200，是否存在 bypass 或检测/阻断策略不一致？")
    return qs
