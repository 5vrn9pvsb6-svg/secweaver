"""Gateway access-log scan and success-hint logic."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .common import (
    _ts_epoch,
    alert_timestamp,
    event_in_investigation_window,
    event_timestamp,
    in_correlation_window,
    investigation_time_bounds,
    text_blob,
)
from .url_match import (
    _alert_path_matches_web,
    _match_attack_url_patterns,
    _normalize_http_status,
    normalize_source_ip,
    _same_src_ip,
    _url_text,
    _web_request_method,
    alert_path_query,
    urls_correlate,
    waf_alert_matches_request,
)

def _block_success_statuses(config: dict) -> set[int]:
    values = config.get("block_success_status") or [403, 401, 406]
    return {v for v in (_normalize_http_status(x) for x in values) if v is not None}


def _gateway_miss_item_severity(web_ev: dict, pattern_hits: list[str], config: dict) -> str:
    status = _normalize_http_status(web_ev.get("status"))
    web_url = str(web_ev.get("url") or web_ev.get("request_uri") or "")
    web_text = _url_text(web_url)
    if status is not None and 400 <= status < 500:
        return "low"
    probe_patterns = [_url_text(str(p)) for p in config.get("probe_url_patterns") or []]
    critical_patterns = [_url_text(str(p)) for p in config.get("critical_url_patterns") or []]
    high_patterns = [_url_text(str(p)) for p in config.get("high_url_patterns") or []]
    hit_text = _url_text(" ".join(pattern_hits))
    if any(p in web_text or p in hit_text for p in probe_patterns):
        return str(config.get("probe_severity") or "medium")
    if any(p in web_text or p in hit_text for p in critical_patterns):
        return "critical"
    if any(p in web_text or p in hit_text for p in high_patterns):
        return "high"
    if status in {200, 201, 204, 302} and pattern_hits:
        return "high"
    if pattern_hits:
        return "medium"
    return "low"


def find_gateway_access_coverage(
    alert: dict,
    evidence: dict,
    params: dict | None = None,
    *,
    tight_seconds: int = 60,
) -> dict[str, Any]:
    """Check gateway coverage while separating missing data from an unmatched request.

    A populated gateway asset with no same-source/same-path match is a correlation
    gap, not proof that the gateway log is absent. Keeping these states distinct
    prevents the report from asking operators to backfill a logstore that was
    already queried successfully.
    """
    web_logs = list(evidence.get("web_access_log") or [])
    if not web_logs:
        return _gateway_access_gap(
            "gateway_log_missing",
            "WAF 有告警，但本次未获取到 web_access_log/网关访问日志，需补充网关访问日志以确认是否到达后端。",
            observed_count=0,
            scoped_count=0,
        )

    scoped = [ev for ev in web_logs if event_in_investigation_window(ev, params)]
    if not scoped:
        return _gateway_access_gap(
            "gateway_log_no_investigation_window",
            "WAF 有告警，但调查时间窗内无网关访问日志，需补齐该时间段网关 access log。",
            observed_count=len(web_logs),
            scoped_count=0,
        )

    use_tight = tight_seconds if alert_timestamp(alert) is not None else None
    matched = [
        ev
        for ev in scoped
        if waf_alert_matches_request(alert, ev, tight_seconds=use_tight)
    ]
    if matched:
        return {
            "status": "matched",
            "reason": "gateway_log_matched",
            "message": "已找到对应网关访问日志。",
            "observed_gateway_events": len(web_logs),
            "scoped_gateway_events": len(scoped),
            "matching_count": len(matched),
            "evidence_refs": _web_refs(matched),
        }

    loose = [ev for ev in scoped if waf_alert_matches_request(alert, ev)] if use_tight is not None else []
    if loose:
        return _gateway_access_gap(
            "gateway_log_outside_tight_window",
            "WAF 有告警，网关日志存在同源同路径请求但不在时间匹配窗口内，需核对时间同步或补齐精确网关日志。",
            observed_count=len(web_logs),
            scoped_count=len(scoped),
            candidate_refs=_web_refs(loose),
        )

    return _gateway_access_gap(
        "gateway_log_no_matching_request",
        f"网关访问日志资产在调查时间窗内已有 {len(scoped)} 条记录，但未找到同源同路径对应请求；请优先核对字段映射、路径归一化和时间偏差（src_ip、url/request_uri、method、timestamp），不能据此判定网关日志缺失。",
        observed_count=len(web_logs),
        scoped_count=len(scoped),
    )


def _gateway_access_gap(
    reason: str,
    message: str,
    *,
    observed_count: int,
    scoped_count: int,
    candidate_refs: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "status": "missing",
        "reason": reason,
        "message": message,
        "observed_gateway_events": observed_count,
        "scoped_gateway_events": scoped_count,
        "matching_count": 0,
        "evidence_refs": [],
        "candidate_refs": candidate_refs or [],
    }


def _web_refs(events: list[dict]) -> list[str]:
    refs = [ev.get("evidence_id") or ev.get("_ref") or "web-unknown" for ev in events]
    return list(dict.fromkeys(refs))


def web_request_has_waf_alert(
    web_ev: dict,
    waf_alerts: list[dict],
    minutes: int,
    *,
    blocked_actions: set[str] | None = None,
    bypass_status_ok: set[int | None] | None = None,
    gateway_miss_config: dict | None = None,
) -> bool:
    """True when this gateway request is adequately covered by WAF (exclude from miss scan).

    Block alerts only cover the blocked attempt itself (typically HTTP 403), not every
    later 200/302 on the same URL path.
    """
    web_ts = event_timestamp(web_ev)
    web_url = str(web_ev.get("url") or web_ev.get("request_uri") or "")
    web_status = _normalize_http_status(web_ev.get("status"))
    bypass_ok = bypass_status_ok if bypass_status_ok is not None else {200, 201, 204, 302}
    blocked = blocked_actions or set()
    miss_cfg = gateway_miss_config or {}
    tight_seconds = int(miss_cfg.get("bypass_tight_seconds") or 5)
    block_success = _block_success_statuses(miss_cfg)

    for alert in waf_alerts:
        if not _same_src_ip(alert, web_ev):
            continue
        alert_ts = alert_timestamp(alert)
        if web_ts and alert_ts and not in_correlation_window(web_ts, alert_ts, minutes, minutes):
            continue
        if not _alert_path_matches_web(alert, web_url):
            continue
        action = (alert.get("action") or "").lower()
        if action in blocked:
            if web_status in block_success and waf_alert_matches_request(
                alert, web_ev, tight_seconds=tight_seconds
            ):
                return True
            continue
        if web_status in bypass_ok or web_status in block_success:
            return True
    return False


def classify_gateway_miss_reason(
    web_ev: dict,
    waf_alerts: list[dict],
    minutes: int,
    *,
    blocked_actions: set[str],
    status_ok: set[int],
    gateway_miss_config: dict,
    reason_labels: dict[str, str],
    block_success_keys: set[tuple[str, str, str]] | None = None,
) -> tuple[str, str]:
    """Classify why a successful gateway response is a WAF miss."""
    default_reason = "gateway_exploit_no_waf_alert"
    default_label = reason_labels.get(default_reason, default_reason)
    web_ts = event_timestamp(web_ev)
    web_url = str(web_ev.get("url") or web_ev.get("request_uri") or "")
    web_status = _normalize_http_status(web_ev.get("status"))
    if web_status not in status_ok:
        return default_reason, default_label

    tight_seconds = int(gateway_miss_config.get("bypass_tight_seconds") or 5)
    related_blocks: list[dict] = []
    for alert in waf_alerts:
        if not _same_src_ip(alert, web_ev):
            continue
        alert_ts = alert_timestamp(alert)
        if web_ts and alert_ts and not in_correlation_window(web_ts, alert_ts, minutes, minutes):
            continue
        if (alert.get("action") or "").lower() not in blocked_actions:
            continue
        if _alert_path_matches_web(alert, web_url):
            related_blocks.append(alert)

    src_ip = normalize_source_ip(web_ev.get("src_ip") or web_ev.get("remote_addr") or "")
    path_key = _url_text(web_url).partition("?")[0]
    method_key = _web_request_method(web_ev)
    success_keys = block_success_keys or set()
    path_had_block_success = (src_ip, path_key, method_key) in success_keys

    for alert in related_blocks:
        if waf_alert_matches_request(alert, web_ev, tight_seconds=tight_seconds):
            if not path_had_block_success:
                reason = "waf_block_bypass"
                return reason, reason_labels.get(reason) or "WAF 拦截告警与网关成功响应高度吻合，疑似 bypass"
            break

    if related_blocks:
        reason = "waf_partial_block_same_path"
        return reason, reason_labels.get(reason) or "同路径 WAF 曾拦截，但本条请求未告警/已放行"

    return default_reason, default_label


def _block_success_keys(
    web_logs: list[dict],
    waf_alerts: list[dict],
    *,
    blocked_actions: set[str],
    block_success: set[int],
    tight_seconds: int,
) -> set[tuple[str, str, str]]:
    """Paths where WAF block correlated with gateway 403 (enforcement worked)."""
    keys: set[tuple[str, str, str]] = set()
    for ev in web_logs:
        status = _normalize_http_status(ev.get("status"))
        if status not in block_success:
            continue
        web_url = str(ev.get("url") or ev.get("request_uri") or "")
        path = _url_text(web_url).partition("?")[0]
        src = normalize_source_ip(ev.get("src_ip") or ev.get("remote_addr") or "")
        method = _web_request_method(ev)
        for alert in waf_alerts:
            if (alert.get("action") or "").lower() not in blocked_actions:
                continue
            if waf_alert_matches_request(alert, ev, tight_seconds=tight_seconds):
                keys.add((src, path, method))
                break
    return keys


def scan_gateway_misses(
    alerts: list[dict],
    evidence: dict,
    catalog: dict,
    params: dict | None = None,
) -> dict[str, Any]:
    config = catalog.get("gateway_miss_scan") or {}
    if not config.get("enabled"):
        return {"count": 0, "items": [], "summary": {}, "enabled": False}

    status_ok = {_normalize_http_status(v) for v in config.get("status_ok") or [200, 201, 204, 302]}
    status_ok.discard(None)
    url_patterns = list(config.get("url_patterns") or [])
    minutes = int(config.get("correlation_minutes") or 15)
    reason = "gateway_exploit_no_waf_alert"
    reason_labels = config.get("reason_labels") or {}
    reason_label = reason_labels.get(reason, reason)

    waf_alerts: list[dict] = list(alerts)
    seen_ids: set[str] = set()
    deduped: list[dict] = []
    for alert in waf_alerts:
        aid = str(alert.get("alert_id") or alert.get("id") or id(alert))
        if aid in seen_ids:
            continue
        seen_ids.add(aid)
        deduped.append(alert)
    waf_alerts = deduped

    blocked_actions = {(a or "").lower() for a in catalog.get("blocked_actions") or []}
    exclude_patterns = [p.lower() for p in config.get("exclude_url_patterns") or []]
    tight_seconds = int(config.get("bypass_tight_seconds") or 5)
    block_success = _block_success_statuses(config)
    web_logs = list(evidence.get("web_access_log") or [])
    block_success_keys = _block_success_keys(
        web_logs,
        waf_alerts,
        blocked_actions=blocked_actions,
        block_success=block_success,
        tight_seconds=tight_seconds,
    )
    misses: list[dict[str, Any]] = []
    pattern_counter: Counter[str] = Counter()
    src_counter: Counter[str] = Counter()
    reason_counter: Counter[str] = Counter()
    severity_counter: Counter[str] = Counter()

    for ev in evidence.get("web_access_log") or []:
        if not event_in_investigation_window(ev, params):
            continue
        web_url = str(ev.get("url") or ev.get("request_uri") or "")
        web_text = _url_text(web_url)
        if exclude_patterns and any(p in web_text for p in exclude_patterns):
            continue
        pattern_hits = _match_attack_url_patterns(web_text, url_patterns)
        if not pattern_hits:
            continue
        status = _normalize_http_status(ev.get("status"))
        if status not in status_ok:
            continue
        src_ip = normalize_source_ip(ev.get("src_ip") or ev.get("remote_addr") or "unknown")
        if web_request_has_waf_alert(
            ev,
            waf_alerts,
            minutes,
            blocked_actions=blocked_actions,
            gateway_miss_config=config,
        ):
            continue

        bypass_reason, bypass_label = classify_gateway_miss_reason(
            ev,
            waf_alerts,
            minutes,
            blocked_actions=blocked_actions,
            status_ok=status_ok,
            gateway_miss_config=config,
            reason_labels=reason_labels,
            block_success_keys=block_success_keys,
        )

        ref = ev.get("evidence_id") or ev.get("_ref") or "web-unknown"
        severity = _gateway_miss_item_severity(ev, pattern_hits, config)
        misses.append(
            {
                "reason": bypass_reason,
                "reason_label": bypass_label,
                "severity": severity,
                "evidence_ref": ref,
                "src_ip": src_ip,
                "url": web_url[:300],
                "status": status,
                "pattern_hits": pattern_hits[:5],
                "timestamp": ev.get("timestamp") or ev.get("time"),
            }
        )
        for hit in pattern_hits[:3]:
            pattern_counter[hit] += 1
        src_counter[src_ip] += 1
        reason_counter[bypass_reason] += 1
        severity_counter[severity] += 1

    return {
        "enabled": True,
        "count": len(misses),
        "items": misses[:50],
        "summary": {
            "top_patterns": [p for p, _ in pattern_counter.most_common(8)],
            "top_src_ips": [ip for ip, _ in src_counter.most_common(5)],
            "by_reason": dict(reason_counter),
            "by_severity": dict(severity_counter),
            "reason_label": reason_label,
        },
    }


def find_gateway_success_hint(
    alert: dict,
    evidence: dict,
    *,
    attack_type: str,
    alert_verdict: str,
    attack_success: bool,
    catalog: dict,
    params: dict | None = None,
) -> dict[str, Any] | None:
    """Gateway-layer hint when web_access suggests app success but D2 does not confirm."""
    if attack_success:
        return None
    if alert_verdict not in ("confirmed_attack", "suspicious", "scanning_or_probe"):
        return None

    scan_probe = alert_verdict == "scanning_or_probe"
    config = catalog.get("gateway_success_hint") or {}
    web_cfg = config.get("web_access_log") or config
    minutes = int(config.get("correlation_minutes") or web_cfg.get("correlation_minutes") or 10)
    if scan_probe:
        status_values = config.get("scanning_or_probe_status_ok") or config.get("status_ok") or [200, 201, 204]
    else:
        status_values = config.get("status_ok") or [200, 201, 204]
    status_ok = {_normalize_http_status(v) for v in status_values}
    status_ok.discard(None)
    upstream_ok = {_normalize_http_status(v) for v in config.get("upstream_status_ok") or [200, 201, 204]}
    upstream_ok.discard(None)

    type_rules = (config.get("attack_type_rules") or {}).get(attack_type) or {}
    url_patterns = list(type_rules.get("url_patterns") or [])
    if scan_probe and not url_patterns:
        rce_rules = (config.get("attack_type_rules") or {}).get("rce") or {}
        url_patterns = list(rce_rules.get("url_patterns") or [])
        type_rules = rce_rules
        attack_type = attack_type if attack_type != "unknown" else "rce"
    min_bytes = int(type_rules.get("min_bytes_sent") or config.get("default_min_bytes_sent") or 64)
    large_bytes = int(
        type_rules.get("large_response_bytes")
        or config.get("default_large_response_bytes")
        or 500
    )

    alert_ts = alert_timestamp(alert)
    alert_pq = alert_path_query(alert)
    alert_text = _url_text(text_blob(alert))
    waf_action = (alert.get("action") or "").lower()
    blocked_actions = {a.lower() for a in catalog.get("blocked_actions", [])}
    waf_pass = waf_action == "pass"
    waf_blocked = waf_action in blocked_actions
    inv_start, inv_end = investigation_time_bounds(params)

    candidates: list[dict[str, Any]] = []
    for ev in evidence.get("web_access_log") or []:
        if alert.get("src_ip") and ev.get("src_ip") != alert.get("src_ip"):
            continue
        ts = event_timestamp(ev)
        if scan_probe:
            ts_epoch = _ts_epoch(ts)
            start_epoch = _ts_epoch(inv_start)
            end_epoch = _ts_epoch(inv_end)
            if start_epoch is not None and end_epoch is not None and ts_epoch is not None:
                if not (start_epoch <= ts_epoch <= end_epoch):
                    continue
            elif alert_ts and not in_correlation_window(ts, alert_ts, minutes * 3, minutes * 3):
                continue
        elif not in_correlation_window(ts, alert_ts, minutes, minutes):
            continue

        web_url = str(ev.get("url") or "")
        web_text = _url_text(web_url)
        if not scan_probe and alert_pq and not urls_correlate(alert_pq, web_url):
            continue

        status = _normalize_http_status(ev.get("status"))
        upstream_status = _normalize_http_status(ev.get("upstream_status"))
        if status not in status_ok:
            continue
        if upstream_status is not None and upstream_status not in upstream_ok:
            continue

        bytes_sent = ev.get("bytes_sent") or ev.get("body_bytes_sent")
        try:
            bytes_sent = int(bytes_sent) if bytes_sent not in (None, "") else 0
        except (TypeError, ValueError):
            bytes_sent = 0
        if bytes_sent < min_bytes:
            continue

        pattern_hits = _match_attack_url_patterns(web_text or alert_text, url_patterns)
        if attack_type != "unknown" and url_patterns and not pattern_hits:
            continue

        reason = "exploit_url_backend_200_large_body"
        level = "possible"
        if waf_pass:
            reason = "waf_pass_backend_200"
            level = "likely"
        elif waf_blocked:
            reason = "waf_block_bypass_backend_200"
            level = "likely"
        elif bytes_sent >= large_bytes and pattern_hits:
            level = "likely"

        candidates.append(
            {
                "level": level,
                "reason": reason,
                "evidence_ref": ev.get("evidence_id") or ev.get("_ref") or "web-unknown",
                "web_url": web_url[:200],
                "status": status,
                "upstream_status": upstream_status,
                "bytes_sent": bytes_sent,
                "pattern_hits": pattern_hits[:3],
            }
        )

    if not candidates:
        return None

    level_rank = {"likely": 2, "possible": 1}
    best = max(candidates, key=lambda c: (level_rank.get(c["level"], 0), c.get("bytes_sent") or 0))
    reason_labels = config.get("reason_labels") or {}
    refs = list(dict.fromkeys(c["evidence_ref"] for c in candidates if c.get("evidence_ref")))

    return {
        "level": best["level"],
        "reason": best["reason"],
        "reason_label": reason_labels.get(best["reason"], best["reason"]),
        "evidence_refs": refs,
        "signals": [
            {"signal": "waf_action", "value": alert.get("action")},
            {"signal": "web_status", "value": best.get("status")},
            {"signal": "upstream_status", "value": best.get("upstream_status")},
            {"signal": "bytes_sent", "value": best.get("bytes_sent")},
        ],
        "matched_web_urls": list(dict.fromkeys(c["web_url"] for c in candidates if c.get("web_url")))[:5],
        "pattern_hits": best.get("pattern_hits") or [],
        "note": "应用层可能已成功；无 D2 证据时 attack_outcome 不得判为 success_confirmed",
    }


def gateway_hint_recommended_action(hint: dict | None, catalog: dict) -> tuple[str, str] | None:
    if not hint:
        return None
    amap = (catalog.get("gateway_success_hint") or {}).get("recommended_action_map") or {}
    entry = amap.get(hint.get("level") or "")
    if not entry:
        return None
    return entry.get("action", "manual_review_30m"), entry.get("label", "网关层可疑，建议人工复核")
