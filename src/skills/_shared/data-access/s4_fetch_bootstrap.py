"""S4 alert confirmation two-phase fetch when attacker_ip is not preset.

Phase 1: WAF by time window → extract src_ip list
Phase 2: gateway web_access by each src_ip → extract upstream target_ip
Phase 3: host_exec/connect/file_op/host_persistence by each target_ip (Layer 2)
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

from fetch import (
    begin_fetch_attempt_collection,
    current_fetch_attempt_collection,
    end_fetch_attempt_collection,
    fetch_correlation_plan_evidence,
)
from fetch_metadata import build_asset_execution_meta, task_asset_ids
from registry import load_asset, load_connector, load_templates
from template_select import SRC_IP_WEB_ACCESS_TEMPLATES, select_template_for_asset
from normalizer import normalize_ip

S4_ANCHOR_PATTERN = "S4_alert_confirmation"
MAX_ATTACKER_IPS = 20
MAX_TARGET_IPS = 10

UPSTREAM_HOST_IP = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):\d+$")


def should_s4_bootstrap(
    scenarios: list[str] | None,
    anchor_pattern_ids: list[str] | None,
    params: dict[str, Any],
) -> bool:
    """True when S4 runs without attacker_ip / attacker_ips (time-only intake)."""
    if params.get("attacker_ip"):
        return False
    attacker_ips = params.get("attacker_ips")
    if isinstance(attacker_ips, list) and attacker_ips:
        return False
    for key in ("target_ip", "seed_hosts", "hosts"):
        val = params.get(key)
        if isinstance(val, list) and val:
            return False
        if val not in (None, ""):
            return False
    pids = list(anchor_pattern_ids or [])
    if S4_ANCHOR_PATTERN in pids:
        return True
    return "S4" in (scenarios or [])


def strip_upstream_ip(value: Any) -> str | None:
    """Normalize an upstream IP with optional port and export quoting."""
    return normalize_ip(value)


def extract_attacker_ips(waf_events: list[dict[str, Any]]) -> list[str]:
    seen: dict[str, None] = {}
    for ev in waf_events:
        ip = ev.get("src_ip") or ev.get("ip")
        normalized = normalize_ip(ip)
        if normalized:
            seen[normalized] = None
    return sorted(seen.keys())[:MAX_ATTACKER_IPS]


def extract_target_ips(web_events: list[dict[str, Any]]) -> list[str]:
    seen: dict[str, None] = {}
    for ev in web_events:
        raw = ev.get("target_ip") or ev.get("upstream_addr")
        ip = strip_upstream_ip(raw)
        if ip:
            seen[ip] = None
    return sorted(seen.keys())[:MAX_TARGET_IPS]


def _source_ip_from_params(params: dict[str, Any]) -> str | None:
    for key in ("src_ip", "attacker_ip", "ip", "client_ip"):
        value = params.get(key)
        if value not in (None, ""):
            return normalize_ip(value)
    return None


def _normalize_source_ip(value: Any) -> str:
    """Normalize parser-added quotes before narrowing fallback gateway rows.

    Gateway CSV-like records may retain a leading quote around the client IP;
    stripping that formatting keeps D2 scope tied to the WAF source without
    treating unrelated time-window rows as attacker traffic.
    """
    return normalize_ip(value) or ""


def _merge_target_ips(*items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for values in items:
        for value in values:
            if value:
                seen[str(value)] = None
    return sorted(seen.keys())[:MAX_TARGET_IPS]


def _assets_by_type(asset_ids: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for asset_id in asset_ids:
        asset = load_asset(asset_id)
        asset_type = str(asset.get("asset_type") or "")
        if asset_type and asset_type not in out:
            out[asset_type] = asset_id
    return out


def _web_access_template_for_asset(asset_id: str, params: dict[str, Any]) -> str | None:
    asset = load_asset(asset_id)
    connector_id = asset.get("connector_id")
    if not connector_id:
        return None
    connector = load_connector(str(connector_id))
    templates = load_templates()
    per_params = {**params, "src_ip": params.get("src_ip") or "0.0.0.0"}
    template_id, _reason = select_template_for_asset(asset, connector, per_params, templates)
    return template_id


def _web_access_time_template_for_asset(asset_id: str, params: dict[str, Any]) -> str | None:
    """Select a time-only web-access template for bounded fallback retrieval.

    Some gateway logstores contain records but do not index the WAF source IP in
    ``remote_addr``. S4 first uses the narrow IP query; when it returns no rows,
    this helper selects the asset's time-window template so alert confirmation can
    distinguish gateway data from a true missing-log condition.
    """
    asset = load_asset(asset_id)
    connector_id = asset.get("connector_id")
    if not connector_id:
        return None
    connector = load_connector(str(connector_id))
    templates = load_templates()
    time_params = {
        key: params[key]
        for key in ("time_start", "time_end", "limit")
        if params.get(key) not in (None, "")
    }
    template_id, _reason = select_template_for_asset(asset, connector, time_params, templates)
    if not template_id or template_id in SRC_IP_WEB_ACCESS_TEMPLATES:
        return None
    return template_id if template_id.endswith("_by_time") else None


def _web_events_for_attacker_ips(
    web_events: list[dict[str, Any]], attacker_ips: list[str]
) -> list[dict[str, Any]]:
    """Scope fallback gateway rows before deriving D2 target IPs.

    Time-only fallback data is useful for gateway miss scanning, but unrelated
    source IPs must not be treated as evidence for host-side queries in this
    investigation.
    """
    attacker_set = {_normalize_source_ip(value) for value in attacker_ips if _normalize_source_ip(value)}
    if not attacker_set:
        return []
    return [
        event
        for event in web_events
        if _normalize_source_ip(
            event.get("src_ip") or event.get("remote_addr") or event.get("client_ip") or ""
        )
        in attacker_set
    ]


def _merge_evidence_bundles(*parts: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    merged: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen: dict[str, set[tuple[Any, ...]]] = defaultdict(set)
    for part in parts:
        for asset_type, events in part.items():
            asset_type_text = str(asset_type)
            for ev in events:
                key = _evidence_semantic_key(asset_type_text, ev)
                if key in seen[asset_type_text]:
                    continue
                seen[asset_type_text].add(key)
                merged[asset_type_text].append(ev)
    return dict(merged)


def _text(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, (list, tuple, set)):
        return ",".join(sorted(_text(item) for item in value if item not in (None, "")))
    return str(value).strip()


def _first(ev: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = _text(ev.get(key))
        if value:
            return value
    return ""


def _json_fingerprint(ev: dict[str, Any]) -> str:
    ignored = {
        "evidence_id",
        "_ref",
        "_source_connector_id",
        "_fetch_query",
        "_fetch_meta",
    }
    stable = {k: v for k, v in ev.items() if k not in ignored}
    return json.dumps(stable, sort_keys=True, ensure_ascii=False, default=str)


def _evidence_semantic_key(asset_type: str, ev: dict[str, Any]) -> tuple[Any, ...]:
    if asset_type == "waf_alert":
        alert_id = _first(ev, "alert_id", "trace_id", "request_id")
        if alert_id:
            return (asset_type, "alert_id", alert_id)
        return (
            asset_type,
            "fields",
            _first(ev, "timestamp", "time"),
            _first(ev, "src_ip", "client_ip", "ip", "remote_addr"),
            _first(ev, "method", "request_method"),
            _first(ev, "url", "request_uri", "uri", "path"),
            _first(ev, "rule_id", "plugin_name"),
            _first(ev, "action"),
        )
    if asset_type == "web_access_log":
        return (
            asset_type,
            "fields",
            _first(ev, "timestamp", "time"),
            _first(ev, "src_ip", "client_ip", "ip", "remote_addr"),
            _first(ev, "method", "request_method"),
            _first(ev, "url", "request_uri", "uri", "path"),
            _first(ev, "status", "http_status"),
            _first(ev, "upstream_status"),
            _first(ev, "target_ip", "upstream_addr"),
        )
    if asset_type == "host_exec":
        return (
            asset_type,
            "fields",
            _first(ev, "timestamp", "time"),
            _first(ev, "host_ip", "host", "host_name", "_victim_host"),
            _first(ev, "pid", "process_id"),
            _first(ev, "command", "command_line", "cmdline", "cmd", "process_name", "comm"),
        )
    if asset_type == "host_connect":
        return (
            asset_type,
            "fields",
            _first(ev, "timestamp", "time"),
            _first(ev, "host_ip", "host", "host_name", "_victim_host"),
            _first(ev, "pid", "process_id"),
            _first(ev, "dst_ip", "connect_address", "remote_ip"),
            _first(ev, "dst_port", "connect_port", "remote_port"),
        )
    if asset_type == "host_file_op":
        return (
            asset_type,
            "fields",
            _first(ev, "timestamp", "time"),
            _first(ev, "host_ip", "host", "host_name", "_victim_host"),
            _first(ev, "pid", "process_id"),
            _first(ev, "action", "file_action"),
            _first(ev, "path", "file_path", "file_paths"),
        )
    if asset_type == "host_persistence":
        return (
            asset_type,
            "fields",
            _first(ev, "timestamp", "time"),
            _first(ev, "host_ip", "host", "host_name", "log_source", "__source__", "_victim_host"),
            _first(ev, "action", "event_type"),
            _first(ev, "persistence_type", "category"),
            _first(ev, "path", "file_path"),
        )
    return (asset_type, "fingerprint", _json_fingerprint(ev))


def _make_task(
    *,
    join_id: str,
    side: str,
    asset_id: str,
    template_id: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    return {
        "join_id": join_id,
        "side": side,
        "asset_id": asset_id,
        "template_id": template_id,
        "params": dict(params),
    }


def build_s4_bootstrap_plan(
    bundle_asset_ids: list[str],
    params: dict[str, Any],
    *,
    waf_events: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build fetch tasks after optional WAF phase-1 events are available."""
    by_type = _assets_by_type(bundle_asset_ids)
    waf_asset = by_type.get("waf_alert")
    web_asset = by_type.get("web_access_log")
    exec_asset = by_type.get("host_exec")
    connect_asset = by_type.get("host_connect")
    file_op_asset = by_type.get("host_file_op")
    persistence_asset = by_type.get("host_persistence")

    meta: dict[str, Any] = {
        "bootstrap_phase": "plan",
        "waf_asset_id": waf_asset,
        "web_asset_id": web_asset,
        "host_exec_asset_id": exec_asset,
        "host_connect_asset_id": connect_asset,
        "host_file_op_asset_id": file_op_asset,
        "host_persistence_asset_id": persistence_asset,
    }
    tasks: list[dict[str, Any]] = []

    base_params = {
        k: params[k]
        for k in ("time_start", "time_end", "limit")
        if k in params and params[k] not in (None, "")
    }
    if "limit" not in base_params:
        base_params["limit"] = 5000

    if waf_events is None and waf_asset:
        src_ip = _source_ip_from_params(params)
        template_id = "waf_gateway_plugin_by_ip_time" if src_ip else "waf_gateway_plugin_by_time"
        task_params = {**base_params, "src_ip": src_ip} if src_ip else base_params
        tasks.append(
            _make_task(
                join_id="s4_bootstrap_waf",
                side="left",
                asset_id=waf_asset,
                template_id=template_id,
                params=task_params,
            )
        )
        return tasks, meta

    waf_events = waf_events or []
    attacker_ips = extract_attacker_ips(waf_events)
    if not attacker_ips:
        src_ip = _source_ip_from_params(params)
        if src_ip:
            attacker_ips = [src_ip]
    meta["attacker_ips"] = attacker_ips

    if web_asset and attacker_ips:
        web_template = _web_access_template_for_asset(web_asset, params)
        if web_template:
            meta["web_access_template_id"] = web_template
            for src_ip in attacker_ips:
                tasks.append(
                    _make_task(
                        join_id="waf_to_web_access_by_ip",
                        side="right",
                        asset_id=web_asset,
                        template_id=web_template,
                        params={**base_params, "src_ip": src_ip},
                    )
                )

    return tasks, meta


def _fetch_s4_bootstrap_inner(
    bundle_asset_ids: list[str],
    params: dict[str, Any],
    *,
    resolve_secrets: bool = True,
    include_host_side: bool = True,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Run S4 two-phase fetch; return merged evidence + access meta."""
    phase1_tasks, plan_meta = build_s4_bootstrap_plan(bundle_asset_ids, params)
    if not phase1_tasks:
        return {}, {
            "fetch_strategy": "s4_bootstrap",
            "bootstrap_error": "no_waf_asset_in_bundle",
            **plan_meta,
        }

    phase1_evidence = fetch_correlation_plan_evidence(phase1_tasks, resolve_secrets=resolve_secrets)
    waf_events = list(phase1_evidence.get("waf_alert") or [])

    phase2_tasks, phase2_meta = build_s4_bootstrap_plan(
        bundle_asset_ids,
        params,
        waf_events=waf_events,
    )

    # Re-derive target_ips from web fetch (plan built before web events exist).
    # Resolve attacker_ips before the fallback so unrelated time-window rows do
    # not widen the host-side correlation scope.
    attacker_ips = extract_attacker_ips(waf_events)
    if not attacker_ips:
        src_ip = _source_ip_from_params(params)
        if src_ip:
            attacker_ips = [src_ip]

    phase2_evidence: dict[str, list[dict[str, Any]]] = {}
    if phase2_tasks:
        phase2_evidence = fetch_correlation_plan_evidence(phase2_tasks, resolve_secrets=resolve_secrets)

    web_events = list(phase2_evidence.get("web_access_log") or [])
    web_access_fallback: dict[str, Any] = {
        "attempted": False,
        "used": False,
        "reason": None,
        "template_id": None,
        "targeted_event_count": len(web_events),
        "fallback_event_count": 0,
    }
    web_asset = phase2_meta.get("web_asset_id")
    if web_asset and attacker_ips and not web_events:
        fallback_template = _web_access_time_template_for_asset(web_asset, params)
        web_access_fallback.update(
            {
                "attempted": bool(fallback_template),
                "reason": "targeted_ip_query_returned_no_rows",
                "template_id": fallback_template,
            }
        )
        if fallback_template:
            fallback_params = {
                key: params[key]
                for key in ("time_start", "time_end", "limit")
                if params.get(key) not in (None, "")
            }
            fallback_params.setdefault("limit", 5000)
            fallback_task = _make_task(
                join_id="waf_to_web_access_by_time_fallback",
                side="right",
                asset_id=web_asset,
                template_id=fallback_template,
                params=fallback_params,
            )
            fallback_evidence = fetch_correlation_plan_evidence(
                [fallback_task],
                resolve_secrets=resolve_secrets,
            )
            phase2_tasks.append(fallback_task)
            phase2_evidence = _merge_evidence_bundles(phase2_evidence, fallback_evidence)
            web_events = list(phase2_evidence.get("web_access_log") or [])
            web_access_fallback.update(
                {
                    "used": True,
                    "fallback_event_count": len(fallback_evidence.get("web_access_log") or []),
                }
            )
    phase2_meta["web_access_fallback"] = web_access_fallback

    waf_target_ips = extract_target_ips(waf_events)
    web_target_ips = extract_target_ips(_web_events_for_attacker_ips(web_events, attacker_ips))
    target_ips = _merge_target_ips(web_target_ips, waf_target_ips)

    phase3_tasks: list[dict[str, Any]] = []
    by_type = _assets_by_type(bundle_asset_ids)
    exec_asset = by_type.get("host_exec")
    connect_asset = by_type.get("host_connect")
    file_op_asset = by_type.get("host_file_op")
    persistence_asset = by_type.get("host_persistence")
    base_params = {
        k: params[k]
        for k in ("time_start", "time_end", "limit")
        if k in params and params[k] not in (None, "")
    }
    if "limit" not in base_params:
        base_params["limit"] = 5000
    if include_host_side and exec_asset and target_ips:
        for host_ip in target_ips:
            phase3_tasks.append(
                _make_task(
                    join_id="waf_to_host_exec_direct",
                    side="right",
                    asset_id=exec_asset,
                    template_id="host_exec_by_host_ip_time",
                    params={**base_params, "host_ip": host_ip},
                )
            )
    if include_host_side and connect_asset and target_ips:
        for host_ip in target_ips:
            phase3_tasks.append(
                _make_task(
                    join_id="waf_to_host_connect_direct",
                    side="right",
                    asset_id=connect_asset,
                    template_id="host_connect_by_host_ip_time",
                    params={**base_params, "host_ip": host_ip},
                )
            )
    if include_host_side and file_op_asset and target_ips:
        for host_ip in target_ips:
            phase3_tasks.append(
                _make_task(
                    join_id="waf_to_host_file_op_direct",
                    side="right",
                    asset_id=file_op_asset,
                    template_id="host_file_op_by_host_ip_time",
                    params={**base_params, "host_ip": host_ip},
                )
            )
    if include_host_side and persistence_asset and target_ips:
        for host_ip in target_ips:
            phase3_tasks.append(
                _make_task(
                    join_id="waf_to_host_persistence_direct",
                    side="right",
                    asset_id=persistence_asset,
                    template_id="host_persistence_by_host_ip_time",
                    params={**base_params, "host_ip": host_ip},
                )
            )

    phase3_evidence: dict[str, list[dict[str, Any]]] = {}
    if phase3_tasks:
        phase3_evidence = fetch_correlation_plan_evidence(phase3_tasks, resolve_secrets=resolve_secrets)
    host_side_assets_present = bool(exec_asset or connect_asset or file_op_asset or persistence_asset)
    host_side_fetch_skipped = host_side_assets_present and (not target_ips or not include_host_side)
    host_side_skip_reason = (
        "deferred_until_attacker_window_narrowed"
        if host_side_fetch_skipped and target_ips and not include_host_side
        else "no_valid_target_ip_from_waf_or_gateway"
        if host_side_fetch_skipped and not target_ips
        else None
    )

    evidence = _merge_evidence_bundles(phase1_evidence, phase2_evidence, phase3_evidence)
    from waf_enrich import enrich_evidence_waf_targets

    waf_enrich_stats = enrich_evidence_waf_targets(evidence)
    waf_events = list(evidence.get("waf_alert") or [])
    all_tasks = phase1_tasks + phase2_tasks + phase3_tasks
    executed_asset_ids = task_asset_ids(all_tasks)

    enriched_params = dict(params)
    if attacker_ips:
        enriched_params["attacker_ips"] = attacker_ips
        if len(attacker_ips) == 1:
            enriched_params.setdefault("attacker_ip", attacker_ips[0])
            enriched_params.setdefault("src_ip", attacker_ips[0])
    if target_ips:
        enriched_params["target_ips"] = target_ips
        if len(target_ips) == 1:
            enriched_params.setdefault("target_ip", target_ips[0])
    elif waf_enrich_stats.get("enriched"):
        enriched_targets = sorted(
            {
                str(ev.get("target_ip"))
                for ev in waf_events
                if ev.get("target_ip")
            }
        )
        if enriched_targets:
            enriched_params["target_ips"] = enriched_targets
            if len(enriched_targets) == 1:
                enriched_params.setdefault("target_ip", enriched_targets[0])

    meta: dict[str, Any] = {
        "source": "dataasset",
        "fetch_strategy": "s4_bootstrap",
        "correlation_anchor_pattern": S4_ANCHOR_PATTERN,
        "correlation_fetch_plan": all_tasks,
        "plan_task_count": len(all_tasks),
        "skipped_plan_task_count": 0,
        **build_asset_execution_meta(
            declared_asset_ids=bundle_asset_ids,
            fetch_asset_ids=bundle_asset_ids,
            executed_asset_ids=executed_asset_ids,
            skip_reason="not_selected_by_s4_bootstrap",
        ),
        "s4_bootstrap": {
            **plan_meta,
            **phase2_meta,
            "attacker_ips": attacker_ips,
            "target_ips": target_ips,
            "waf_target_ips": waf_target_ips,
            "web_target_ips": web_target_ips,
            "waf_event_count": len(waf_events),
            "web_access_event_count": len(web_events),
            "host_side_fetch_skipped": host_side_fetch_skipped,
            "host_side_skip_reason": host_side_skip_reason,
            "waf_target_enrich": waf_enrich_stats,
        },
        "enriched_params": enriched_params,
    }
    return evidence, meta


def fetch_s4_bootstrap(
    bundle_asset_ids: list[str],
    params: dict[str, Any],
    *,
    resolve_secrets: bool = True,
    include_host_side: bool = True,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Run S4 bootstrap and attach per-asset fetch attempts when no caller is collecting."""
    if current_fetch_attempt_collection() is not None:
        return _fetch_s4_bootstrap_inner(
            bundle_asset_ids,
            params,
            resolve_secrets=resolve_secrets,
            include_host_side=include_host_side,
        )

    fetch_attempts, fetch_attempt_token = begin_fetch_attempt_collection()
    try:
        evidence, meta = _fetch_s4_bootstrap_inner(
            bundle_asset_ids,
            params,
            resolve_secrets=resolve_secrets,
            include_host_side=include_host_side,
        )
        meta["fetch_attempts"] = fetch_attempts
        return evidence, meta
    finally:
        end_fetch_attempt_collection(fetch_attempt_token)
