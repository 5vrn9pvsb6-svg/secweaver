"""Scenario evidence planning and bounded expansion, without Skill execution.

This layer resolves declarative correlation/trace profiles and fetches evidence.
It never imports a concrete Skill's Python implementation or assesses a verdict;
payload adaptation and cross-Skill orchestration belong to skill_runtime.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path
from typing import Any

DATA_ACCESS_ROOT = Path(__file__).resolve().parent

if str(DATA_ACCESS_ROOT) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS_ROOT))

import fetch as data_fetch  # noqa: E402
from fetch import (  # noqa: E402
    current_fetch_attempt_collection,
)
from fetch_metadata import build_asset_execution_meta, task_asset_ids, unique_ids  # noqa: E402
from registry import load_asset, load_connector, load_bundle, load_templates  # noqa: E402
from template_select import build_template_map_for_assets, normalize_fetch_params, params_satisfy_template  # noqa: E402
from normalizer import normalize_ip  # noqa: E402
from trace_time_window import (  # noqa: E402
    filter_evidence_by_time_window as _filter_evidence_by_time_window,
    maybe_narrow_attacker_window as _maybe_narrow_attacker_window,
    parse_trace_datetime as _parse_trace_dt,
)


HOST_IMPACT_ASSET_TYPES = frozenset(
    {
        "host_exec",
        "host_connect",
        "host_file_op",
        "host_persistence",
        "host_process",
        "host_socket",
        "host_identity",
        "host_service",
        "host_kernel_context",
    }
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
LATERAL_HINT_TOKENS = frozenset(
    {
        "ssh",
        "sshpass",
        "scp",
        "sftp",
        "rsync",
        "nc ",
        "ncat",
        "s.phtml",
        "webshell",
    }
)


def resolve_investigation_params(
    params: dict[str, Any],
    *,
    scenarios: list[str] | None = None,
    anchor_pattern_id: str | None = None,
) -> dict[str, Any]:
    """Fill time_start/time_end from anchor_patterns.investigation_window when missing."""
    from correlation_engine import anchor_pattern_for_scenarios, apply_investigation_param_aliases, resolve_anchor_params

    pid = anchor_pattern_id or anchor_pattern_for_scenarios(scenarios or [])
    if pid:
        return resolve_anchor_params(pid, params)
    from correlation_engine import load_matrix

    return apply_investigation_param_aliases(params, matrix=load_matrix())


def attach_correlation_fetch_plan(
    payload: dict[str, Any],
    anchor_pattern_id: str | None = None,
) -> None:
    """Attach matrix-driven fetch task queue to payload (correlation_engine.plan_fetch)."""
    from correlation_engine import anchor_pattern_for_scenarios, plan_fetch

    scenarios = payload.get("scenarios") or []
    if payload.get("scenario"):
        scenarios = [payload["scenario"]] + list(scenarios)
    pid = anchor_pattern_id or anchor_pattern_for_scenarios(scenarios)
    if not pid:
        return
    bundle_id = payload.get("bundle_id")
    asset_ids = None
    if bundle_id:
        asset_ids = list(load_bundle(bundle_id).get("asset_ids") or [])
    params = resolve_investigation_params(
        payload.get("params") or {},
        anchor_pattern_id=pid,
    )
    tasks = plan_fetch(pid, params, asset_ids=asset_ids)
    if tasks:
        payload["correlation_fetch_plan"] = tasks
        payload["correlation_anchor_pattern"] = pid


def _merge_trace_evidence(
    *parts: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    from s4_fetch_bootstrap import _merge_evidence_bundles

    return _merge_evidence_bundles(*parts) if parts else {}


def _scenario_for_anchor_pattern_id(anchor_pattern_id: str | None) -> str | None:
    """Prefer configured priority; retain the S-prefix fallback if metadata fails."""
    if not anchor_pattern_id:
        return None
    try:
        from correlation_engine import load_scenario_priority

        for scenario, pattern_id in load_scenario_priority():
            if pattern_id == anchor_pattern_id:
                return scenario
    except Exception:
        pass
    prefix = str(anchor_pattern_id).split("_", 1)[0]
    return prefix if prefix.startswith("S") else None


def _has_target_context(params: dict[str, Any]) -> bool:
    for key in ("target_ip", "host_ip", "host", "host_name", "victim_ip", "_victim_host"):
        value = params.get(key)
        if _present_target_value(value):
            return True
    for key in ("hosts", "seed_hosts", "target_ips"):
        values = params.get(key)
        if isinstance(values, list) and any(_present_target_value(v) for v in values):
            return True
    return False


def _has_source_ip_context(params: dict[str, Any]) -> bool:
    for key in ("attacker_ip", "src_ip", "ip", "client_ip"):
        value = params.get(key)
        if _present_target_value(value):
            return True
    values = params.get("attacker_ips")
    return isinstance(values, list) and any(_present_target_value(v) for v in values)


def _present_target_value(value: Any) -> bool:
    if value in (None, ""):
        return False
    text = str(value).strip().lower()
    return bool(text and text not in {"-", "null", "none", "unknown"})


def _sync_host_context_from_targets(params: dict[str, Any]) -> dict[str, Any]:
    """Fill host-oriented aliases from target_ip/target_ips without overriding user input."""
    out = dict(params)
    targets: list[str] = []
    target_ips = out.get("target_ips")
    if isinstance(target_ips, list):
        targets.extend(str(v).strip() for v in target_ips if _present_target_value(v))
    elif _present_target_value(target_ips):
        targets.append(str(target_ips).strip())
    if _present_target_value(out.get("target_ip")):
        target = str(out["target_ip"]).strip()
        if target not in targets:
            targets.insert(0, target)
    if not targets:
        return out
    out.setdefault("target_ip", targets[0])
    if not out.get("target_ips"):
        out["target_ips"] = list(targets)
    if not out.get("hosts"):
        out["hosts"] = list(targets)
    if not out.get("seed_hosts"):
        out["seed_hosts"] = list(targets)
    out.setdefault("host_ip", targets[0])
    out.setdefault("host", targets[0])
    return out


def _host_set_from_params(params: dict[str, Any]) -> set[str]:
    hosts: set[str] = set()
    for key in ("target_ip", "host_ip", "host", "victim_ip", "_victim_host"):
        if _present_target_value(params.get(key)):
            hosts.add(str(params[key]).strip())
    for key in ("hosts", "seed_hosts", "target_ips"):
        values = params.get(key)
        if isinstance(values, list):
            hosts.update(str(v).strip() for v in values if _present_target_value(v))
        elif _present_target_value(values):
            hosts.add(str(values).strip())
    for key, value in (params.get("host_ips") or {}).items():
        if _present_target_value(key):
            hosts.add(str(key).strip())
        if _present_target_value(value):
            hosts.add(str(value).strip())
    return hosts


def _nested_event_value(event: dict[str, Any], key: str) -> Any:
    if key in event:
        return event.get(key)
    if "." not in key:
        return None
    current: Any = event
    for part in key.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _first_event_value(event: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = _nested_event_value(event, key)
        if _present_target_value(value):
            return str(value).strip()
    return ""


def _event_text(event: dict[str, Any]) -> str:
    values = []
    for key in (
        "message",
        "raw_log",
        "raw_line",
        "command_line",
        "command",
        "url",
        "request_uri",
        "path",
        "payload",
        "raw_behavior",
        "event_type",
        "result",
    ):
        value = event.get(key)
        if value not in (None, ""):
            values.append(str(value))
    return " ".join(values)


def _strip_host_port(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if ":" in text and text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            return host
    return text


def _is_internal_lateral_target_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return bool(addr.is_private and not (addr.is_loopback or addr.is_link_local or addr.is_reserved))


def _event_matches_source_host(event: dict[str, Any], source_hosts: set[str]) -> bool:
    if not source_hosts:
        return False
    candidates = {
        _strip_host_port(
            _first_event_value(
                event,
                "host_ip",
                "_victim_host",
                "target_ip",
                "upstream_addr",
                "__source__",
                "host",
                "host_name",
                "hostname",
            )
        )
    }
    return bool(candidates & source_hosts)


def _extract_lateral_hint_ips(text: str) -> list[str]:
    """Use shared SSH parsing, with a degraded IPv4 hint scan on parser failure.

    Only internal targets survive; this selects bounded follow-up evidence, not
    a lateral-movement verdict. Stable deduplication preserves discovery order.
    """
    lower = str(text or "").lower()
    try:
        from trace_profile import extract_ssh_lateral_targets  # noqa: E402

        ips = [ip for _user, ip in extract_ssh_lateral_targets(text or "")]
    except Exception:
        ips = []
    if any(token in lower for token in LATERAL_HINT_TOKENS):
        ips.extend(IPV4_RE.findall(text or ""))

    out: list[str] = []
    seen: set[str] = set()
    for ip in ips:
        if not _is_internal_lateral_target_ip(ip) or ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


def _lateral_targets_from_evidence_hints(
    evidence: dict[str, list[dict[str, Any]]],
    params: dict[str, Any],
) -> list[str]:
    if params.get("auto_expand_lateral_targets") is False:
        return []
    source_hosts = _host_set_from_params(params)
    ordered_targets: list[str] = []
    candidate_sources: dict[str, set[str]] = {}
    for asset_type in ("host_exec", "web_access_log", "waf_alert"):
        for event in evidence.get(asset_type) or []:
            if not isinstance(event, dict) or not _event_matches_source_host(event, source_hosts):
                continue
            for ip in _extract_lateral_hint_ips(_event_text(event)):
                if ip in source_hosts:
                    continue
                if ip not in candidate_sources:
                    ordered_targets.append(ip)
                    candidate_sources[ip] = set()
                candidate_sources[ip].add(asset_type)

    targets: list[str] = []
    for ip in ordered_targets:
        is_ambiguous_prefix = (
            any(other.startswith(ip) and other != ip for other in ordered_targets)
        )
        if not is_ambiguous_prefix:
            targets.append(ip)
    return targets


def _is_accepted_ssh_event(event: dict[str, Any]) -> bool:
    event_type = str(event.get("event_type") or "").strip().lower()
    result = str(event.get("result") or "").strip().lower()
    text = _event_text(event).lower()
    if result in {"accepted", "success", "succeeded", "ok"}:
        return True
    if event_type in {"ssh_login_success", "ssh_auth_success", "ssh_accepted", "accepted_password"}:
        return True
    return "accepted password" in text and "ssh" in text


def _lateral_targets_from_accepted_ssh(
    evidence: dict[str, list[dict[str, Any]]],
    params: dict[str, Any],
) -> list[str]:
    """Extract SSH victim hosts, preferring source-record identity over query tags.

    ``_victim_host`` is a fetch-context tag and can describe the source query
    host rather than the host encoded by a syslog event. Structured
    ``host_ip``/``__source__`` fields therefore take precedence.
    """
    source_hosts = _host_set_from_params(params)
    if not source_hosts:
        return []
    targets: list[str] = []
    seen: set[str] = set()
    for asset_type in ("syslog_risk_alert", "ssh_auth"):
        for event in evidence.get(asset_type) or []:
            if not isinstance(event, dict) or not _is_accepted_ssh_event(event):
                continue
            src = _first_event_value(event, "src_ip", "source_ip", "remote_addr", "rhost", "fields.src_ip")
            if not src:
                # Some syslog-risk rows keep auth identity only in message;
                # reuse the canonical parser before declaring no lateral match.
                try:
                    from syslog_risk_normalize import syslog_to_ssh_auth_event

                    src = str((syslog_to_ssh_auth_event(event) or {}).get("src_ip") or "")
                except Exception:
                    src = ""
            if src not in source_hosts:
                continue
            target = _first_event_value(
                event,
                "host_ip",
                "__source__",
                "target_ip",
                "_victim_host",
                "host",
                "hostname",
                "host_name",
            )
            if not target or target in source_hosts or target in seen:
                continue
            seen.add(target)
            targets.append(target)
    return targets


def _asset_ids_for_types(asset_ids: list[str], asset_types: set[str] | frozenset[str]) -> list[str]:
    selected: list[str] = []
    for asset_id in asset_ids:
        try:
            asset_type = str(load_asset(str(asset_id)).get("asset_type") or "")
        except FileNotFoundError:
            continue
        if asset_type in asset_types:
            selected.append(str(asset_id))
    return selected


def _asset_ids_covering_ssh_auth(asset_ids: list[str]) -> list[str]:
    """Return assets that can provide SSH auth, including syslog substitutes.

    TigerSec exposes ``ssh_auth`` through ``syslog_risk_alert``.  The asset-list
    fetch path must therefore inspect ``covers_asset_types`` instead of looking
    only for a literal ``asset_type=ssh_auth`` asset.
    """
    selected: list[str] = []
    for asset_id in asset_ids:
        try:
            asset = load_asset(str(asset_id))
        except FileNotFoundError:
            continue
        covered = {str(asset.get("asset_type") or "")}
        covered.update(str(value) for value in (asset.get("covers_asset_types") or []))
        if "ssh_auth" in covered:
            selected.append(str(asset_id))
    return selected


def _bounded_trace_params(params: dict[str, Any]) -> dict[str, Any]:
    """Keep forced lateral queries limited to the active investigation window."""
    out = {
        key: params[key]
        for key in ("time_start", "time_end", "limit")
        if params.get(key) not in (None, "")
    }
    out.setdefault("limit", 2000)
    return out


def _build_forced_asset_tasks(
    asset_ids: list[str],
    params: dict[str, Any],
    *,
    join_id: str,
    forced_template_by_type: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Build connector-aware tasks while allowing a semantic query override.

    ``build_fetch_plan`` normally prefers a risk query for syslog assets when a
    host is present.  Lateral verification needs the SSH-auth index instead,
    so this helper keeps connector selection from the registry but explicitly
    selects the auth template where the asset declares support for it.
    """
    from template_select import build_fetch_plan

    if not asset_ids:
        return []
    plan = build_fetch_plan(
        asset_ids,
        params,
        load_asset=load_asset,
        load_connector=load_connector,
        load_templates=load_templates,
    )
    forced = forced_template_by_type or {}
    tasks: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in plan:
        asset_id = str(item.get("asset_id") or "")
        try:
            asset = load_asset(asset_id)
            asset_type = str(asset.get("asset_type") or "")
        except FileNotFoundError:
            continue
        requested_template = forced.get(asset_type)
        declared_templates = {str(value) for value in (asset.get("query_template_ids") or [])}
        template_id = (
            requested_template
            if requested_template in declared_templates
            else str(item.get("template_id") or "")
        )
        key = (asset_id, str(item.get("connector_id") or ""), template_id)
        if not template_id or key in seen:
            continue
        seen.add(key)
        tasks.append(
            {
                **item,
                "join_id": join_id,
                "side": "right",
                "template_id": template_id,
                "params": dict(params),
            }
        )
    return tasks


def _waf_request_scope_tokens(events: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    """Extract stable host/path tokens for filtering a time-only WAF fallback.

    The WAF target query can legitimately return no rows when ``upstream_addr``
    is empty on a request, even though the same request is present in gateway
    access logs. Host/path tokens provide a bounded application-side join for
    that degraded query without treating every WAF row in the time window as
    evidence for this incident.
    """
    from urllib.parse import urlparse
    from correlation_engine import normalize_url_path

    hosts: set[str] = set()
    paths: set[str] = set()
    for event in events or []:
        if not isinstance(event, dict):
            continue
        values = [
            event.get(key)
            for key in (
                "url",
                "request_uri",
                "path",
                "raw_behavior",
                "raw_log",
            )
        ]
        for value in values:
            text = str(value or "").strip()
            if not text:
                continue
            candidates = re.findall(r"https?://[^\s'\"<>]+", text, flags=re.I)
            if not candidates and text.startswith("/"):
                candidates = [text]
            for candidate in candidates:
                token = candidate.rstrip(",;)]}")
                parsed = urlparse(token if "://" in token else f"https://{token}")
                if parsed.netloc:
                    hosts.add(parsed.netloc.lower().rstrip("."))
                if parsed.path:
                    normalized_path = normalize_url_path(parsed.path)
                    if normalized_path:
                        paths.add(normalized_path)
        for key in ("http_host", "victim_host", "host"):
            value = str(event.get(key) or "").strip().lower().rstrip(".")
            if value:
                hosts.add(value)
    return hosts, paths


def _waf_event_matches_fallback_scope(
    event: dict[str, Any],
    *,
    target_ip: str | None,
    source_ips: set[str],
    scope_hosts: set[str],
    scope_paths: set[str],
) -> bool:
    """Apply target/source plus host/path constraints to fallback WAF rows."""
    from trace_d1_bootstrap import victim_field_matches

    target_fields = [
        event.get(key)
        for key in ("target_ip", "upstream_addr", "dst_ip", "upstream_host")
        if event.get(key) not in (None, "", "-")
    ]
    if target_ip and target_fields:
        if not victim_field_matches(event, target_ip):
            return False

    event_source_values = [
        normalize_ip(event.get(key))
        for key in ("src_ip", "source_ip", "remote_addr", "client_ip", "ip")
    ]
    event_sources = {value for value in event_source_values if value}
    if source_ips and event_sources and not event_sources.intersection(source_ips):
        return False

    event_hosts, event_paths = _waf_request_scope_tokens([event])
    if scope_hosts and event_hosts and scope_hosts.intersection(event_hosts):
        if not scope_paths or event_paths.intersection(scope_paths):
            return True
    if scope_paths and event_paths:
        for event_path in event_paths:
            for scope_path in scope_paths:
                if event_path == scope_path or event_path in scope_path or scope_path in event_path:
                    return True
    if target_ip and target_fields:
        return victim_field_matches(event, target_ip)
    return False


def _waf_target_query_fallback_reason(asset_ids: list[str]) -> str:
    """Explain why a WAF target query is being retried in degraded mode."""
    attempts = current_fetch_attempt_collection() or []
    waf_ids = set(_asset_ids_for_types(asset_ids, {"waf_alert"}))
    target_attempts = [
        attempt
        for attempt in attempts
        if attempt.get("asset_id") in waf_ids
        and attempt.get("template_id") == "waf_gateway_plugin_by_target_ip_time"
    ]
    if any(attempt.get("status") == "failed" for attempt in target_attempts):
        return "targeted_upstream_query_failed"
    if any(
        attempt.get("status") == "success"
        and int(attempt.get("returned_event_count") or 0) == 0
        for attempt in target_attempts
    ):
        return "targeted_upstream_query_returned_no_rows"
    return "targeted_upstream_query_no_target_match"


def _fetch_asset_list_waf_target_fallback(
    asset_ids: list[str],
    params: dict[str, Any],
    evidence: dict[str, list[dict[str, Any]]],
    *,
    resolve_secrets: bool,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any] | None]:
    """Recover WAF evidence when an indexed upstream query has no match.

    The first retry uses the attacker IP because it is selective and preserves
    the WAF source scope. If no source IP is available, the retry uses the
    bounded time window and filters rows against target_ip, gateway host, and
    normalized request path. The fallback is deliberately separate from the
    primary query so fetch statistics expose both attempts and a no-result
    fallback is not mistaken for a connector failure.
    """
    if evidence.get("waf_alert"):
        return {}, None
    if not params.get("time_start"):
        return {}, None
    waf_asset_ids = _asset_ids_for_types(asset_ids, {"waf_alert"})
    if not waf_asset_ids:
        return {}, None

    target_ip = str(params.get("target_ip") or "").strip() or None
    web_events = list(evidence.get("web_access_log") or [])
    source_ips: list[str] = []
    for key in ("attacker_ip", "src_ip", "client_ip", "ip"):
        normalized = normalize_ip(params.get(key))
        if normalized and normalized not in source_ips:
            source_ips.append(normalized)
    if not source_ips and target_ip and web_events:
        try:
            from trace_d1_bootstrap import extract_attacker_ips_from_d1

            source_ips = extract_attacker_ips_from_d1(web_events, [], target_ip=target_ip)
        except Exception:
            source_ips = []
    source_ip_set = set(source_ips)
    scope_hosts, scope_paths = _waf_request_scope_tokens(web_events)
    base_params = _bounded_trace_params(params)
    fallback_tasks: list[dict[str, Any]] = []
    fallback_mode = "time_window_scope_filter"
    if source_ips:
        fallback_mode = "attacker_ip_time"
        for source_ip in source_ips:
            fallback_tasks.extend(
                _build_forced_asset_tasks(
                    waf_asset_ids,
                    {**base_params, "src_ip": source_ip},
                    join_id="victim_host_to_waf_by_ip_fallback",
                    forced_template_by_type={"waf_alert": "waf_gateway_plugin_by_ip_time"},
                )
            )
    else:
        fallback_tasks.extend(
            _build_forced_asset_tasks(
                waf_asset_ids,
                base_params,
                join_id="victim_host_to_waf_by_time_fallback",
                forced_template_by_type={"waf_alert": "waf_gateway_plugin_by_time"},
            )
        )
    if not fallback_tasks:
        return {}, {
            "attempted": False,
            "used": False,
            "reason": _waf_target_query_fallback_reason(asset_ids),
            "fallback_mode": fallback_mode,
            "fallback_template_ids": [],
            "attacker_ips": source_ips,
            "candidate_event_count": 0,
            "matched_event_count": 0,
        }

    candidate_evidence = data_fetch.fetch_correlation_plan_evidence(
        fallback_tasks,
        resolve_secrets=resolve_secrets,
    )
    candidate_waf = list(candidate_evidence.get("waf_alert") or [])
    from waf_enrich import enrich_evidence_waf_targets

    enrich_input = {
        "waf_alert": candidate_waf,
        "web_access_log": web_events,
    }
    enrich_evidence_waf_targets(enrich_input)
    candidate_waf = list(enrich_input.get("waf_alert") or [])
    matched_waf = [
        event
        for event in candidate_waf
        if _waf_event_matches_fallback_scope(
            event,
            target_ip=target_ip,
            source_ips=source_ip_set,
            scope_hosts=scope_hosts,
            scope_paths=scope_paths,
        )
    ]
    reason = _waf_target_query_fallback_reason(asset_ids)
    metadata = {
        "attempted": True,
        "used": bool(matched_waf),
        "reason": reason,
        "fallback_mode": fallback_mode,
        "fallback_template_ids": sorted({str(task.get("template_id") or "") for task in fallback_tasks}),
        "attacker_ips": source_ips,
        "candidate_event_count": len(candidate_waf),
        "matched_event_count": len(matched_waf),
        "filter_scope": {
            "target_ip": target_ip,
            "hosts": sorted(scope_hosts),
            "paths": sorted(scope_paths),
        },
        "correlation_fetch_plan": fallback_tasks,
    }
    if not matched_waf:
        return {}, metadata
    return {"waf_alert": matched_waf}, metadata


def _fetch_asset_list_lateral_evidence(
    asset_ids: list[str],
    params: dict[str, Any],
    evidence: dict[str, list[dict[str, Any]]],
    *,
    resolve_secrets: bool,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any] | None]:
    """Discover SSH lateral targets and fetch their D2 evidence for asset-list mode.

    The bundle path already performs this workflow in ``_fetch_second_hop_impact``.
    Asset-list mode used to bypass it, which made a real ``Accepted`` event on a
    second host invisible when the initial query was scoped to the entry host.
    Source-IP auth discovery is intentionally bounded to the current window;
    only after it identifies a target do we fetch target-host auth and host data.
    """
    auth_asset_ids = _asset_ids_covering_ssh_auth(asset_ids)
    if not auth_asset_ids:
        return {}, None

    source_hosts = sorted(
        host for host in _host_set_from_params(params) if _is_internal_lateral_target_ip(host)
    )
    discovery_tasks: list[dict[str, Any]] = []
    for source_host in source_hosts:
        discovery_params = {
            **_bounded_trace_params(params),
            "src_ip": source_host,
        }
        discovery_tasks.extend(
            _build_forced_asset_tasks(
                auth_asset_ids,
                discovery_params,
                join_id="host_ip_to_ssh_auth_lateral_discovery",
                forced_template_by_type={
                    "syslog_risk_alert": "ssh_auth_by_src_ip_time",
                    "ssh_auth": "ssh_auth_by_src_ip_time",
                },
            )
        )

    discovery_evidence: dict[str, list[dict[str, Any]]] = {}
    if discovery_tasks:
        discovery_evidence = data_fetch.fetch_correlation_plan_evidence(
            discovery_tasks,
            resolve_secrets=resolve_secrets,
        )
    combined = _merge_trace_evidence(evidence, discovery_evidence)

    hinted_targets = _lateral_targets_from_evidence_hints(combined, params)
    accepted_targets = _lateral_targets_from_accepted_ssh(combined, params)
    target_hosts: list[str] = []
    seen = set(_host_set_from_params(params))
    for host in hinted_targets + accepted_targets:
        if host in seen:
            continue
        seen.add(host)
        target_hosts.append(host)

    target_asset_ids = unique_ids(
        _asset_ids_for_types(asset_ids, HOST_IMPACT_ASSET_TYPES)
        + auth_asset_ids
    )
    target_tasks: list[dict[str, Any]] = []
    for target_host in target_hosts:
        target_params = {
            **_bounded_trace_params(params),
            "target_ip": target_host,
            "target_ips": [target_host],
            "hosts": [target_host],
            "seed_hosts": [target_host],
            "host_ip": target_host,
            "host": target_host,
        }
        target_tasks.extend(
            _build_forced_asset_tasks(
                target_asset_ids,
                target_params,
                join_id="host_ip_to_target_impact",
                forced_template_by_type={
                    "syslog_risk_alert": "ssh_auth_by_host_ip_time",
                    "ssh_auth": "ssh_auth_by_host_ip_time",
                },
            )
        )

    target_evidence: dict[str, list[dict[str, Any]]] = {}
    if target_tasks:
        target_evidence = data_fetch.fetch_correlation_plan_evidence(
            target_tasks,
            resolve_secrets=resolve_secrets,
        )
    fetched = _merge_trace_evidence(discovery_evidence, target_evidence)
    # Keep connector fallback rows inside the same bounded window as the
    # initial asset-list fetch before exposing them to trace correlation.
    fetched, _ = _filter_evidence_by_time_window(fetched, params)
    if not fetched and not discovery_tasks and not target_tasks:
        return {}, None

    sources: list[str] = []
    if hinted_targets:
        sources.append("exec_or_web_lateral_hint")
    if accepted_targets:
        sources.append("accepted_ssh_lateral")
    if discovery_tasks:
        sources.append("source_host_ssh_auth_discovery")
    return fetched, {
        "source": "+".join(sources) if sources else "source_host_ssh_auth_discovery",
        "target_host_sources": {
            "exec_or_web_lateral_hint": hinted_targets,
            "accepted_ssh_lateral": accepted_targets,
        },
        "target_hosts": target_hosts,
        "discovery_asset_ids": auth_asset_ids,
        "discovery_query_count": len(discovery_tasks),
        "target_query_count": len(target_tasks),
        "correlation_fetch_plan": discovery_tasks + target_tasks,
        "asset_ids": unique_ids(target_asset_ids),
        "time_window": {
            "time_start": params.get("time_start"),
            "time_end": params.get("time_end"),
        },
    }


def _fetch_second_hop_impact(
    bundle_asset_ids: list[str],
    params: dict[str, Any],
    evidence: dict[str, list[dict[str, Any]]],
    *,
    resolve_secrets: bool,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any] | None]:
    """Fetch host and SSH-auth evidence for targets discovered from entry data."""
    source_hosts = _host_set_from_params(params)
    hinted_targets = _lateral_targets_from_evidence_hints(evidence, params)
    accepted_targets = _lateral_targets_from_accepted_ssh(evidence, params)
    target_hosts: list[str] = []
    seen = set(source_hosts)
    for host in hinted_targets + accepted_targets:
        if host in seen:
            continue
        seen.add(host)
        target_hosts.append(host)
    if not target_hosts:
        return {}, None
    impact_asset_ids = _asset_ids_for_types(bundle_asset_ids, HOST_IMPACT_ASSET_TYPES)
    auth_asset_ids = _asset_ids_covering_ssh_auth(bundle_asset_ids)
    if not impact_asset_ids and not auth_asset_ids:
        return {}, None

    second_hop_params = {
        **params,
        "target_ip": target_hosts[0],
        "target_ips": list(target_hosts),
        "hosts": list(target_hosts),
        "seed_hosts": list(target_hosts),
        "host_ip": target_hosts[0],
        "host": target_hosts[0],
    }
    fetched = data_fetch.fetch_bundle_evidence(
        impact_asset_ids,
        second_hop_params,
        resolve_secrets=resolve_secrets,
    ) if impact_asset_ids else {}
    auth_tasks = _build_forced_asset_tasks(
        auth_asset_ids,
        second_hop_params,
        join_id="host_ip_to_ssh_auth_target",
        forced_template_by_type={
            "syslog_risk_alert": "ssh_auth_by_host_ip_time",
            "ssh_auth": "ssh_auth_by_host_ip_time",
        },
    )
    if auth_tasks:
        fetched = _merge_trace_evidence(
            fetched,
            data_fetch.fetch_correlation_plan_evidence(
                auth_tasks,
                resolve_secrets=resolve_secrets,
            ),
        )
    # Connector-side limits are advisory; reapply the narrowed incident window
    # before second-hop evidence can re-enter the merged investigation scope.
    fetched, _ = _filter_evidence_by_time_window(fetched, second_hop_params)
    sources: list[str] = []
    if hinted_targets:
        sources.append("exec_or_web_lateral_hint")
    if accepted_targets:
        sources.append("accepted_ssh_lateral")
    return fetched, {
        "source": "+".join(sources) if sources else "lateral_target",
        "target_host_sources": {
            "exec_or_web_lateral_hint": hinted_targets,
            "accepted_ssh_lateral": accepted_targets,
        },
        "target_hosts": target_hosts,
        "asset_ids": unique_ids(impact_asset_ids + auth_asset_ids),
        "target_auth_query_count": len(auth_tasks),
        "target_auth_fetch_plan": auth_tasks,
        "time_window": {
            "time_start": second_hop_params.get("time_start"),
            "time_end": second_hop_params.get("time_end"),
        },
    }


def _should_trace_external_ip_impact_bootstrap(
    scenarios: list[str] | None,
    pattern_ids: list[str] | None,
    params: dict[str, Any],
    *,
    full_impact_fetch: bool = False,
) -> bool:
    """Use WAF/gateway as D1 entry to discover victim hosts for S1 impact trace."""
    if not _has_source_ip_context(params):
        return False
    if _has_target_context(params):
        return False
    if not params.get("time_start"):
        return False
    if "S1_external_ip_trace" in (pattern_ids or []):
        return True
    if "S1" in (scenarios or []):
        return True
    return bool(full_impact_fetch)


def _task_asset_type(task: dict[str, Any]) -> str:
    asset_type = str(task.get("asset_type") or "")
    if asset_type:
        return asset_type
    try:
        return str(load_asset(str(task.get("asset_id") or "")).get("asset_type") or "")
    except FileNotFoundError:
        return ""


def _coalesce_trace_tasks(
    tasks: list[dict[str, Any]],
    templates: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Coalesce equivalent persistence queries and narrow-window syslog scans."""
    retained: list[dict[str, Any]] = []
    reused: list[dict[str, Any]] = []
    persistence_groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    syslog_groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    passthrough: list[dict[str, Any]] = []

    for task in tasks:
        asset_type = _task_asset_type(task)
        task_params = task.get("params") or {}
        asset_id = str(task.get("asset_id") or "")
        time_start = str(task_params.get("time_start") or "")
        time_end = str(task_params.get("time_end") or "")
        template_id = str(task.get("template_id") or "")
        if asset_type == "host_persistence" and template_id in {
            "host_persistence_by_host_time",
            "host_persistence_by_host_ip_time",
        }:
            target = str(
                task_params.get("host_ip")
                or task_params.get("host")
                or task_params.get("host_name")
                or ""
            )
            persistence_groups.setdefault((asset_id, target, time_start, time_end), []).append(task)
        elif asset_type == "syslog_risk_alert":
            syslog_groups.setdefault((asset_id, time_start, time_end), []).append(task)
        else:
            passthrough.append(task)

    retained.extend(passthrough)
    for group in persistence_groups.values():
        preferred = next(
            (
                task
                for task in group
                if task.get("template_id") == "host_persistence_by_host_ip_time"
            ),
            group[0],
        )
        retained.append(preferred)
        for task in group:
            if task is preferred:
                continue
            reused.append(
                {
                    **task,
                    "fetch_disposition": "reused_equivalent_asset_query",
                    "reused_by_template_id": preferred.get("template_id"),
                }
            )

    generic_syslog = templates.get("syslog_risk_by_time")
    for group in syslog_groups.values():
        if len(group) < 2 or not generic_syslog:
            retained.extend(group)
            continue
        sample_params = dict(group[0].get("params") or {})
        start = _parse_trace_dt(sample_params.get("time_start"))
        end = _parse_trace_dt(sample_params.get("time_end"))
        narrow_window = bool(start and end and 0 <= (end - start).total_seconds() <= 3600)
        host_ip = next(
            (
                str((task.get("params") or {}).get(key))
                for task in group
                for key in ("host_ip", "host", "host_name")
                if (task.get("params") or {}).get(key)
            ),
            "",
        )
        src_ips = [
            str((task.get("params") or {}).get("src_ip"))
            for task in group
            if (task.get("params") or {}).get("src_ip")
        ]
        if not host_ip:
            for value in src_ips:
                try:
                    if ipaddress.ip_address(value).is_private:
                        host_ip = value
                        break
                except ValueError:
                    continue
        source_host_task = next(
            (
                task
                for task in group
                if task.get("template_id") == "ssh_auth_by_src_ip_time"
                and str((task.get("params") or {}).get("src_ip") or "") == host_ip
            ),
            None,
        )
        host_text_task = next(
            (
                task
                for task in group
                if task.get("template_id") in {"ssh_auth_by_host_time", "ssh_auth_by_host_name_time"}
                and str(
                    (task.get("params") or {}).get("host")
                    or (task.get("params") or {}).get("host_name")
                    or ""
                )
                == host_ip
            ),
            None,
        )
        if narrow_window and source_host_task and host_text_task:
            retained.extend([source_host_task, host_text_task])
            source_template = templates.get("syslog_risk_by_host_ip_time")
            source_params = {
                "host_ip": host_ip,
                "time_start": sample_params.get("time_start"),
                "time_end": sample_params.get("time_end"),
                "limit": max(
                    int((task.get("params") or {}).get("limit") or 2000)
                    for task in group
                ),
            }
            if source_template and params_satisfy_template(source_template, source_params):
                retained.append(
                    {
                        **source_host_task,
                        "join_id": "trace_syslog_source_scope",
                        "template_id": "syslog_risk_by_host_ip_time",
                        "params": source_params,
                    }
                )
            for task in group:
                if task is source_host_task or task is host_text_task:
                    continue
                reused.append(
                    {
                        **task,
                        "fetch_disposition": "reused_complementary_syslog_queries",
                        "reused_by_template_ids": [
                            source_host_task.get("template_id"),
                            host_text_task.get("template_id"),
                            "syslog_risk_by_host_ip_time",
                        ],
                    }
                )
            continue

        selected_template_id = "syslog_risk_by_time"
        selected_template = generic_syslog
        generic_params = {
            "time_start": sample_params.get("time_start"),
            "time_end": sample_params.get("time_end"),
            "limit": max(int((task.get("params") or {}).get("limit") or 2000) for task in group),
        }
        if not narrow_window or not selected_template or not params_satisfy_template(selected_template, generic_params):
            retained.extend(group)
            continue
        combined = {
            **group[0],
            "join_id": "trace_syslog_scope_coalesced",
            "template_id": selected_template_id,
            "params": generic_params,
            "coalesced_join_ids": list(
                dict.fromkeys(str(task.get("join_id") or "") for task in group if task.get("join_id"))
            ),
            "coalesced_template_ids": list(
                dict.fromkeys(
                    str(task.get("template_id") or "")
                    for task in group
                    if task.get("template_id")
                )
            ),
        }
        retained.append(combined)
        for task in group:
            reused.append(
                {
                    **task,
                    "fetch_disposition": "reused_narrow_window_syslog_query",
                    "reused_by_template_id": selected_template_id,
                }
            )

    original_order = {id(task): idx for idx, task in enumerate(tasks)}
    retained.sort(key=lambda task: original_order.get(id(task), len(tasks)))
    return retained, reused


def append_anchor_bundle_assets_for_chain(
    asset_ids: list[str],
    anchor_pattern_id: str | None,
) -> tuple[list[str], list[dict[str, str]]]:
    """Append assets required by the anchor recommended_chain from its default bundle."""
    if not asset_ids or not anchor_pattern_id:
        return list(asset_ids), []
    try:
        from correlation_engine import expand_path, get_anchor_pattern, get_join, load_matrix

        pattern = get_anchor_pattern(anchor_pattern_id) or {}
        bundle_id = str(pattern.get("bundle_id") or "")
        if not bundle_id:
            return list(asset_ids), []
        matrix = load_matrix()
        required_types: set[str] = set()
        for join_id in pattern.get("recommended_chain") or []:
            for step in expand_path(str(join_id), matrix):
                join = get_join(step, matrix) or {}
                for key in ("from_asset_type", "to_asset_type"):
                    asset_type = str(join.get(key) or "")
                    if asset_type:
                        required_types.add(asset_type)
        if not required_types:
            return list(asset_ids), []

        current_types: set[str] = set()
        for asset_id in asset_ids:
            try:
                current_types.add(str(load_asset(asset_id).get("asset_type") or ""))
            except FileNotFoundError:
                continue
        missing_types = required_types - current_types
        if not missing_types:
            return list(asset_ids), []

        merged = list(asset_ids)
        seen = set(merged)
        appended: list[dict[str, str]] = []
        for candidate_id in load_bundle(bundle_id).get("asset_ids") or []:
            if candidate_id in seen:
                continue
            try:
                asset = load_asset(str(candidate_id))
            except FileNotFoundError:
                continue
            asset_type = str(asset.get("asset_type") or "")
            if asset_type not in missing_types:
                continue
            merged.append(str(candidate_id))
            seen.add(str(candidate_id))
            appended.append(
                {
                    "asset_id": str(candidate_id),
                    "asset_type": asset_type,
                    "reason": f"{anchor_pattern_id}:recommended_chain_requires_{asset_type}",
                }
            )
            missing_types.discard(asset_type)
            if not missing_types:
                break
        return merged, appended
    except Exception:
        return list(asset_ids), []


def fetch_scenario_evidence(
    bundle_id: str,
    params: dict[str, Any],
    *,
    scenarios: list[str] | None = None,
    anchor_pattern_id: str | None = None,
    anchor_pattern_ids: list[str] | None = None,
    resolve_secrets: bool = True,
    full_impact_fetch: bool = False,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Fetch host-risk bundles directly and other scenarios by correlation plan.

    S5 screening must query its declared sources even without D1 anchor evidence.
    Falls back to bundle-wide template selection when no scenario plan can be
    derived, preserving backward compatibility for bundles without patterns.

    When ``anchor_pattern_ids`` lists multiple patterns, fetch tasks from each
    recommended_chain are merged (traceability S1+S3 uses this path).
    """
    from correlation_engine import anchor_pattern_for_scenarios, plan_fetch, resolve_anchor_params

    bundle = load_bundle(bundle_id)
    bundle_asset_ids = list(bundle.get("asset_ids") or [])
    fetch_params = resolve_investigation_params(
        normalize_fetch_params(params),
        scenarios=scenarios,
        anchor_pattern_id=anchor_pattern_id,
    )
    scenario_list = scenarios or bundle.get("investigation_scenarios") or []
    pattern_ids = list(anchor_pattern_ids or [])
    if not pattern_ids:
        single = anchor_pattern_id or anchor_pattern_for_scenarios(scenario_list)
        pattern_ids = [single] if single else []

    pid = pattern_ids[0] if pattern_ids else None

    # Host-risk screening owns the complete declared bundle. D1 reverse lookup
    # is a trace/alert enrichment step, not a prerequisite for host evidence;
    # even a successful but empty WAF response must not prune these sources.
    if scenario_list and set(scenario_list) <= {"S5", "S5-HOST"} and all(
        pattern == "S5_host_risk" for pattern in pattern_ids
    ):
        evidence = data_fetch.fetch_bundle_evidence(
            bundle_asset_ids, fetch_params, resolve_secrets=resolve_secrets,
        )
        return evidence, {
            "source": "dataasset", "bundle_id": bundle_id,
            "fetch_strategy": "host_risk_bundle", "correlation_anchor_pattern": pid,
            "correlation_fetch_plan": [], "plan_task_count": 0,
            **build_asset_execution_meta(
                declared_asset_ids=bundle_asset_ids, fetch_asset_ids=bundle_asset_ids,
                executed_asset_ids=bundle_asset_ids,
                skip_reason="not_selected_by_correlation_plan",
            ),
        }

    def _planned_tasks(plan_params: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Keep pattern order, merge duplicate requests and report unexecutable tasks.

        Missing templates/parameters are skipped explicitly; coalescing equivalent
        scans limits redundant reads without moving verdict logic into this layer.
        """
        tasks: list[dict[str, Any]] = []
        seen_task_keys: set[tuple[Any, ...]] = set()
        for pattern_id in pattern_ids:
            per_params = resolve_anchor_params(pattern_id, dict(plan_params))
            for task in plan_fetch(pattern_id, per_params, asset_ids=bundle_asset_ids):
                key = (
                    task.get("join_id"),
                    task.get("template_id"),
                    task.get("asset_id"),
                    tuple(sorted((task.get("params") or {}).items())),
                )
                if key in seen_task_keys:
                    continue
                seen_task_keys.add(key)
                tasks.append(task)
        templates = load_templates().get("templates", {})
        executable: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for task in tasks:
            template = templates.get(str(task.get("template_id") or ""))
            task_params = dict(task.get("params") or {})
            if template and params_satisfy_template(template, task_params):
                executable.append(task)
            else:
                skipped.append(task)
        executable, coalesced = _coalesce_trace_tasks(executable, templates)
        return tasks, executable, skipped + coalesced

    bootstrap_evidence: dict[str, list[dict[str, Any]]] = {}
    bootstrap_meta: dict[str, Any] = {}
    from s4_fetch_bootstrap import fetch_s4_bootstrap, should_s4_bootstrap

    if _should_trace_external_ip_impact_bootstrap(
        scenario_list,
        pattern_ids,
        fetch_params,
        full_impact_fetch=full_impact_fetch,
    ):
        bootstrap_evidence, bootstrap_meta = fetch_s4_bootstrap(
            bundle_asset_ids,
            fetch_params,
            resolve_secrets=resolve_secrets,
            include_host_side=False,
        )
        enriched = bootstrap_meta.get("enriched_params") or {}
        if enriched:
            fetch_params = _sync_host_context_from_targets({**fetch_params, **enriched})

    d1_evidence: dict[str, list[dict[str, Any]]] = {}
    d1_meta: dict[str, Any] = {}
    from trace_d1_bootstrap import fetch_trace_d1_bootstrap, should_trace_d1_bootstrap

    if should_trace_d1_bootstrap(scenario_list, pattern_ids, fetch_params):
        d1_evidence, d1_meta = fetch_trace_d1_bootstrap(
            bundle_asset_ids,
            fetch_params,
            resolve_secrets=resolve_secrets,
        )
        enriched = d1_meta.get("enriched_params") or {}
        if enriched:
            fetch_params = _sync_host_context_from_targets({**fetch_params, **enriched})

    evidence_parts: list[dict[str, list[dict[str, Any]]]] = []
    plan_parts: list[dict[str, Any]] = []
    strategy_parts: list[str] = []
    window_narrowing_meta: dict[str, Any] | None = None
    second_hop_meta: dict[str, Any] | None = None
    reused_correlation_tasks: list[dict[str, Any]] = []
    full_impact_asset_ids: list[str] = []
    full_impact_reused_asset_ids: list[str] = []

    if bootstrap_evidence:
        evidence_parts.append(bootstrap_evidence)
    if bootstrap_meta.get("correlation_fetch_plan"):
        plan_parts.extend(bootstrap_meta.get("correlation_fetch_plan") or [])
    if bootstrap_meta:
        strategy_parts.append("trace_external_ip_impact_bootstrap")
    if any(d1_evidence.values()):
        evidence_parts.append(d1_evidence)
    if d1_meta.get("correlation_fetch_plan"):
        plan_parts.extend(d1_meta.get("correlation_fetch_plan") or [])
    if d1_meta:
        strategy_parts.append("trace_d1_bootstrap")

    # D1 evidence establishes the attacker observation window before any D2 fetch.
    if evidence_parts:
        first_pass_evidence = _merge_trace_evidence(*evidence_parts)
        narrowed_params, window_narrowing_meta = _maybe_narrow_attacker_window(
            fetch_params,
            first_pass_evidence,
        )
        if window_narrowing_meta:
            fetch_params = narrowed_params
            narrowed_evidence, evidence_filter_meta = _filter_evidence_by_time_window(
                first_pass_evidence,
                fetch_params,
            )
            if evidence_filter_meta:
                window_narrowing_meta["evidence_filter"] = evidence_filter_meta
            evidence_parts = [narrowed_evidence]

    _tasks, executable_tasks, skipped_tasks = _planned_tasks(fetch_params)
    for task in skipped_tasks:
        if task.get("fetch_disposition"):
            reused_correlation_tasks.append(task)
    covered_d1_types = {
        asset_type
        for asset_type in ("waf_alert", "web_access_log")
        if any(asset_type in part for part in evidence_parts)
    }
    tasks_to_fetch: list[dict[str, Any]] = []
    for task in executable_tasks:
        try:
            task_asset_type = str(load_asset(str(task.get("asset_id") or "")).get("asset_type") or "")
        except FileNotFoundError:
            task_asset_type = ""
        if task_asset_type in covered_d1_types:
            reused_correlation_tasks.append({**task, "fetch_disposition": "reused_d1_evidence"})
        else:
            tasks_to_fetch.append(task)

    if tasks_to_fetch:
        evidence_parts.append(
            data_fetch.fetch_correlation_plan_evidence(tasks_to_fetch, resolve_secrets=resolve_secrets)
        )
        plan_parts.extend(tasks_to_fetch)
        strategy_parts.append("correlation_fetch_plan")

    # Victim-host investigations may not have a separate D1 phase. In that
    # path, converge as soon as the first matrix evidence establishes the IP range.
    if evidence_parts and window_narrowing_meta is None:
        first_pass_evidence = _merge_trace_evidence(*evidence_parts)
        narrowed_params, window_narrowing_meta = _maybe_narrow_attacker_window(
            fetch_params,
            first_pass_evidence,
        )
        if window_narrowing_meta:
            fetch_params = narrowed_params
            narrowed_evidence, evidence_filter_meta = _filter_evidence_by_time_window(
                first_pass_evidence,
                fetch_params,
            )
            if evidence_filter_meta:
                window_narrowing_meta["evidence_filter"] = evidence_filter_meta
            evidence_parts = [narrowed_evidence]

    if not full_impact_fetch and evidence_parts:
        merged_for_lateral = _merge_trace_evidence(*evidence_parts)
        second_hop_evidence, second_hop_meta = _fetch_second_hop_impact(
            bundle_asset_ids,
            fetch_params,
            merged_for_lateral,
            resolve_secrets=resolve_secrets,
        )
        if second_hop_evidence:
            evidence_parts.append(second_hop_evidence)
            strategy_parts.append("second_hop_impact")

    if full_impact_fetch:
        already_queried_asset_ids = set(task_asset_ids(plan_parts))
        queried_templates_by_asset: dict[str, set[str]] = {}
        for task in plan_parts:
            asset_id = str(task.get("asset_id") or "")
            template_id = str(task.get("template_id") or "")
            if asset_id and template_id:
                queried_templates_by_asset.setdefault(asset_id, set()).add(template_id)

        def _needs_full_impact_query(asset_id: str) -> bool:
            if asset_id not in already_queried_asset_ids:
                return True
            try:
                asset_type = str(load_asset(asset_id).get("asset_type") or "")
            except FileNotFoundError:
                return False
            if asset_type == "syslog_risk_alert":
                queried = queried_templates_by_asset.get(asset_id, set())
                has_syslog_query = any(template_id.startswith("syslog_risk") for template_id in queried)
                has_complementary_auth_queries = {
                    "ssh_auth_by_src_ip_time",
                    "ssh_auth_by_host_time",
                }.issubset(queried)
                return not (has_syslog_query or has_complementary_auth_queries)
            return False

        full_impact_asset_ids = [
            asset_id for asset_id in bundle_asset_ids if _needs_full_impact_query(asset_id)
        ]
        full_impact_reused_asset_ids = [
            asset_id for asset_id in bundle_asset_ids if asset_id in already_queried_asset_ids
        ]
        if full_impact_asset_ids:
            evidence_parts.append(
                data_fetch.fetch_bundle_evidence(
                    full_impact_asset_ids,
                    fetch_params,
                    resolve_secrets=resolve_secrets,
                )
            )
            strategy_parts.append("bundle_full_impact_missing_assets")
        merged_for_lateral = _merge_trace_evidence(*evidence_parts)
        second_hop_evidence, second_hop_meta = _fetch_second_hop_impact(
            bundle_asset_ids,
            fetch_params,
            merged_for_lateral,
            resolve_secrets=resolve_secrets,
        )
        if second_hop_evidence:
            evidence_parts.append(second_hop_evidence)
            strategy_parts.append("second_hop_impact")

    if evidence_parts:
        evidence = _merge_trace_evidence(*evidence_parts)
        second_hop_asset_ids = list((second_hop_meta or {}).get("asset_ids") or [])
        executed_asset_ids = unique_ids(
            task_asset_ids(plan_parts)
            + full_impact_asset_ids
            + second_hop_asset_ids
        )
        fetch_strategy = "+".join(strategy_parts) if strategy_parts else "correlation_fetch_plan"
        meta: dict[str, Any] = {
            "source": "dataasset",
            "fetch_strategy": fetch_strategy,
            "bundle_id": bundle_id,
            "correlation_anchor_pattern": pid,
            "correlation_fetch_plan": plan_parts,
            "plan_task_count": len(plan_parts),
            "skipped_plan_task_count": sum(
                1 for task in skipped_tasks if not task.get("fetch_disposition")
            ),
            **build_asset_execution_meta(
                declared_asset_ids=bundle_asset_ids,
                fetch_asset_ids=bundle_asset_ids,
                executed_asset_ids=executed_asset_ids,
                skip_reason="not_selected_by_correlation_plan",
            ),
        }
        if bootstrap_meta.get("s4_bootstrap"):
            meta["trace_external_ip_impact_bootstrap"] = bootstrap_meta["s4_bootstrap"]
        if d1_meta.get("trace_d1_bootstrap"):
            meta["trace_d1_bootstrap"] = d1_meta["trace_d1_bootstrap"]
        if window_narrowing_meta:
            meta["attacker_ip_window_narrowing"] = window_narrowing_meta
        if second_hop_meta:
            meta["second_hop_impact_fetch"] = second_hop_meta
        if reused_correlation_tasks:
            meta["reused_correlation_tasks"] = reused_correlation_tasks
        if full_impact_fetch:
            meta["full_impact_fetch"] = {
                "queried_asset_ids": full_impact_asset_ids,
                "reused_asset_ids": full_impact_reused_asset_ids,
            }
        enriched_params: dict[str, Any] = {}
        if bootstrap_meta.get("enriched_params"):
            enriched_params.update(bootstrap_meta["enriched_params"])
        if d1_meta.get("enriched_params"):
            enriched_params.update(d1_meta["enriched_params"])
        if window_narrowing_meta:
            enriched_params["time_start"] = window_narrowing_meta["narrowed_time_start"]
            enriched_params["time_end"] = window_narrowing_meta["narrowed_time_end"]
        if enriched_params:
            meta["enriched_params"] = _sync_host_context_from_targets({**fetch_params, **enriched_params})
        if len(pattern_ids) > 1:
            meta["correlation_anchor_patterns"] = pattern_ids
        return evidence, meta

    if should_s4_bootstrap(scenario_list, pattern_ids, fetch_params):
        evidence, s4_meta = fetch_s4_bootstrap(
            bundle_asset_ids,
            fetch_params,
            resolve_secrets=resolve_secrets,
        )
        s4_meta["bundle_id"] = bundle_id
        if len(pattern_ids) > 1:
            s4_meta["correlation_anchor_patterns"] = pattern_ids
        if evidence:
            return evidence, s4_meta

    evidence = data_fetch.fetch_bundle_evidence(
        bundle_asset_ids,
        fetch_params,
        resolve_secrets=resolve_secrets,
    )
    meta = {
        "source": "dataasset",
        "fetch_strategy": "bundle_full_fallback",
        "bundle_id": bundle_id,
        "correlation_anchor_pattern": pid,
        "correlation_fetch_plan": [],
        "plan_task_count": 0,
        "skipped_plan_task_count": len(skipped_tasks),
        **build_asset_execution_meta(
            declared_asset_ids=bundle_asset_ids,
            fetch_asset_ids=bundle_asset_ids,
            executed_asset_ids=bundle_asset_ids,
            skip_reason="not_selected_by_bundle_fallback",
        ),
    }
    if len(pattern_ids) > 1:
        meta["correlation_anchor_patterns"] = pattern_ids
    return evidence, meta


def fetch_template_map(asset_ids: list[str], params: dict[str, Any]) -> dict[str, str]:
    """Select registered templates through the canonical loaders, without fetching."""
    return build_template_map_for_assets(
        asset_ids,
        params,
        load_asset=load_asset,
        load_connector=load_connector,
        load_templates=load_templates,
    )
