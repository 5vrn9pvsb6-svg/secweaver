"""Traceability D1 bootstrap — resolve external attacker_ip from WAF + web_access.

When investigation has victim ``target_ip`` / ``hosts`` but no ``attacker_ip``, fetch
gateway access (and WAF by time) first, then derive attacker IP(s) from D1 logs.
Used by traceability-analysis and evidence-fetch asset-list mode.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from functools import lru_cache
from typing import Any

from dataasset_paths import REPO_ROOT
from fetch import fetch_correlation_plan_evidence
from s4_gateway_bootstrap import resolve_s4_gateway_asset_id
from s4_fetch_bootstrap import (
    MAX_ATTACKER_IPS,
    _assets_by_type,
    _make_task,
    _merge_evidence_bundles,
    should_s4_bootstrap,
    strip_upstream_ip,
)
from normalizer import normalize_ip

# Default public D1 assets (WAF + gateway access).
DEFAULT_D1_ASSET_IDS = [
    "asset-waf-prod-01",
    resolve_s4_gateway_asset_id(),
]
HIGH_RISK_RULES_PATH = REPO_ROOT / "src" / "skills" / "traceability-analysis" / "heuristic-rules.json"
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    )
)

S2_ANCHOR_PATTERN = "S2_web_breach"


def resolve_target_ip(params: dict[str, Any]) -> str | None:
    """Canonical victim IP from target_ip / seed_hosts / hosts (correlation-matrix aliases)."""
    for key in ("target_ip", "seed_hosts", "hosts"):
        val = params.get(key)
        if isinstance(val, list) and val:
            return str(val[0]).strip()
        if val not in (None, ""):
            return str(val).strip()
    return None


def victim_field_matches(ev: dict[str, Any], target_ip: str, victim_fields: list[str] | None = None) -> bool:
    """Match upstream_addr with or without port (192.0.2.91:80)."""
    if not target_ip:
        return True
    fields = victim_fields or ["target_ip", "upstream_addr"]
    needle = str(target_ip).strip()
    for field in fields:
        raw = ev.get(field)
        if raw in (None, ""):
            continue
        text = str(raw).strip()
        ip = strip_upstream_ip(text) or text.split(":")[0]
        if ip == needle or text.startswith(f"{needle}:"):
            return True
    return False


def is_external_ip(ip: str) -> bool:
    try:
        normalized = normalize_ip(ip)
        if not normalized:
            return False
        addr = ipaddress.ip_address(normalized)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except ValueError:
        return False


def is_private_attacker_candidate(ip: str, *, target_ip: str | None = None) -> bool:
    try:
        text = normalize_ip(ip)
        if not text:
            return False
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    if target_ip and text == str(target_ip).strip():
        return False
    return bool(any(addr in network for network in RFC1918_NETWORKS))


def ensure_d1_asset_ids(asset_ids: list[str] | None) -> list[str]:
    merged = list(asset_ids or [])
    seen = set(merged)
    for aid in DEFAULT_D1_ASSET_IDS:
        if aid not in seen:
            merged.append(aid)
            seen.add(aid)
    return merged


def should_trace_d1_bootstrap(
    scenarios: list[str] | None,
    anchor_pattern_ids: list[str] | None,
    params: dict[str, Any],
) -> bool:
    """True when victim is known but attacker_ip is not — run D1 reverse lookup."""
    if params.get("attacker_ip") or params.get("attacker_ips"):
        return False
    if params.get("resolve_attacker_ip") is False:
        return False
    if not resolve_target_ip(params):
        return False
    if not params.get("time_start"):
        return False
    # Victim-known reverse lookup takes priority over S4 time-only intake.
    if resolve_target_ip(params):
        return True
    if should_s4_bootstrap(scenarios, anchor_pattern_ids, params):
        return False
    pids = list(anchor_pattern_ids or [])
    if any(p in ("S2_web_breach", "S5_host_risk", "S1_external_ip_trace") for p in pids):
        return True
    if any(s in ("S2", "S5", "S1") for s in (scenarios or [])):
        return True
    return True


def should_trace_d1_bootstrap_for_asset_fetch(params: dict[str, Any], asset_ids: list[str] | None) -> bool:
    """Asset-list fetch: auto-append D1 when victim known and attacker unknown."""
    if not asset_ids:
        return False
    if params.get("attacker_ip") or params.get("attacker_ips"):
        return False
    if params.get("resolve_attacker_ip") is False:
        return False
    return bool(resolve_target_ip(params) and params.get("time_start"))


def _compile_flags(flags: str) -> int:
    value = 0
    text = (flags or "").lower()
    if "i" in text:
        value |= re.I
    if "m" in text:
        value |= re.M
    if "s" in text:
        value |= re.S
    return value


@lru_cache(maxsize=2)
def _high_risk_exec_patterns() -> tuple[tuple[str, re.Pattern[str], str], ...]:
    try:
        data = json.loads(HIGH_RISK_RULES_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ()
    block = data.get("target_exec_lateral") if isinstance(data, dict) else {}
    compiled: list[tuple[str, re.Pattern[str], str]] = []
    for entry in (block or {}).get("high_risk_exec_rules") or []:
        if not isinstance(entry, dict) or entry.get("enabled", True) is False:
            continue
        try:
            compiled.append(
                (
                    str(entry.get("id") or entry.get("category") or "rule"),
                    re.compile(str(entry["pattern"]), _compile_flags(str(entry.get("flags") or "i"))),
                    str(entry.get("category") or "unknown"),
                )
            )
        except (KeyError, re.error):
            continue
    return tuple(compiled)


def _event_target_ip(ev: dict[str, Any]) -> str | None:
    from trace_profile import extract_host_ip_from_event, is_plausible_ip

    for value in (
        extract_host_ip_from_event(ev),
        ev.get("host_ip"),
        ev.get("_victim_host"),
        ev.get("__source__"),
        ev.get("host"),
    ):
        if value and is_plausible_ip(value):
            return str(value).strip()
    return None


def infer_d1_targets_from_host_exec(
    evidence_bundles: dict[str, list[dict[str, Any]]],
    *,
    max_candidates: int = 3,
) -> list[dict[str, Any]]:
    """Infer victim hosts for D1 reverse lookup from fetched host_exec evidence.

    This is a second-stage asset-list fallback: when an investigation only gives
    a time window, first fetch exec/syslog; if a host shows non-interactive Web
    listener execution plus high-risk commands, use that host as target_ip for
    WAF/gateway reverse lookup.
    """
    events = evidence_bundles.get("host_exec") or []
    if not events:
        return []

    from trace_profile import command_blob, is_non_interactive_exec, is_web_listener_exec, load_trace_profile_template

    by_host: dict[str, dict[str, Any]] = {}
    patterns = _high_risk_exec_patterns()
    profile = load_trace_profile_template("secweaver-host-exec")

    for ev in events:
        host = _event_target_ip(ev)
        if not host:
            continue
        row = by_host.setdefault(
            host,
            {
                "target_ip": host,
                "web_exec_refs": [],
                "high_risk_refs": [],
                "risk_categories": [],
                "first_seen": ev.get("timestamp") or ev.get("time") or "",
            },
        )
        ts = str(ev.get("timestamp") or ev.get("time") or "")
        if ts and (not row.get("first_seen") or ts < row["first_seen"]):
            row["first_seen"] = ts

        ref = str(ev.get("evidence_id") or ev.get("_ref") or "")
        non_interactive = is_non_interactive_exec(ev, profile) is True
        web_listener = is_web_listener_exec(ev, [], profile) and non_interactive
        if web_listener and ref and ref not in row["web_exec_refs"]:
            row["web_exec_refs"].append(ref)

        text = command_blob(ev, profile)
        hit_categories = [category for _, regex, category in patterns if regex.search(text)]
        if hit_categories:
            if ref and ref not in row["high_risk_refs"]:
                row["high_risk_refs"].append(ref)
            for category in hit_categories:
                if category not in row["risk_categories"]:
                    row["risk_categories"].append(category)

    candidates = [
        {
            **row,
            "web_exec_count": len(row.get("web_exec_refs") or []),
            "high_risk_count": len(row.get("high_risk_refs") or []),
        }
        for row in by_host.values()
        if row.get("web_exec_refs") and row.get("high_risk_refs")
    ]
    candidates.sort(
        key=lambda item: (
            -int(item.get("high_risk_count") or 0),
            -int(item.get("web_exec_count") or 0),
            str(item.get("first_seen") or ""),
            str(item.get("target_ip") or ""),
        )
    )
    return candidates[:max_candidates]


def extract_attacker_ips_from_d1(
    web_events: list[dict[str, Any]],
    waf_events: list[dict[str, Any]] | None = None,
    *,
    target_ip: str | None = None,
    include_private: bool = False,
) -> list[str]:
    """Rank attacker IPs from D1 events scoped to victim target_ip."""
    counts: Counter[str] = Counter()
    attacker_fields = ("src_ip", "ip", "remote_addr", "client_ip")

    for ev in list(web_events) + list(waf_events or []):
        if not victim_field_matches(ev, target_ip or ""):
            continue
        for field in attacker_fields:
            ip = ev.get(field)
            if not ip:
                continue
            text = normalize_ip(ip)
            if not text:
                continue
            if is_external_ip(text) or (include_private and is_private_attacker_candidate(text, target_ip=target_ip)):
                counts[text] += 1
    return [ip for ip, _ in counts.most_common(MAX_ATTACKER_IPS)]


def _base_time_params(params: dict[str, Any]) -> dict[str, Any]:
    base = {k: params[k] for k in ("time_start", "time_end", "limit") if params.get(k) not in (None, "")}
    base.setdefault("limit", 5000)
    return base


def fetch_trace_d1_bootstrap(
    bundle_asset_ids: list[str],
    params: dict[str, Any],
    *,
    resolve_secrets: bool = True,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Phase 1: web_access by target_ip + WAF by time. Phase 2: WAF by resolved src_ip."""
    target_ip = resolve_target_ip(params)
    if not target_ip:
        return {}, {"fetch_strategy": "trace_d1_bootstrap", "bootstrap_error": "no_target_ip"}

    asset_ids = ensure_d1_asset_ids(bundle_asset_ids)
    by_type = _assets_by_type(asset_ids)
    web_asset = by_type.get("web_access_log")
    waf_asset = by_type.get("waf_alert")
    base = _base_time_params(params)
    tasks: list[dict[str, Any]] = []

    if web_asset:
        tasks.append(
            _make_task(
                join_id="victim_host_to_web_access_by_target_ip",
                side="left",
                asset_id=web_asset,
                template_id="web_access_by_target_ip_time",
                params={**base, "target_ip": target_ip},
            )
        )
    if waf_asset:
        # Prefer time-only WAF query (upstream_addr SQL index may be missing on some logstores)
        tasks.append(
            _make_task(
                join_id="victim_host_to_waf_by_target_ip",
                side="left",
                asset_id=waf_asset,
                template_id="waf_gateway_plugin_by_time",
                params=base,
            )
        )

    evidence: dict[str, list[dict[str, Any]]] = {}
    if tasks:
        evidence = fetch_correlation_plan_evidence(tasks, resolve_secrets=resolve_secrets)

    from waf_enrich import enrich_evidence_waf_targets

    waf_enrich_stats = enrich_evidence_waf_targets(evidence)
    web_events = list(evidence.get("web_access_log") or [])
    waf_events = list(evidence.get("waf_alert") or [])
    attacker_ips = extract_attacker_ips_from_d1(web_events, waf_events, target_ip=target_ip)
    attacker_ip_scope = "external" if attacker_ips else None
    if not attacker_ips and params.get("allow_private_attacker_ip") is not False:
        attacker_ips = extract_attacker_ips_from_d1(
            web_events,
            waf_events,
            target_ip=target_ip,
            include_private=True,
        )
        if attacker_ips:
            attacker_ip_scope = "private"

    phase2_tasks: list[dict[str, Any]] = []
    if waf_asset and attacker_ips:
        for src_ip in attacker_ips:
            phase2_tasks.append(
                _make_task(
                    join_id="waf_to_web_access_by_ip",
                    side="left",
                    asset_id=waf_asset,
                    template_id="waf_gateway_plugin_by_ip_time",
                    params={**base, "src_ip": src_ip},
                )
            )
    if phase2_tasks:
        phase2 = fetch_correlation_plan_evidence(phase2_tasks, resolve_secrets=resolve_secrets)
        evidence = _merge_evidence_bundles(evidence, phase2)
        enrich_evidence_waf_targets(evidence)
        attacker_ips = extract_attacker_ips_from_d1(
            list(evidence.get("web_access_log") or []),
            list(evidence.get("waf_alert") or []),
            target_ip=target_ip,
        )
        attacker_ip_scope = "external" if attacker_ips else None
        if not attacker_ips and params.get("allow_private_attacker_ip") is not False:
            attacker_ips = extract_attacker_ips_from_d1(
                list(evidence.get("web_access_log") or []),
                list(evidence.get("waf_alert") or []),
                target_ip=target_ip,
                include_private=True,
            )
            if attacker_ips:
                attacker_ip_scope = "private"

    enriched_params = dict(params)
    enriched_params.setdefault("target_ip", target_ip)
    if attacker_ips:
        enriched_params["attacker_ips"] = attacker_ips
        enriched_params.setdefault("attacker_ip", attacker_ips[0])
        enriched_params.setdefault("src_ip", attacker_ips[0])

    meta: dict[str, Any] = {
        "source": "dataasset",
        "fetch_strategy": "trace_d1_bootstrap",
        "correlation_anchor_pattern": S2_ANCHOR_PATTERN,
        "correlation_fetch_plan": tasks + phase2_tasks,
        "plan_task_count": len(tasks) + len(phase2_tasks),
        "trace_d1_bootstrap": {
            "target_ip": target_ip,
            "attacker_ips": attacker_ips,
            "attacker_ip_scope": attacker_ip_scope,
            "web_access_event_count": len(evidence.get("web_access_log") or []),
            "waf_event_count": len(evidence.get("waf_alert") or []),
            "waf_target_enrich": waf_enrich_stats,
            "d1_asset_ids": list(DEFAULT_D1_ASSET_IDS),
        },
        "enriched_params": enriched_params,
    }
    return evidence, meta


def build_attacker_ip_resolution(
    params: dict[str, Any],
    attacker_ip: str | None,
    initial: dict[str, Any] | None,
    data_access: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Structured attacker IP resolution block for traceability JSON output."""
    bootstrap = (data_access or {}).get("trace_d1_bootstrap") or {}
    method = "params"
    if params.get("attacker_ip") and not bootstrap.get("attacker_ips"):
        method = "params"
    elif bootstrap.get("attacker_ips"):
        method = "d1_reverse_lookup_private" if bootstrap.get("attacker_ip_scope") == "private" else "d1_reverse_lookup"
    elif initial and initial.get("attacker_ip"):
        method = str(initial.get("correlation_source") or "heuristic")

    return {
        "resolved": bool(attacker_ip),
        "attacker_ip": attacker_ip,
        "attacker_ips": params.get("attacker_ips") or bootstrap.get("attacker_ips") or [],
        "target_ip": resolve_target_ip(params),
        "method": method,
        "d1_assets": list(DEFAULT_D1_ASSET_IDS),
        "attacker_ip_scope": bootstrap.get("attacker_ip_scope"),
        "web_access_event_count": bootstrap.get("web_access_event_count"),
        "waf_event_count": bootstrap.get("waf_event_count"),
    }
