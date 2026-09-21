"""Initial access discovery and D1 fallback helpers."""

from __future__ import annotations

import re

from heuristic_rules import format_template, section  # noqa: E402
from host_normalize import (  # noqa: E402
    investigation_host_set,
    is_web_listener_exec,
    victim_host_from_event,
)
from source_adapters.tigersec import (  # noqa: E402
    exec_session_signals,
    initial_access_inference_note,
    is_non_interactive_exec,
)
from trace_d1_bootstrap import is_external_ip, victim_field_matches  # noqa: E402
from normalizer import normalize_ip  # noqa: E402

from .common import (
    cmd_text,
    in_window,
    parse_ts,
    web_event_gateway_host,
    web_event_request_outcome,
    web_event_url,
    web_event_victim_host,
)


GENERIC_SCRIPT_EXTENSIONS = {"php", ".php", "jsp", ".jsp", "asp", ".asp", "aspx", ".aspx"}
SQLI_RE = re.compile(
    r"(\bunion\b\s*(?:all\s*)?\bselect\b|union\+select|information_schema|"
    r"(?:\bor\b|\band\b)\s+[\w'\"()]+\s*=\s*[\w'\"()]+|--\s*(?:\+|-|$))",
    re.I,
)
RCE_RE = re.compile(r"([?&](?:cmd|command|exec|shell)=|;\s*(?:id|whoami|cat|sh|bash)\b|/cmdi/)", re.I)

OUTCOME_RANK = {"success": 0, "unknown": 1, "failed": 2, "blocked": 3}
# A WebShell request proves control was observed, but usually not how the host was
# first compromised. Prefer a successful exploit trigger when both are present.
VECTOR_RANK = {"web_exploit:rce": 0, "web_exploit:sqli": 1, "webshell": 2, "web_exploit": 3}
ATTACKER_IP_FIELDS = ("src_ip", "source_ip", "ip", "client_ip", "remote_addr", "rhost")


def event_attacker_ip(event: dict) -> str | None:
    """Read one canonical attacker IP from WAF or gateway source aliases.

    D1 events may expose the client address under different fields. Centralizing
    this lookup prevents victim-based reverse lookup from writing a raw quoted
    value back into ``initial_access``.
    """
    for field in ATTACKER_IP_FIELDS:
        ip = normalize_ip(event.get(field))
        if ip:
            return ip
    return None


def _web_entry_rank(ev: dict, vector: str, ts: datetime) -> tuple[int, int, datetime]:
    return (
        OUTCOME_RANK.get(web_event_request_outcome(ev), 1),
        VECTOR_RANK.get(vector, 4),
        ts,
    )


def _entry_point_metadata(
    selected_ev: dict,
    selected_vector: str,
    webshell_candidates: list[tuple[datetime, dict]],
) -> dict:
    outcome = web_event_request_outcome(selected_ev)
    if selected_vector in {"web_exploit:rce", "web_exploit:sqli"}:
        role = "compromise_trigger"
        status = "supported" if outcome == "success" else "candidate"
        reason = "successful_exploit_trigger_preferred_over_observed_control_page"
    elif selected_vector == "webshell":
        role = "observed_control_point"
        status = "unresolved"
        reason = "webshell_control_observed_but_original_compromise_not_proven"
    else:
        role = "suspicious_request"
        status = "candidate"
        reason = "earliest_ranked_suspicious_web_request"

    metadata = {
        "entry_point_role": role,
        "first_compromise_point_status": status,
        "selection_reason": reason,
    }
    if webshell_candidates:
        shell_ts, shell_ev = min(webshell_candidates, key=lambda item: item[0])
        metadata.update(
            {
                "first_observed_control_url": web_event_url(shell_ev)
                or shell_ev.get("url")
                or shell_ev.get("path"),
                "first_observed_control_timestamp": shell_ts.isoformat(),
                "first_observed_control_evidence_refs": [shell_ev["_ref"]],
            }
        )
    return metadata


def classify_web_vector(url: str, patterns: list[str]) -> str:
    u = (url or "").lower()
    if match_webshell(u, patterns):
        return "webshell"
    if SQLI_RE.search(url or ""):
        return "web_exploit:sqli"
    if RCE_RE.search(url or ""):
        return "web_exploit:rce"
    return "web_exploit"


def find_initial_access_from_exec(
    index: dict[str, dict],
    patterns: dict,
    t_start: datetime | None,
    t_end: datetime | None,
    host_ip_map: dict[str, str] | None = None,
) -> dict | None:
    """S2 fallback: infer WebShell/RCE from nginx/listener exec when WAF/WEB absent."""
    url_patterns = patterns.get("webshell_url_patterns", [])
    candidates: list[tuple[datetime, dict, str, str]] = []

    for ref, ev in index.items():
        if ev["_bundle"] != "host_exec":
            continue
        if not is_web_listener_exec(ev, url_patterns):
            continue
        ts = parse_ts(ev.get("timestamp"))
        if not in_window(ts, t_start, t_end):
            continue
        host = victim_host_from_event(ev, host_ip_map) or ev.get("host") or "unknown"
        text = cmd_text(ev).lower()
        vector = "webshell" if any(p in text for p in ("s.phtml", "webshell", "uploads/")) else "web_exploit:rce"
        if ts:
            candidates.append((ts, ev, vector, str(host)))

    if not candidates:
        return None

    def _non_interactive_rank(ev: dict) -> int:
        ni = is_non_interactive_exec(ev)
        if ni is True:
            return 2
        if ni is None:
            return 1
        return 0

    candidates.sort(key=lambda x: (x[0], -_non_interactive_rank(x[1])))
    ts, ev, vector, host = candidates[0]
    url = "/uploads/s.phtml" if "s.phtml" in cmd_text(ev).lower() else "/uploads/"
    return {
        "host": host,
        "timestamp": ts.isoformat(),
        "vector": vector,
        "url": url if vector == "webshell" else None,
        "attacker_ip": None,
        "primary_evidence_refs": [ev["_ref"]],
        "supporting_evidence_refs": [],
        "evidence_refs": [ev["_ref"]],
        "correlation_source": "exec_inferred",
        "inference_note": initial_access_inference_note(ev),
        "session_signals": exec_session_signals(ev),
    }


def resolve_execution_hosts(
    params: dict,
    initial: dict | None,
    index: dict[str, dict],
    host_ip_map: dict[str, str],
) -> list[str]:
    if initial and initial.get("host"):
        return [str(initial["host"])]
    seeds = [str(h) for h in (params.get("seed_hosts") or []) if h]
    if seeds:
        return seeds
    for hip in params.get("hosts") or []:
        if hip and str(hip) not in seeds:
            seeds.append(str(hip))
    if seeds:
        return seeds
    web_hosts: set[str] = set()
    for ev in index.values():
        if ev.get("_bundle") != "host_exec":
            continue
        victim = victim_host_from_event(ev, host_ip_map)
        if victim and is_web_listener_exec(ev, []):
            web_hosts.add(victim)
    if web_hosts:
        return sorted(web_hosts)
    return sorted({victim_host_from_event(ev, host_ip_map) for ev in index.values() if victim_host_from_event(ev, host_ip_map)})


def match_webshell(url: str, patterns: list[str]) -> bool:
    u = (url or "").lower()
    for pattern in patterns:
        token = str(pattern or "").lower().strip()
        if not token or token in GENERIC_SCRIPT_EXTENSIONS:
            continue
        if token in u:
            return True
    return False


def find_initial_access(
    bundles: dict,
    index: dict[str, dict],
    attacker_ip: str | None,
    patterns: dict,
    t_start: datetime | None,
    t_end: datetime | None,
    target_ip: str | None = None,
) -> dict | None:
    """Find a suspicious web entry while comparing source IPs canonically."""
    candidates: list[tuple[tuple[int, int, datetime], datetime, dict, str]] = []
    webshell_candidates: list[tuple[datetime, dict]] = []
    url_patterns = patterns.get("webshell_url_patterns", [])
    requested_attacker_ip = normalize_ip(attacker_ip)

    for ref, ev in index.items():
        if ev["_bundle"] not in ("waf_alert", "web_access_log"):
            continue
        src = event_attacker_ip(ev)
        if requested_attacker_ip and src != requested_attacker_ip:
            continue
        if target_ip:
            victim = web_event_victim_host(ev)
            if victim and str(victim) != str(target_ip):
                continue
        ts = parse_ts(ev.get("timestamp"))
        if not in_window(ts, t_start, t_end):
            continue
        url = web_event_url(ev) or ev.get("url") or ev.get("path") or ""
        host = ev.get("host") or ev.get("dst_host") or ev.get("server")
        if not host:
            host = ev.get("hostname")
        if not host and target_ip:
            host = str(target_ip)
        vector = classify_web_vector(url, url_patterns)
        if ts:
            candidates.append((_web_entry_rank(ev, vector, ts), ts, ev, vector))
            if vector == "webshell" and web_event_request_outcome(ev) in {"success", "unknown"}:
                webshell_candidates.append((ts, ev))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[0])
    _, ts, ev, vector = candidates[0]
    url = web_event_url(ev) or ev.get("url") or ev.get("path")
    host = web_event_victim_host(ev, target_ip) or "unknown"
    result = {
        "host": host,
        "timestamp": ts.isoformat(),
        "vector": vector,
        "url": url,
        "attacker_ip": requested_attacker_ip or event_attacker_ip(ev),
        "target_ip": web_event_victim_host(ev, target_ip),
        "gateway_host": web_event_gateway_host(ev),
        "request_outcome": web_event_request_outcome(ev),
        "primary_evidence_refs": [ev["_ref"]],
        "supporting_evidence_refs": [],
        "evidence_refs": [ev["_ref"]],
        "correlation_source": "heuristic_fallback",
    }
    result.update(_entry_point_metadata(ev, vector, webshell_candidates))
    return result


def find_initial_access_from_victim(
    index: dict[str, dict],
    target_ip: str | None,
    patterns: dict,
    t_start: datetime | None,
    t_end: datetime | None,
    attacker_ip: str | None = None,
) -> dict | None:
    """Reverse D1 lookup with canonical source-IP filtering.

    When an attacker IP is supplied, it narrows the victim-host candidates as
    well as the later Join. This avoids selecting a same-target event from a
    different source and ensures the report uses the normalized IP.
    """
    cfg = section("initial_access_from_victim")
    if cfg.get("enabled") is False or not target_ip:
        return None

    victim_fields = list(cfg.get("victim_fields") or ["target_ip", "upstream_addr"])
    requested_attacker_ip = normalize_ip(attacker_ip)
    url_patterns = patterns.get("webshell_url_patterns", [])
    candidates: list[tuple[tuple[int, int, datetime], datetime, dict, str, str]] = []
    webshell_candidates: list[tuple[datetime, dict]] = []

    for ref, ev in index.items():
        if ev["_bundle"] not in ("waf_alert", "web_access_log"):
            continue
        if not victim_field_matches(ev, str(target_ip), victim_fields):
            continue
        ts = parse_ts(ev.get("timestamp"))
        if not in_window(ts, t_start, t_end) or ts is None:
            continue
        attacker = event_attacker_ip(ev)
        if requested_attacker_ip and attacker != requested_attacker_ip:
            continue
        url = web_event_url(ev) or ev.get("url") or ev.get("path") or ""
        vector = classify_web_vector(url, url_patterns)
        candidates.append((_web_entry_rank(ev, vector, ts), ts, ev, vector, attacker or ""))
        if vector == "webshell" and web_event_request_outcome(ev) in {"success", "unknown"}:
            webshell_candidates.append((ts, ev))

    if not candidates:
        return None

    candidates.sort(key=lambda x: (x[0], x[1]))
    _, ts, ev, vector, attacker = candidates[0]
    tpl_key = "description_template_waf" if ev["_bundle"] == "waf_alert" else "description_template_web"
    description = format_template(
        str(cfg.get(tpl_key) or "受害 upstream {target_ip} 反查 D1：攻击源 {attacker_ip}"),
        target_ip=target_ip,
        attacker_ip=attacker or "unknown",
        url=web_event_url(ev) or ev.get("url") or ev.get("path") or "",
        vector=vector,
    )
    conf = float(cfg.get("confidence_waf") if ev["_bundle"] == "waf_alert" else cfg.get("confidence_web_access") or 0.9)
    result = {
        "host": str(target_ip),
        "timestamp": ts.isoformat(),
        "vector": vector,
        "url": web_event_url(ev) or ev.get("url") or ev.get("path"),
        "attacker_ip": attacker or requested_attacker_ip,
        "target_ip": str(target_ip),
        "gateway_host": web_event_gateway_host(ev),
        "request_outcome": web_event_request_outcome(ev),
        "primary_evidence_refs": [ev["_ref"]],
        "supporting_evidence_refs": [],
        "evidence_refs": [ev["_ref"]],
        "correlation_source": "victim_target_ip",
        "inference_note": description,
        "confidence": conf,
    }
    result.update(_entry_point_metadata(ev, vector, webshell_candidates))
    return result


def d1_reverse_lookup_gap(target_ip: str | None, index: dict[str, dict]) -> str | None:
    """Return structured data gap when target_ip set but no WAF/WEB rows match (ops template in heuristic-rules)."""
    if not target_ip:
        return None
    cfg = section("initial_access_from_victim")
    victim_fields = list(cfg.get("victim_fields") or ["target_ip", "upstream_addr"])
    for ev in index.values():
        if ev.get("_bundle") not in ("waf_alert", "web_access_log"):
            continue
        if victim_field_matches(ev, str(target_ip), victim_fields):
            return None
    tpl = str(cfg.get("no_match_gap_template") or "d1_reverse_lookup:no_waf_or_web_for_target_ip={target_ip}")
    return format_template(tpl, target_ip=target_ip)


def _exec_inferred_confidence(initial: dict) -> float:
    cfg = section("initial_access_exec_inferred")
    non_interactive = (initial.get("session_signals") or {}).get("non_interactive")
    if non_interactive is True:
        return float(cfg.get("confidence_non_interactive") or 0.90)
    if non_interactive is False:
        return float(cfg.get("confidence_interactive") or 0.85)
    return float(cfg.get("confidence_default") or 0.88)


def _initial_access_description(initial: dict) -> str:
    src = initial.get("correlation_source", "")
    attacker = initial.get("attacker_ip")
    url = initial.get("url") or "WEB"
    vector = initial.get("vector") or "web_exploit"
    attacker_text = str(attacker) if attacker else "未知来源"
    attacker_scope = "外网" if attacker and is_external_ip(str(attacker)) else "攻击源"
    if src == "matrix":
        return f"matrix 关联：{attacker_scope} {attacker_text} 访问 {url}（{vector}）"
    if src == "exec_inferred":
        note = initial.get("inference_note") or "exec 推断"
        return f"Web 入口（exec 推断）：{initial.get('host')} {url}（{vector}）— {note}"
    if src in ("victim_target_ip", "matrix+victim_target_ip"):
        note = initial.get("inference_note") or f"受害 upstream {initial.get('target_ip')} 反查 D1"
        return note
    if src == "matrix+heuristic":
        return f"{attacker_scope} {attacker_text} 访问 {url}（{vector}）"
    return f"{attacker_scope} {attacker_text} 访问 {url}（{vector}）"
