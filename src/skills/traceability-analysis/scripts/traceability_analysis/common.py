"""Shared JSON, timestamp, host, and evidence-index helpers."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit
from datetime import datetime
from pathlib import Path

from host_normalize import build_trace_host_ip_map, victim_host_from_event  # noqa: E402

UPSTREAM_HOST_IP = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):\d+$")
ABSOLUTE_URL = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def cmd_text(ev: dict) -> str:
    cmd = ev.get("command")
    if isinstance(cmd, list):
        return " ".join(str(c) for c in cmd)
    return str(cmd or ev.get("comm") or "")


def _first_text(ev: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = ev.get(key)
        if value is None or value == "":
            continue
        return str(value)
    return ""


def _short_text(value: object, limit: int = 320) -> str:
    text = str(value or "").replace("\n", "\\n").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def strip_upstream_host(value: object) -> str | None:
    text = str(value or "").strip()
    if not text or text in {"-", "unknown", "null"}:
        return None
    match = UPSTREAM_HOST_IP.match(text)
    return match.group("ip") if match else text


def web_event_victim_host(ev: dict, target_ip: str | None = None) -> str | None:
    """Return the victim upstream host for WAF/web access rows, not the gateway node."""
    for key in ("target_ip", "upstream_addr", "upstream_host", "dst_ip"):
        host = strip_upstream_host(ev.get(key))
        if host:
            return host
    if target_ip:
        return str(target_ip)
    for key in ("host", "dst_host", "hostname", "server"):
        host = strip_upstream_host(ev.get(key))
        if host:
            return host
    return None


def _request_path(raw_url: object) -> str | None:
    text = str(raw_url or "").strip()
    if not text:
        return None
    if ABSOLUTE_URL.match(text):
        return text
    if text.startswith("//"):
        return text
    parts = text.split()
    if len(parts) >= 2 and parts[0].isalpha() and parts[1].startswith("/"):
        return parts[1]
    return text if text.startswith("/") else f"/{text}"


def _request_host(ev: dict) -> str | None:
    for key in (
        "http_host",
        "request_host",
        "host_header",
        "authority",
        "server_name",
        "domain",
        "vhost",
        "host",
    ):
        host = str(ev.get(key) or "").strip()
        if not host or host in {"-", "unknown", "null"}:
            continue
        if ABSOLUTE_URL.match(host):
            host = host.split("://", 1)[1]
        return host.rstrip("/")
    return None


def _request_scheme(ev: dict, host: str | None) -> str:
    for key in ("scheme", "request_scheme", "x_forwarded_proto", "proto", "protocol"):
        raw = str(ev.get(key) or "").strip().lower()
        if raw.startswith("https"):
            return "https"
        if raw.startswith("http"):
            return "http"
    port_hints = " ".join(
        str(ev.get(key) or "")
        for key in ("server_port", "dst_port", "port", "upstream_addr", "target_ip")
    )
    if (host and host.endswith(":443")) or ":443" in port_hints:
        return "https"
    return "http"


def web_event_url(ev: dict) -> str | None:
    """Build a full URL from WAF/web access fields when only request_uri is normalized."""
    raw = ev.get("url") or ev.get("request_uri") or ev.get("uri") or ev.get("path")
    path = _request_path(raw)
    if not path:
        return None
    if ABSOLUTE_URL.match(path):
        return path
    host = _request_host(ev)
    if path.startswith("//"):
        return f"{_request_scheme(ev, host)}:{path}"
    if not host:
        return path
    return f"{_request_scheme(ev, host)}://{host}{path}"


def web_event_gateway_host(ev: dict) -> str | None:
    """Return the public HTTP authority without confusing it with the upstream host."""
    host = _request_host(ev)
    if host:
        return host
    url = web_event_url(ev)
    if not url:
        return None
    try:
        return urlsplit(url).netloc or None
    except ValueError:
        return None


def web_event_request_outcome(ev: dict) -> str:
    """Normalize a WAF/access event to success, blocked, failed, or unknown."""
    action = str(ev.get("action") or ev.get("waf_action") or "").strip().lower()
    if action in {"block", "blocked", "deny", "denied", "drop", "reject", "intercept"}:
        return "blocked"
    if action in {"allow", "allowed", "pass", "passed", "permit"}:
        return "success"

    raw_status = ev.get("status") or ev.get("http_status") or ev.get("status_code")
    try:
        status = int(str(raw_status).split(".", 1)[0])
    except (TypeError, ValueError):
        return "unknown"
    if 200 <= status < 400:
        return "success"
    if status >= 400:
        return "failed"
    return "unknown"


def raw_behavior_text(ev: dict) -> str:
    """Return operator-facing raw behavior: detailed URL, command, connection, file op, or log line."""
    bundle = str(ev.get("_bundle") or ev.get("asset_type") or ev.get("source_type") or "")
    web_like = (
        bundle in {"waf_alert", "web_access_log"}
        or any(ev.get(key) for key in ("url", "request_uri", "uri"))
        or bool((ev.get("method") or ev.get("request_method")) and ev.get("path"))
    )
    if web_like:
        parts: list[str] = []
        method = _first_text(ev, ("method", "request_method", "http_method")).upper()
        url = web_event_url(ev) or _first_text(ev, ("url", "request_uri", "uri", "path"))
        if method:
            parts.append(method)
        if url:
            parts.append(url)
        status = _first_text(ev, ("status", "status_code", "http_status"))
        if status:
            parts.append(f"status={status}")
        action = _first_text(ev, ("action", "waf_action", "disposition"))
        if action:
            parts.append(f"action={action}")
        rule = _first_text(ev, ("rule_name", "rule_id", "attack_type", "threat_type"))
        if rule:
            parts.append(f"rule={_short_text(rule, 160)}")
        payload = _first_text(ev, ("payload", "request_body", "args", "query_string"))
        if payload:
            parts.append(f"payload={_short_text(payload)}")
        if parts:
            return " ".join(parts)

    command = _first_text(ev, ("command_line", "cmdline"))
    if not command:
        command = cmd_text(ev)
    if command:
        return _short_text(command, 600)

    dst = _first_text(ev, ("dst_ip", "remote_ip", "target_ip"))
    dst_port = _first_text(ev, ("dst_port", "remote_port", "target_port"))
    if bundle in {"host_connect", "firewall_log", "network_traffic_audit"} or dst:
        target = f"{dst}:{dst_port}" if dst and dst_port else dst or dst_port
        proto = _first_text(ev, ("protocol", "proto"))
        return " ".join(part for part in (proto, "connect", target) if part)

    query = _first_text(ev, ("query", "qname", "domain", "hostname"))
    if bundle == "dns_log" or query:
        rcode = _first_text(ev, ("rcode", "response_code", "status"))
        qtype = _first_text(ev, ("query_type", "qtype", "type"))
        answer = _first_text(ev, ("response", "answers", "resolved_ip", "answer"))
        parts = ["dns"]
        if qtype:
            parts.append(qtype)
        if query:
            parts.append(query)
        if rcode:
            parts.append(f"rcode={rcode}")
        if answer:
            parts.append(f"answer={_short_text(answer, 180)}")
        return " ".join(parts)

    path = _first_text(ev, ("file_path", "path", "filename", "object_path"))
    if bundle in {"host_file_op", "host_persistence"} or path:
        op = _first_text(ev, ("operation", "op", "action", "event_type"))
        return " ".join(part for part in (op, path) if part)

    message = _first_text(ev, ("message", "raw_line", "raw", "event_detail", "log"))
    return _short_text(message, 600)


def in_window(ts: datetime | None, start: datetime | None, end: datetime | None) -> bool:
    if ts is None:
        return True
    if start and ts < start:
        return False
    if end and ts > end:
        return False
    return True


def near(a: datetime | None, b: datetime | None, seconds: int) -> bool:
    if a is None or b is None:
        return False
    return abs((a - b).total_seconds()) <= seconds


def index_evidence(bundles: dict[str, list]) -> tuple[dict[str, dict], dict[str, str]]:
    """Assign stable refs: waf-001, exec-001, ..."""
    index: dict[str, dict] = {}
    prefix_map = {
        "waf_alert": "waf",
        "web_access_log": "web",
        "host_exec": "exec",
        "host_connect": "connect",
        "host_file_op": "file",
        "host_persistence": "persist",
        "ssh_auth": "ssh",
        "firewall_log": "fw",
        "dns_log": "dns",
        "network_traffic_audit": "nta",
        "asset_inventory": "asset",
    }
    counters: dict[str, int] = {}

    for bundle_type, events in bundles.items():
        prefix = prefix_map.get(bundle_type, bundle_type[:4])
        for ev in events or []:
            counters[prefix] = counters.get(prefix, 0) + 1
            ref = f"{prefix}-{counters[prefix]:03d}"
            enriched = dict(ev)
            enriched["_ref"] = ref
            enriched["_bundle"] = bundle_type
            if "evidence_id" in ev:
                ref = ev["evidence_id"]
                enriched["_ref"] = ref
            index[ref] = enriched
    return index, {v["_ref"]: k for k, v in index.items()}


def build_host_ip_map(bundles: dict, params: dict) -> dict[str, str]:
    return build_trace_host_ip_map(bundles, params)


def event_on_host(ev: dict, host: str, host_ip_map: dict[str, str] | None = None) -> bool:
    victim = victim_host_from_event(ev, host_ip_map)
    if victim and str(victim) == str(host):
        return True
    return str(ev.get("host") or "") == str(host)
