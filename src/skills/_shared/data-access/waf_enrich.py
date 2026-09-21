"""WAF victim field normalization and target_ip backfill from gateway access."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

UPSTREAM_HOST_IP = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$")
HOST_HEADER = re.compile(r"^Host:\s*(?P<host>\S+)", re.I | re.M)


def strip_upstream_ip(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text or text == "-":
        return None
    m = UPSTREAM_HOST_IP.match(text)
    if m:
        return m.group("ip")
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", text):
        return text
    return None


def parse_http_host_from_url(url: Any) -> str | None:
    text = str(url or "").strip()
    if not text:
        return None
    if "://" not in text:
        text = f"https://{text.lstrip('/')}"
    try:
        parsed = urlparse(text)
    except ValueError:
        return None
    host = parsed.netloc or parsed.hostname
    return str(host).strip() if host else None


def parse_host_from_request_header(header: Any) -> str | None:
    text = str(header or "")
    if not text.strip():
        return None
    m = HOST_HEADER.search(text)
    return m.group("host").strip() if m else None


def resolve_waf_http_host(event: dict[str, Any]) -> str | None:
    for key in ("http_host", "victim_host", "host"):
        val = event.get(key)
        if val not in (None, "", "-"):
            return str(val).strip()
    for key in ("url", "payload"):
        host = parse_http_host_from_url(event.get(key))
        if host:
            return host
    return parse_host_from_request_header(event.get("request.header"))


def canonicalize_waf_victim(event: dict[str, Any]) -> dict[str, Any]:
    """Derive http_host / victim_host; strip upstream_addr port into target_ip."""
    raw_upstream = event.get("upstream_addr")
    if raw_upstream and not event.get("target_ip"):
        ip = strip_upstream_ip(raw_upstream)
        if ip:
            event["target_ip"] = ip
    elif event.get("target_ip"):
        ip = strip_upstream_ip(event["target_ip"])
        if ip:
            event["target_ip"] = ip

    http_host = resolve_waf_http_host(event)
    if http_host:
        event.setdefault("http_host", http_host)
        event.setdefault("victim_host", http_host)
    return event


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _url_path(value: Any) -> str:
    from correlation_engine import normalize_url_path

    return normalize_url_path(str(value or ""))


def _paths_related(waf_url: Any, access_uri: Any) -> bool:
    waf_path = _url_path(waf_url)
    access_path = _url_path(access_uri)
    if not waf_path or not access_path:
        return True
    if waf_path == access_path:
        return True
    return access_path in waf_path or waf_path in access_path


def enrich_waf_events_from_access(
    waf_events: list[dict[str, Any]],
    web_events: list[dict[str, Any]],
    *,
    time_window_seconds: int = 120,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Backfill WAF target_ip from gateway access upstream_addr (same src_ip + URL)."""
    by_src: dict[str, list[dict[str, Any]]] = {}
    for row in web_events:
        src = row.get("src_ip") or row.get("remote_addr") or row.get("ip")
        if src not in (None, ""):
            by_src.setdefault(str(src), []).append(row)

    stats = {"enriched": 0, "already_had_target_ip": 0, "no_match": 0}
    out: list[dict[str, Any]] = []
    for ev in waf_events:
        row = dict(ev)
        if row.get("target_ip"):
            stats["already_had_target_ip"] += 1
            out.append(row)
            continue

        src = row.get("src_ip") or row.get("ip")
        waf_ts = _parse_ts(row.get("timestamp"))
        candidates = by_src.get(str(src or ""), [])
        matched_upstream: str | None = None

        for acc in candidates:
            acc_ts = _parse_ts(acc.get("timestamp") or acc.get("time_local"))
            if waf_ts and acc_ts and abs((acc_ts - waf_ts).total_seconds()) > time_window_seconds:
                continue
            if not _paths_related(row.get("url") or row.get("payload"), acc.get("url") or acc.get("request_uri")):
                continue
            upstream = acc.get("target_ip") or acc.get("upstream_addr")
            ip = strip_upstream_ip(upstream)
            if ip:
                matched_upstream = ip
                break

        if matched_upstream:
            row["target_ip"] = matched_upstream
            row["target_ip_source"] = "web_access_upstream_addr"
            stats["enriched"] += 1
        else:
            stats["no_match"] += 1
        out.append(row)

    return out, stats


def enrich_evidence_waf_targets(evidence: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Enrich waf_alert bundle in-place when web_access_log is present."""
    waf = evidence.get("waf_alert") or []
    web = evidence.get("web_access_log") or []
    if not waf or not web:
        return {"skipped": True, "reason": "missing_waf_or_web"}
    enriched, stats = enrich_waf_events_from_access(waf, web)
    evidence["waf_alert"] = enriched
    return stats
