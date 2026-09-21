"""URL, HTTP request, and WAF-request matching helpers."""

from __future__ import annotations

import json
import ipaddress
import re
from datetime import datetime
from typing import Any
from urllib.parse import unquote, urlparse

from .common import _ts_epoch, alert_timestamp, event_timestamp


def _normalize_http_status(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def alert_path_query(alert: dict) -> str:
    for key in ("url", "payload", "query_string"):
        raw = str(alert.get(key) or "").strip()
        if not raw:
            continue
        return _path_query_from_urlish(raw)
    return ""


def _path_query_from_urlish(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parts = raw.split()
    if len(parts) >= 2 and parts[0].upper() in {
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    }:
        raw = parts[1]
    if "://" in raw:
        parsed = urlparse(raw)
        path = parsed.path or "/"
        if parsed.query:
            return f"{path}?{parsed.query}"
        return path
    if raw.startswith("//"):
        parsed = urlparse(f"http:{raw}")
        path = parsed.path or "/"
        if parsed.query:
            return f"{path}?{parsed.query}"
        return path
    return raw


def _url_text(value: str) -> str:
    text = (value or "").lower().replace("+", " ")
    for _ in range(2):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return text.replace("\\", "/")


def urls_correlate(alert_pq: str, web_url: str) -> bool:
    alert_pq = _url_text(_path_query_from_urlish(alert_pq))
    web_url = _url_text(_path_query_from_urlish(web_url))
    if not alert_pq or not web_url:
        return False
    alert_path, _, alert_query = alert_pq.partition("?")
    web_path, _, web_query = web_url.partition("?")
    if alert_path != web_path:
        return False
    if alert_query and web_query:
        if alert_query in web_query or web_query in alert_query:
            return True
        alert_tokens = [t for t in re.split(r"[&=?'\s]+", alert_query) if len(t) >= 4]
        overlap = sum(1 for token in alert_tokens if token in web_query)
        if overlap >= 2:
            return True
    return bool(alert_path)


def _match_attack_url_patterns(text: str, patterns: list[str]) -> list[str]:
    lower = _url_text(text)
    return [p for p in patterns if p.lower() in lower]


def _web_request_method(web_ev: dict) -> str:
    return str(web_ev.get("method") or web_ev.get("request_method") or "GET").upper()


def _alert_request_method(alert: dict) -> str | None:
    for key in ("request.method", "method", "request_method", "http_method"):
        val = alert.get(key)
        if val:
            return str(val).upper()
    req = alert.get("request")
    if isinstance(req, dict) and req.get("method"):
        return str(req["method"]).upper()
    if req and str(req).strip().startswith("{"):
        try:
            req_obj = json.loads(str(req))
        except json.JSONDecodeError:
            req_obj = {}
        if isinstance(req_obj, dict):
            for key in ("method", "request_method", "http_method"):
                val = req_obj.get(key)
                if val:
                    return str(val).upper()
    request_line = alert.get("request_line") or alert.get("request")
    if request_line:
        first = str(request_line).strip().split(maxsplit=1)[0]
        if first.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
            return first.upper()
    return None


def normalize_source_ip(value: Any) -> str:
    """Normalize quoted or lightly decorated client IP fields before joins.

    Some access-log parsers preserve a leading quote from CSV-like records,
    while WAF records contain the bare address. Correlation must remove this
    presentation noise without changing the original evidence payload.
    """
    text = str(value or "").strip().strip('"\'').strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _same_src_ip(alert: dict, web_ev: dict) -> bool:
    src_ip = web_ev.get("src_ip") or web_ev.get("remote_addr")
    alert_ip = alert.get("src_ip") or alert.get("ip")
    if not src_ip or not alert_ip:
        return True
    return normalize_source_ip(alert_ip) == normalize_source_ip(src_ip)


def _alert_path_matches_web(alert: dict, web_url: str) -> bool:
    alert_pq = alert_path_query(alert)
    if alert_pq and urls_correlate(alert_pq, web_url):
        return True
    alert_path = _url_text(_path_query_from_urlish(alert_pq)).partition("?")[0]
    web_path = _url_text(_path_query_from_urlish(web_url)).partition("?")[0]
    return bool(alert_path and web_path and alert_path == web_path)


def _within_tight_seconds(
    web_ts: datetime | None,
    alert_ts: datetime | None,
    tight_seconds: int,
) -> bool:
    web_epoch = _ts_epoch(web_ts)
    alert_epoch = _ts_epoch(alert_ts)
    if web_epoch is None or alert_epoch is None:
        return False
    return abs(web_epoch - alert_epoch) <= tight_seconds


def waf_alert_matches_request(
    alert: dict,
    web_ev: dict,
    *,
    tight_seconds: int | None = None,
) -> bool:
    """True when a WAF alert likely refers to this specific gateway request."""
    if not _same_src_ip(alert, web_ev):
        return False
    web_url = str(web_ev.get("url") or web_ev.get("request_uri") or "")
    if not _alert_path_matches_web(alert, web_url):
        return False
    alert_method = _alert_request_method(alert)
    if alert_method and alert_method != _web_request_method(web_ev):
        return False
    if tight_seconds is None:
        return True
    return _within_tight_seconds(
        event_timestamp(web_ev),
        alert_timestamp(alert),
        tight_seconds,
    )
