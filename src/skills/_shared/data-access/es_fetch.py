"""Elasticsearch connector: POST index/_search with DSL from query templates."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from typing import Any

from dataasset_paths import DATAASSET_ROOT
from http_transport import NoRedirect, ssl_context


class _NoRedirect(NoRedirect):
    """Compatibility alias for callers that test the ES redirect boundary."""


def _open_request(req: urllib.request.Request, *, timeout: int, context=None):
    """Keep the legacy test hook while using the shared request-local opener."""
    handlers = [_NoRedirect()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)


def render_es_query(value: Any, params: dict[str, Any]) -> Any:
    """Deep-render {placeholder} strings inside es_query JSON."""
    if isinstance(value, str):
        try:
            return value.format(**params)
        except KeyError:
            return value
    if isinstance(value, dict):
        return {k: render_es_query(v, params) for k, v in value.items()}
    if isinstance(value, list):
        return [render_es_query(v, params) for v in value]
    return value


def _coerce_size(body: dict[str, Any]) -> dict[str, Any]:
    out = dict(body)
    size = out.get("size")
    if isinstance(size, str) and size.isdigit():
        out["size"] = int(size)
    return out


def _auth_header(credentials: dict[str, Any]) -> str | None:
    cred_type = credentials.get("type")
    if cred_type not in ("es", "elasticsearch"):
        return None
    api_key = (credentials.get("api_key") or "").strip()
    if api_key:
        token = base64.b64encode(api_key.encode()).decode()
        return f"ApiKey {token}"
    user = credentials.get("username") or ""
    password = credentials.get("password") or ""
    if user:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return f"Basic {token}"
    return None


def _hits_to_events(hits: list[dict[str, Any]], *, time_field: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        source = hit.get("_source")
        if isinstance(source, dict):
            event = dict(source)
        else:
            event = {}
        if time_field and time_field not in event and hit.get("_source", {}).get(time_field):
            event[time_field] = hit["_source"][time_field]
        event.setdefault("_es_index", hit.get("_index"))
        event.setdefault("_es_id", hit.get("_id"))
        events.append(event)
    return events


def _ssl_context(config: dict[str, Any], base_url: str):
    """Delegate the ES TLS boundary to the shared connector transport policy."""
    return ssl_context(
        config,
        base_url,
        verify_keys=("tls_verify",),
        label="es connector endpoint",
        dataasset_root=DATAASSET_ROOT,
    )


def fetch_es(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    es_query: dict[str, Any],
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch one bounded page and retain incomplete-query signals for reports.

    A successful HTTP response may contain partial hits. Keep useful evidence,
    but report timeout, shard failures, server page limits and local truncation;
    callers must not use such a response to prove an absence of activity.
    """
    config = connector.get("config") or {}
    base_url = (config.get("url") or config.get("endpoint") or "").rstrip("/")
    index = config.get("index") or config.get("index_pattern")
    if not base_url or not index:
        raise ValueError("es connector config requires url (or endpoint) and index")

    merged = {**params}
    body = _coerce_size(render_es_query(es_query, merged))
    url = f"{base_url}/{index}/_search"

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    auth = _auth_header(credentials)
    if auth:
        headers["Authorization"] = auth

    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    timeout = int((connector.get("constraints") or {}).get("request_timeout_sec") or 30)
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    context = _ssl_context(config, base_url)
    try:
        with _open_request(req, timeout=timeout, context=context) as resp:
            raw = resp.read().decode("utf-8")
            status = resp.status
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"ES HTTP {exc.code}: {err_body[:500]}") from exc

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"ES response is not JSON: {raw[:200]}") from exc

    hits = (payload.get("hits") or {}).get("hits") or []
    time_field = config.get("time_field") or "@timestamp"
    events = _hits_to_events(hits, time_field=time_field)

    max_rows = int((connector.get("constraints") or {}).get("max_records_per_request") or 500)
    local_truncated = len(events) > max_rows
    if len(events) > max_rows:
        events = events[:max_rows]

    total = (payload.get("hits") or {}).get("total")
    total_value = total.get("value") if isinstance(total, dict) else total
    total_relation = total.get("relation", "eq") if isinstance(total, dict) else "eq"
    timed_out = payload.get("timed_out") is True
    terminated_early = payload.get("terminated_early") is True
    failed_shards = int((payload.get("_shards") or {}).get("failed") or 0)
    reasons: list[str] = []
    if timed_out:
        reasons.append("timeout")
    if terminated_early:
        reasons.append("terminated_early")
    if failed_shards:
        reasons.append("failed_shards")
    if local_truncated:
        reasons.append("local_limit")
    # ES can omit totals (track_total_hits=false); a full page then cannot
    # establish completeness, even if there may be exactly that many hits.
    if isinstance(total_value, int) and not isinstance(total_value, bool):
        if total_value > len(events) or total_relation != "eq":
            reasons.append("total_hits_exceed_returned_or_lower_bound")
    elif len(hits) >= int(body.get("size", 10)):
        reasons.append("page_limit_without_total")

    meta = {
        "url": url,
        "index": index,
        "http_status": status,
        "rows_returned": len(events),
        "total_hits": total,
        "timed_out": timed_out,
        "terminated_early": terminated_early,
        "failed_shards": failed_shards,
        "truncated": local_truncated or any(reason.startswith(("total_hits_", "page_limit_")) for reason in reasons),
        "partial": bool(reasons),
        "incomplete_reasons": reasons,
        "tls_verified": config.get("tls_verify", True) if base_url.lower().startswith("https://") else None,
    }
    return events, meta
