"""HTTP API connector fetch."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from http_transport import open_secure_request


def _render_http_value(value: Any, params: dict[str, Any]) -> Any:
    if isinstance(value, str):
        try:
            return value.format(**params)
        except KeyError:
            return value
    if isinstance(value, dict):
        return {k: _render_http_value(v, params) for k, v in value.items()}
    if isinstance(value, list):
        return [_render_http_value(v, params) for v in value]
    return value


def _extract_events(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "alerts", "items", "records", "results", "events"):
        val = payload.get(key)
        if isinstance(val, list):
            return [x for x in val if isinstance(x, dict)]
    return [payload]


def fetch_http_api(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    http_spec: dict[str, Any],
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    config = connector.get("config") or {}
    base_url = config.get("base_url", "").rstrip("/")
    method = (http_spec.get("method") or "GET").upper()
    path = _render_http_value(http_spec.get("path") or "", params)
    if not path.startswith("/"):
        path = "/" + path
    url = base_url + path

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    cred_type = credentials.get("type")
    token = credentials.get("token") or credentials.get("access_token") or ""
    if cred_type == "http_api" and token:
        auth_method = credentials.get("auth_method") or config.get("auth") or "bearer"
        if auth_method in ("bearer", "oauth2_client_credentials"):
            headers["Authorization"] = f"Bearer {token}"
        else:
            headers["Authorization"] = token

    body_obj = http_spec.get("body")
    data: bytes | None = None
    if body_obj is not None:
        rendered_body = _render_http_value(body_obj, params)
        data = json.dumps(rendered_body, ensure_ascii=False).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    timeout = int((connector.get("constraints") or {}).get("request_timeout_sec") or 30)
    try:
        with open_secure_request(
            req,
            timeout=timeout,
            config=config,
            verify_keys=("tls_verify",),
            label="http_api base_url",
        ) as resp:
            raw = resp.read().decode("utf-8")
            status = resp.status
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {err_body[:500]}") from exc

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"HTTP response is not JSON: {raw[:200]}") from exc

    events = _extract_events(payload)
    max_rows = int((connector.get("constraints") or {}).get("max_records_per_request") or 500)
    if len(events) > max_rows:
        events = events[:max_rows]

    meta = {
        "url": url,
        "method": method,
        "http_status": status,
        "rows_returned": len(events),
    }
    return events, meta
