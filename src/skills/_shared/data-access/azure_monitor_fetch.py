"""Azure Monitor / Log Analytics connector fetcher."""

from __future__ import annotations

import json
import urllib.parse
from typing import Any

from connector_fetch_common import (
    external_executor_endpoint,
    fetch_local_samples,
    first_non_empty,
    http_json_request,
    http_request,
    max_rows,
    planned_meta,
    post_json,
    public_config,
    request_timeout,
    time_defaults,
)
from http_fetch import _extract_events


def azure_access_token(config: dict[str, Any], credentials: dict[str, Any], timeout: int) -> str:
    token = first_non_empty(credentials.get("access_token"), credentials.get("token"))
    if token:
        return token
    tenant_id = first_non_empty(credentials.get("tenant_id"), config.get("tenant_id"))
    client_id = first_non_empty(credentials.get("client_id"), credentials.get("app_id"))
    client_secret = first_non_empty(credentials.get("client_secret"), credentials.get("secret"))
    if not (tenant_id and client_id and client_secret):
        return ""
    form = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": str(config.get("scope") or "https://api.loganalytics.io/.default"),
        }
    ).encode("utf-8")
    url = f"https://login.microsoftonline.com/{urllib.parse.quote(tenant_id, safe='')}/oauth2/v2.0/token"
    status, raw = http_request(
        url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        body=form,
        timeout=timeout,
    )
    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Azure token response is not JSON: {raw[:200]!r}") from exc
    token = str(payload.get("access_token") or "")
    if not token:
        raise RuntimeError(f"Azure token endpoint returned HTTP {status} without access_token")
    return token


def _azure_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for table in body.get("tables") or []:
        if not isinstance(table, dict):
            continue
        columns = [str(col.get("name") if isinstance(col, dict) else col) for col in table.get("columns") or []]
        for values in table.get("rows") or []:
            if isinstance(values, list):
                rows.append(dict(zip(columns, values, strict=False)))
            elif isinstance(values, dict):
                rows.append(values)
    if rows:
        return rows
    return _extract_events(body)


def fetch(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    query: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    config = connector.get("config") or {}
    local_result = fetch_local_samples(connector, query, params)
    if local_result is not None:
        return local_result

    timeout = request_timeout(connector)
    executor_endpoint = external_executor_endpoint(config)
    if executor_endpoint:
        payload = {"query": query, "params": params, "config": public_config(config)}
        events, meta = post_json(
            executor_endpoint,
            payload,
            credentials,
            timeout=timeout,
            transport_config=config,
        )
        return events, {**meta, "backend": "azure_monitor", "query": query}

    workspace_id = str(config.get("workspace_id") or credentials.get("workspace_id") or "").strip()
    if not workspace_id:
        raise ValueError("azure_monitor connector config requires workspace_id")
    token = azure_access_token(config, credentials, timeout)
    if not token:
        return planned_meta(connector, query, params, "azure credentials not configured; query rendered for live Log Analytics fetch")

    endpoint = str(config.get("endpoint") or "").strip()
    if not endpoint:
        endpoint = f"https://api.loganalytics.io/v1/workspaces/{urllib.parse.quote(workspace_id, safe='')}/query"
    start, end = time_defaults(params)
    payload: dict[str, Any] = {"query": query}
    if params.get("time_start") or params.get("time_end"):
        payload["timespan"] = f"{start.isoformat().replace('+00:00', 'Z')}/{end.isoformat().replace('+00:00', 'Z')}"
    body, status = http_json_request(
        endpoint,
        payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    events = _azure_rows(body)[: max_rows(connector, params)]
    return events, {
        "mode": "live",
        "backend": "azure_monitor",
        "workspace_id": workspace_id,
        "http_status": status,
        "query": query,
        "rows_returned": len(events),
    }
