"""Google Cloud Logging connector fetcher."""

from __future__ import annotations

import json
from typing import Any

from connector_fetch_common import (
    external_executor_endpoint,
    fetch_local_samples,
    first_non_empty,
    http_json_request,
    max_rows,
    planned_meta,
    post_json,
    public_config,
    request_timeout,
)


def gcp_access_token(config: dict[str, Any], credentials: dict[str, Any]) -> str:
    token = first_non_empty(credentials.get("access_token"), credentials.get("token"))
    if token:
        return token
    info = credentials.get("service_account_json") or credentials.get("service_account")
    if isinstance(info, str) and info.strip():
        try:
            service_account_info = json.loads(info)
        except json.JSONDecodeError as exc:
            raise RuntimeError("gcp service_account_json is not valid JSON") from exc
    elif isinstance(info, dict):
        service_account_info = dict(info)
    else:
        service_account_info = {
            key: credentials.get(key)
            for key in ("type", "project_id", "private_key_id", "private_key", "client_email", "client_id", "token_uri")
            if credentials.get(key)
        }
    if not service_account_info or not service_account_info.get("private_key"):
        return ""
    service_account_info.setdefault("type", "service_account")
    service_account_info.setdefault("project_id", config.get("project_id"))
    service_account_info.setdefault("token_uri", "https://oauth2.googleapis.com/token")
    try:
        from google.auth.transport.requests import Request
        from google.oauth2 import service_account
    except ImportError as exc:
        raise RuntimeError("live GCP Logging fetch with service account credentials requires optional dependency: pip install google-auth requests") from exc
    scopes = [str(config.get("scope") or "https://www.googleapis.com/auth/logging.read")]
    google_credentials = service_account.Credentials.from_service_account_info(service_account_info, scopes=scopes)
    google_credentials.refresh(Request())
    return str(google_credentials.token or "")


def _gcp_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for entry in body.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        row: dict[str, Any] = {
            "timestamp": entry.get("timestamp") or entry.get("receiveTimestamp"),
            "severity": entry.get("severity"),
            "logName": entry.get("logName"),
            "insertId": entry.get("insertId"),
        }
        payload = entry.get("jsonPayload") or entry.get("protoPayload")
        if isinstance(payload, dict):
            row.update(payload)
        elif entry.get("textPayload") is not None:
            row["message"] = entry.get("textPayload")
        if isinstance(entry.get("labels"), dict):
            row["labels"] = entry["labels"]
        if isinstance(entry.get("resource"), dict):
            row["resource"] = entry["resource"]
        rows.append({key: value for key, value in row.items() if value is not None})
    return rows


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
        return events, {**meta, "backend": "gcp_logging", "query": query}

    project_id = str(config.get("project_id") or credentials.get("project_id") or "").strip()
    if not project_id:
        raise ValueError("gcp_logging connector config requires project_id")
    token = gcp_access_token(config, credentials)
    if not token:
        return planned_meta(connector, query, params, "gcp credentials not configured; query rendered for live Cloud Logging fetch")
    resource_names = config.get("resource_names") or [f"projects/{project_id}"]
    payload = {
        "resourceNames": [str(item) for item in resource_names],
        "filter": query,
        "pageSize": max_rows(connector, params),
        "orderBy": str(config.get("order_by") or "timestamp desc"),
    }
    body, status = http_json_request(
        "https://logging.googleapis.com/v2/entries:list",
        payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    events = _gcp_rows(body)
    return events, {
        "mode": "live",
        "backend": "gcp_logging",
        "project_id": project_id,
        "http_status": status,
        "query": query,
        "rows_returned": len(events),
    }
