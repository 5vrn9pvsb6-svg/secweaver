"""Huawei Cloud LTS connector fetcher."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import urllib.parse
from typing import Any

from connector_fetch_common import (
    epoch_millis,
    external_executor_endpoint,
    fetch_local_samples,
    first_non_empty,
    http_request,
    json_bytes,
    max_rows,
    planned_meta,
    post_json,
    public_config,
    request_timeout,
    time_defaults,
)
from http_fetch import _extract_events


def _huawei_credentials(credentials: dict[str, Any]) -> dict[str, str] | None:
    token = first_non_empty(credentials.get("token"), credentials.get("access_token"), credentials.get("x_auth_token"))
    if token:
        return {"token": token}
    access_key = first_non_empty(credentials.get("access_key"), credentials.get("ak"), credentials.get("access_key_id"))
    secret_key = first_non_empty(credentials.get("secret_key"), credentials.get("sk"), credentials.get("secret_access_key"))
    if access_key and secret_key:
        return {"access_key": access_key, "secret_key": secret_key}
    return None


def _huawei_canonical_query(query: str) -> str:
    parts = urllib.parse.parse_qsl(query, keep_blank_values=True)
    encoded = [
        (
            urllib.parse.quote(str(key), safe="-_.~"),
            urllib.parse.quote(str(value), safe="-_.~"),
        )
        for key, value in parts
    ]
    return "&".join(f"{key}={value}" for key, value in sorted(encoded))


def _huawei_auth_headers(
    method: str,
    url: str,
    *,
    credentials: dict[str, str],
    body: bytes,
    now: dt.datetime | None = None,
) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if credentials.get("token"):
        headers["X-Auth-Token"] = credentials["token"]
        return headers

    parsed = urllib.parse.urlsplit(url)
    timestamp = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    header_map = {
        "content-type": "application/json",
        "host": parsed.netloc,
        "x-sdk-date": timestamp,
    }
    canonical_headers = "".join(f"{key}:{header_map[key]}\n" for key in sorted(header_map))
    signed_headers = ";".join(sorted(header_map))
    canonical_request = "\n".join(
        [
            method.upper(),
            urllib.parse.quote(parsed.path or "/", safe="/-_.~"),
            _huawei_canonical_query(parsed.query),
            canonical_headers,
            signed_headers,
            hashlib.sha256(body).hexdigest(),
        ]
    )
    string_to_sign = "\n".join(
        [
            "SDK-HMAC-SHA256",
            timestamp,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signature = hmac.new(credentials["secret_key"].encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "Authorization": (
            "SDK-HMAC-SHA256 "
            f"Access={credentials['access_key']}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        ),
        "Content-Type": "application/json",
        "Host": parsed.netloc,
        "X-Sdk-Date": timestamp,
    }


def _huawei_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = body.get("logs") or body.get("result") or body.get("events") or []
    rows: list[dict[str, Any]] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        content = item.get("content") or item.get("message")
        if isinstance(content, str) and content.strip():
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                parsed = {"message": content}
            if isinstance(parsed, dict):
                rows.append({**item, **parsed})
                continue
        rows.append(item)
    return rows or _extract_events(body)


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
        return events, {**meta, "backend": "huawei_lts", "query": query}

    endpoint = str(config.get("endpoint") or "").strip().rstrip("/")
    if not endpoint:
        return planned_meta(connector, query, params, "huawei LTS endpoint not configured; query rendered for live LTS fetch")
    hw_credentials = _huawei_credentials(credentials)
    if not hw_credentials:
        return planned_meta(connector, query, params, "huawei credentials not configured; query rendered for live LTS fetch")
    if not endpoint.startswith(("http://", "https://")):
        endpoint = f"https://{endpoint}"
    log_group_id = str(config.get("log_group_id") or "").strip()
    log_stream_id = str(config.get("log_stream_id") or "").strip()
    if not log_group_id or not log_stream_id:
        raise ValueError("huawei_lts connector config requires log_group_id and log_stream_id")
    project_id = str(config.get("project_id") or credentials.get("project_id") or "").strip()
    path = str(config.get("path") or "").strip()
    if not path:
        if not project_id:
            raise ValueError("huawei_lts connector config requires project_id when path is not configured")
        path = f"/v2/{project_id}/lts/groups/{log_group_id}/streams/{log_stream_id}/content/query"
    start, end = time_defaults(params)
    payload = {
        "keywords": query,
        "start_time": epoch_millis(params.get("time_start"), start),
        "end_time": epoch_millis(params.get("time_end"), end),
        "limit": max_rows(connector, params),
    }
    payload.update(config.get("request_overrides") or {})
    body = json_bytes(payload)
    url = f"{endpoint}{path if path.startswith('/') else '/' + path}"
    headers = _huawei_auth_headers("POST", url, credentials=hw_credentials, body=body)
    status, raw = http_request(url, method="POST", headers=headers, body=body, timeout=timeout)
    parsed = json.loads(raw.decode("utf-8", errors="replace")) if raw else {}
    events = _huawei_rows(parsed)
    return events, {
        "mode": "live",
        "backend": "huawei_lts",
        "http_status": status,
        "log_group_id": log_group_id,
        "log_stream_id": log_stream_id,
        "query": query,
        "rows_returned": len(events),
    }
