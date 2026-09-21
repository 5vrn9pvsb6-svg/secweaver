"""Tencent Cloud CLS connector fetcher."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import time
from typing import Any

from connector_fetch_common import (
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


def _tencent_credentials(credentials: dict[str, Any]) -> dict[str, str] | None:
    secret_id = first_non_empty(credentials.get("secret_id"), credentials.get("access_key_id"), credentials.get("api_key"))
    secret_key = first_non_empty(credentials.get("secret_key"), credentials.get("secret_access_key"), credentials.get("api_secret"))
    if not secret_id or not secret_key:
        return None
    resolved = {"secret_id": secret_id, "secret_key": secret_key}
    token = first_non_empty(credentials.get("token"), credentials.get("session_token"))
    if token:
        resolved["token"] = token
    return resolved


def _tencent_sign_headers(
    *,
    endpoint: str,
    service: str,
    action: str,
    version: str,
    region: str,
    payload: bytes,
    credentials: dict[str, str],
    timestamp: int | None = None,
) -> dict[str, str]:
    ts = timestamp or int(time.time())
    date_stamp = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime("%Y-%m-%d")
    hashed_payload = hashlib.sha256(payload).hexdigest()
    canonical_headers = f"content-type:application/json; charset=utf-8\nhost:{endpoint}\n"
    signed_headers = "content-type;host"
    canonical_request = "\n".join(["POST", "/", "", canonical_headers, signed_headers, hashed_payload])
    credential_scope = f"{date_stamp}/{service}/tc3_request"
    string_to_sign = "\n".join(
        [
            "TC3-HMAC-SHA256",
            str(ts),
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    secret_date = hmac.new(("TC3" + credentials["secret_key"]).encode("utf-8"), date_stamp.encode("utf-8"), hashlib.sha256).digest()
    secret_service = hmac.new(secret_date, service.encode("utf-8"), hashlib.sha256).digest()
    secret_signing = hmac.new(secret_service, b"tc3_request", hashlib.sha256).digest()
    signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    headers = {
        "Authorization": (
            "TC3-HMAC-SHA256 "
            f"Credential={credentials['secret_id']}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        ),
        "Content-Type": "application/json; charset=utf-8",
        "Host": endpoint,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(ts),
        "X-TC-Version": version,
    }
    if region:
        headers["X-TC-Region"] = region
    if credentials.get("token"):
        headers["X-TC-Token"] = credentials["token"]
    return headers


def _tencent_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    response = body.get("Response") if isinstance(body.get("Response"), dict) else body
    error = response.get("Error") if isinstance(response, dict) else None
    if isinstance(error, dict):
        raise RuntimeError(f"Tencent CLS API error {error.get('Code')}: {error.get('Message')}")
    candidates = response.get("Results") or response.get("Logs") or response.get("AnalysisRecords") or []
    rows: list[dict[str, Any]] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        log_json = item.get("LogJson") or item.get("log_json")
        if isinstance(log_json, str) and log_json.strip():
            try:
                parsed = json.loads(log_json)
            except json.JSONDecodeError:
                parsed = {"message": log_json}
            if isinstance(parsed, dict):
                rows.append({**item, **parsed})
                continue
        rows.append(item)
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
        return events, {**meta, "backend": "tencent_cls", "query": query}

    tc_credentials = _tencent_credentials(credentials)
    if not tc_credentials:
        return planned_meta(connector, query, params, "tencent credentials not configured; query rendered for live CLS fetch")
    endpoint = str(config.get("endpoint") or "cls.tencentcloudapi.com").strip().removeprefix("https://").removeprefix("http://").strip("/")
    topic_id = str(config.get("topic_id") or "").strip()
    if not topic_id:
        raise ValueError("tencent_cls connector config requires topic_id")
    start, end = time_defaults(params)
    payload = {
        "TopicId": topic_id,
        "Query": query,
        "From": int(start.timestamp()),
        "To": int(end.timestamp()),
        "Limit": max_rows(connector, params),
    }
    body = json_bytes(payload)
    action = str(config.get("action") or "SearchLog")
    version = str(config.get("version") or "2020-10-16")
    region = str(config.get("region") or credentials.get("region") or "")
    headers = _tencent_sign_headers(
        endpoint=endpoint,
        service=str(config.get("service") or "cls"),
        action=action,
        version=version,
        region=region,
        payload=body,
        credentials=tc_credentials,
    )
    status, raw = http_request(f"https://{endpoint}/", method="POST", headers=headers, body=body, timeout=timeout)
    parsed = json.loads(raw.decode("utf-8", errors="replace")) if raw else {}
    events = _tencent_rows(parsed)
    return events, {
        "mode": "live",
        "backend": "tencent_cls",
        "topic_id": topic_id,
        "http_status": status,
        "query": query,
        "rows_returned": len(events),
        "request_id": ((parsed.get("Response") or {}).get("RequestId") if isinstance(parsed, dict) else None),
    }
