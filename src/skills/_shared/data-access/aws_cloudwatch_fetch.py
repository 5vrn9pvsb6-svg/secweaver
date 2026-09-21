"""AWS CloudWatch Logs connector fetcher."""

from __future__ import annotations

import json
import time
from typing import Any

import aws_common_fetch
from connector_fetch_common import (
    external_executor_endpoint,
    fetch_local_samples,
    max_rows,
    planned_meta,
    post_json,
    public_config,
    request_timeout,
    time_defaults,
)


def _load_boto3() -> Any | None:
    try:
        import boto3
    except ImportError:
        return None
    return boto3


def _boto3_client(service: str, region: str, credentials: dict[str, str], timeout: int, boto3_module: Any) -> Any:
    session_kwargs: dict[str, Any] = {
        "region_name": region,
        "aws_access_key_id": credentials["access_key_id"],
        "aws_secret_access_key": credentials["secret_access_key"],
    }
    if credentials.get("session_token"):
        session_kwargs["aws_session_token"] = credentials["session_token"]
    try:
        from botocore.config import Config
    except ImportError:
        return boto3_module.client(service, **session_kwargs)
    return boto3_module.client(
        service,
        config=Config(connect_timeout=timeout, read_timeout=timeout, retries={"max_attempts": 2}),
        **session_kwargs,
    )


def _cloudwatch_rows(results: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, list):
            continue
        row: dict[str, Any] = {}
        for item in result:
            if isinstance(item, dict) and item.get("field"):
                row[str(item["field"])] = item.get("value")
        if "@message" in row:
            try:
                parsed = json.loads(str(row["@message"]))
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                row = {**parsed, **row}
        rows.append(row)
    return rows


def _fetch_with_boto3(
    connector: dict[str, Any],
    config: dict[str, Any],
    credentials: dict[str, str],
    query: str,
    params: dict[str, Any],
    *,
    timeout: int,
    region: str,
    boto3_module: Any,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    log_groups = config.get("log_groups") or config.get("log_group_names")
    log_group = str(config.get("log_group") or "").strip()
    start, end = time_defaults(params)
    payload: dict[str, Any] = {
        "queryString": query,
        "startTime": int(start.timestamp()),
        "endTime": int(end.timestamp()),
        "limit": max_rows(connector, params),
    }
    if isinstance(log_groups, list) and log_groups:
        payload["logGroupNames"] = [str(item) for item in log_groups if str(item).strip()]
    elif log_group:
        payload["logGroupName"] = log_group
    else:
        raise ValueError("aws_cloudwatch connector config requires log_group or log_groups")

    client = _boto3_client("logs", region, credentials, timeout, boto3_module)
    start_body = client.start_query(**payload)
    query_id = str(start_body.get("queryId") or "")
    if not query_id:
        raise RuntimeError(f"CloudWatch StartQuery response missing queryId: {start_body}")

    deadline = time.monotonic() + timeout
    last_body: dict[str, Any] = {}
    while True:
        last_body = client.get_query_results(queryId=query_id)
        status = str(last_body.get("status") or "")
        if status == "Complete":
            break
        if status in {"Failed", "Cancelled", "Timeout"}:
            raise RuntimeError(f"CloudWatch Logs query {query_id} ended with status={status}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"CloudWatch Logs query {query_id} did not complete within {timeout}s")
        time.sleep(1)

    events = _cloudwatch_rows(last_body.get("results") or [])
    return events, {
        "mode": "live",
        "backend": "aws_cloudwatch",
        "sdk": "boto3",
        "region": region,
        "log_group": log_group or log_groups,
        "query_id": query_id,
        "query": query,
        "rows_returned": len(events),
    }


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
    endpoint = external_executor_endpoint(config)
    if endpoint:
        payload = {"query": query, "params": params, "config": public_config(config)}
        events, meta = post_json(
            endpoint,
            payload,
            credentials,
            timeout=timeout,
            transport_config=config,
        )
        return events, {**meta, "backend": "aws_cloudwatch", "query": query}

    aws = aws_common_fetch.aws_credentials(credentials)
    if not aws:
        return planned_meta(connector, query, params, "aws credentials not configured; query rendered for live CloudWatch Logs fetch")

    region = str(config.get("region") or credentials.get("region") or "us-east-1")
    if config.get("prefer_sdk") is not False and str(config.get("sdk") or "").lower() != "rest":
        boto3_module = _load_boto3()
        if boto3_module is not None:
            return _fetch_with_boto3(
                connector,
                config,
                aws,
                query,
                params,
                timeout=timeout,
                region=region,
                boto3_module=boto3_module,
            )

    log_groups = config.get("log_groups") or config.get("log_group_names")
    log_group = str(config.get("log_group") or "").strip()
    start, end = time_defaults(params)
    payload: dict[str, Any] = {
        "queryString": query,
        "startTime": int(start.timestamp()),
        "endTime": int(end.timestamp()),
        "limit": max_rows(connector, params),
    }
    if isinstance(log_groups, list) and log_groups:
        payload["logGroupNames"] = [str(item) for item in log_groups if str(item).strip()]
    elif log_group:
        payload["logGroupName"] = log_group
    else:
        raise ValueError("aws_cloudwatch connector config requires log_group or log_groups")

    url = f"https://logs.{region}.amazonaws.com/"
    start_body = aws_common_fetch.aws_json_request(
        url,
        target="Logs_20140328.StartQuery",
        region=region,
        service="logs",
        credentials=aws,
        payload=payload,
        timeout=timeout,
    )
    query_id = str(start_body.get("queryId") or "")
    if not query_id:
        raise RuntimeError(f"CloudWatch StartQuery response missing queryId: {start_body}")

    deadline = time.monotonic() + timeout
    last_body: dict[str, Any] = {}
    while True:
        last_body = aws_common_fetch.aws_json_request(
            url,
            target="Logs_20140328.GetQueryResults",
            region=region,
            service="logs",
            credentials=aws,
            payload={"queryId": query_id},
            timeout=timeout,
        )
        status = str(last_body.get("status") or "")
        if status == "Complete":
            break
        if status in {"Failed", "Cancelled", "Timeout"}:
            raise RuntimeError(f"CloudWatch Logs query {query_id} ended with status={status}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"CloudWatch Logs query {query_id} did not complete within {timeout}s")
        time.sleep(1)

    events = _cloudwatch_rows(last_body.get("results") or [])
    return events, {
        "mode": "live",
        "backend": "aws_cloudwatch",
        "sdk": "rest_sigv4",
        "region": region,
        "log_group": log_group or log_groups,
        "query_id": query_id,
        "query": query,
        "rows_returned": len(events),
    }
