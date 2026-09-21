"""AWS S3 log archive connector fetcher."""

from __future__ import annotations

import urllib.parse
import xml.etree.ElementTree as ET
from typing import Any

import aws_common_fetch
from connector_fetch_common import (
    event_matches_params,
    external_executor_endpoint,
    fetch_local_samples,
    int_value,
    max_rows,
    parse_text_payload,
    planned_meta,
    post_json,
    public_config,
    request_timeout,
)


def _load_boto3() -> Any | None:
    try:
        import boto3
    except ImportError:
        return None
    return boto3


def _boto3_client(region: str, credentials: dict[str, str], timeout: int, boto3_module: Any) -> Any:
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
        return boto3_module.client("s3", **session_kwargs)
    return boto3_module.client(
        "s3",
        config=Config(connect_timeout=timeout, read_timeout=timeout, retries={"max_attempts": 2}),
        **session_kwargs,
    )


def _s3_list_keys(xml_body: bytes) -> list[str]:
    root = ET.fromstring(xml_body)
    keys: list[str] = []
    for element in root.iter():
        if element.tag.endswith("Key") and element.text:
            keys.append(element.text)
    return keys


def _s3_url(bucket: str, key: str = "", *, region: str, query: dict[str, Any] | None = None) -> str:
    encoded_key = urllib.parse.quote(key, safe="/-_.~")
    base = f"https://{bucket}.s3.{region}.amazonaws.com/{encoded_key}" if encoded_key else f"https://{bucket}.s3.{region}.amazonaws.com/"
    if not query:
        return base
    encoded_query = urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
    return f"{base}?{encoded_query}"


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
    bucket = str(config.get("bucket") or "").strip()
    if not bucket:
        raise ValueError("aws_s3_logs connector config requires bucket")
    prefix = str(config.get("prefix") or "").strip()
    max_objects = int_value(config.get("max_objects"), 20)
    row_limit = max_rows(connector, params)
    client = _boto3_client(region, credentials, timeout, boto3_module)
    listed = client.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=max_objects)
    keys = [str(item.get("Key")) for item in listed.get("Contents") or [] if item.get("Key")]
    events: list[dict[str, Any]] = []
    fetched_keys: list[str] = []
    for key in keys[:max_objects]:
        obj = client.get_object(Bucket=bucket, Key=key)
        body = obj.get("Body")
        raw = body.read() if hasattr(body, "read") else body
        if isinstance(raw, str):
            text = raw
        else:
            text = bytes(raw or b"").decode("utf-8", errors="replace")
        fetched_keys.append(key)
        for event in parse_text_payload(text, connector, source=key):
            if event_matches_params(event, params):
                row = dict(event)
                row.setdefault("_s3_bucket", bucket)
                row.setdefault("_s3_key", key)
                events.append(row)
                if len(events) >= row_limit:
                    return events, {
                        "mode": "live",
                        "backend": "aws_s3_logs",
                        "sdk": "boto3",
                        "bucket": bucket,
                        "prefix": prefix,
                        "query": query,
                        "objects_scanned": len(fetched_keys),
                        "rows_returned": len(events),
                    }
    return events, {
        "mode": "live",
        "backend": "aws_s3_logs",
        "sdk": "boto3",
        "bucket": bucket,
        "prefix": prefix,
        "query": query,
        "objects_scanned": len(fetched_keys),
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

    timeout = request_timeout(connector, default=120)
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
        return events, {**meta, "backend": "aws_s3_logs", "query": query}

    aws = aws_common_fetch.aws_credentials(credentials)
    if not aws:
        return planned_meta(connector, query, params, "aws credentials not configured; query rendered for live S3 log fetch")

    bucket = str(config.get("bucket") or "").strip()
    if not bucket:
        raise ValueError("aws_s3_logs connector config requires bucket")
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

    prefix = str(config.get("prefix") or "").strip()
    max_objects = int_value(config.get("max_objects"), 20)
    list_url = _s3_url(bucket, region=region, query={"list-type": "2", "prefix": prefix, "max-keys": max_objects})
    _status, xml_body = aws_common_fetch.aws_raw_request(list_url, region=region, service="s3", credentials=aws, timeout=timeout)
    keys = _s3_list_keys(xml_body)
    row_limit = max_rows(connector, params)
    events: list[dict[str, Any]] = []
    fetched_keys: list[str] = []
    for key in keys[:max_objects]:
        obj_url = _s3_url(bucket, key, region=region)
        _obj_status, raw = aws_common_fetch.aws_raw_request(obj_url, region=region, service="s3", credentials=aws, timeout=timeout)
        fetched_keys.append(key)
        text = raw.decode("utf-8", errors="replace")
        for event in parse_text_payload(text, connector, source=key):
            if event_matches_params(event, params):
                row = dict(event)
                row.setdefault("_s3_bucket", bucket)
                row.setdefault("_s3_key", key)
                events.append(row)
                if len(events) >= row_limit:
                    return events, {
                        "mode": "live",
                        "backend": "aws_s3_logs",
                        "sdk": "rest_sigv4",
                        "bucket": bucket,
                        "prefix": prefix,
                        "query": query,
                        "objects_scanned": len(fetched_keys),
                        "rows_returned": len(events),
                    }

    return events, {
        "mode": "live",
        "backend": "aws_s3_logs",
        "sdk": "rest_sigv4",
        "bucket": bucket,
        "prefix": prefix,
        "query": query,
        "objects_scanned": len(fetched_keys),
        "rows_returned": len(events),
    }
