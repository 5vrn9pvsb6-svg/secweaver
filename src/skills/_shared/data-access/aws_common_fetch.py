"""AWS SigV4 helpers shared by AWS connector fetchers."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import urllib.parse
from typing import Any

from connector_fetch_common import first_non_empty, http_json_request, http_request, json_bytes


def aws_credentials(credentials: dict[str, Any]) -> dict[str, str] | None:
    access_key_id = first_non_empty(credentials.get("access_key_id"), credentials.get("aws_access_key_id"))
    secret_access_key = first_non_empty(
        credentials.get("secret_access_key"),
        credentials.get("aws_secret_access_key"),
        credentials.get("access_key_secret"),
    )
    if not access_key_id or not secret_access_key:
        return None
    resolved = {
        "access_key_id": access_key_id,
        "secret_access_key": secret_access_key,
    }
    session_token = first_non_empty(credentials.get("session_token"), credentials.get("aws_session_token"))
    if session_token:
        resolved["session_token"] = session_token
    return resolved


def _aws_hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _aws_signing_key(secret_access_key: str, date_stamp: str, region: str, service: str) -> bytes:
    date_key = _aws_hmac(("AWS4" + secret_access_key).encode("utf-8"), date_stamp)
    region_key = _aws_hmac(date_key, region)
    service_key = _aws_hmac(region_key, service)
    return _aws_hmac(service_key, "aws4_request")


def _aws_canonical_query(query: str) -> str:
    parts = urllib.parse.parse_qsl(query, keep_blank_values=True)
    encoded = [
        (
            urllib.parse.quote(str(key), safe="-_.~"),
            urllib.parse.quote(str(value), safe="-_.~"),
        )
        for key, value in parts
    ]
    return "&".join(f"{key}={value}" for key, value in sorted(encoded))


def aws_sigv4_headers(
    method: str,
    url: str,
    *,
    region: str,
    service: str,
    credentials: dict[str, str],
    body: bytes,
    headers: dict[str, str] | None = None,
    now: dt.datetime | None = None,
) -> dict[str, str]:
    parsed = urllib.parse.urlsplit(url)
    timestamp = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    amz_date = timestamp.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = timestamp.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()

    signed_header_map = {str(key).lower(): " ".join(str(value).strip().split()) for key, value in (headers or {}).items()}
    signed_header_map["host"] = parsed.netloc
    signed_header_map["x-amz-content-sha256"] = payload_hash
    signed_header_map["x-amz-date"] = amz_date
    if credentials.get("session_token"):
        signed_header_map["x-amz-security-token"] = credentials["session_token"]

    canonical_uri = urllib.parse.quote(parsed.path or "/", safe="/-_.~")
    canonical_headers = "".join(f"{key}:{signed_header_map[key]}\n" for key in sorted(signed_header_map))
    signed_headers = ";".join(sorted(signed_header_map))
    canonical_request = "\n".join(
        [
            method.upper(),
            canonical_uri,
            _aws_canonical_query(parsed.query),
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signature = hmac.new(
        _aws_signing_key(credentials["secret_access_key"], date_stamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    signed_header_map["authorization"] = (
        "AWS4-HMAC-SHA256 "
        f"Credential={credentials['access_key_id']}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )
    return signed_header_map


def aws_json_request(
    url: str,
    *,
    target: str,
    region: str,
    service: str,
    credentials: dict[str, str],
    payload: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    body = json_bytes(payload)
    headers = {
        "content-type": "application/x-amz-json-1.1",
        "x-amz-target": target,
    }
    headers = aws_sigv4_headers("POST", url, region=region, service=service, credentials=credentials, body=body, headers=headers)
    parsed, _status = http_json_request(url, payload, method="POST", headers=headers, timeout=timeout)
    return parsed


def aws_raw_request(
    url: str,
    *,
    method: str = "GET",
    region: str,
    service: str,
    credentials: dict[str, str],
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    timeout: int,
) -> tuple[int, bytes]:
    signed = aws_sigv4_headers(method, url, region=region, service=service, credentials=credentials, body=body, headers=headers)
    return http_request(url, method=method, headers=signed, body=body if body else None, timeout=timeout)
