"""WAF / gateway log payload helpers — base64 body decode for alert triage."""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

_DATA_URI = re.compile(r"^data:[^;]+;base64,(.+)$", re.I | re.S)
_B64_CHARS = re.compile(r"^[A-Za-z0-9+/_=\-\s]+$")


def _pad(s: str) -> str:
    t = re.sub(r"\s+", "", s)
    rem = len(t) % 4
    if rem:
        t += "=" * (4 - rem)
    return t


def _decode_bytes(raw: bytes) -> str | None:
    if len(raw) < 1:
        return None
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) / len(raw)
    if printable < 0.55:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("latin-1")
        except UnicodeDecodeError:
            return None


def try_decode_base64_text(text: str) -> tuple[str | None, str]:
    """Return (decoded_text, hint). hint: plain | base64 | base64_urlsafe | data_uri."""
    if not text or str(text).strip() in ("", "null", "None"):
        return None, "plain"

    raw_in = str(text).strip()
    if raw_in.startswith(("{", "[", "<", "POST ", "GET ")):
        return None, "plain"

    candidate = raw_in
    m = _DATA_URI.match(raw_in)
    if m:
        candidate = m.group(1).strip()
        prefix = "data_uri"
    else:
        prefix = ""

    if len(candidate) < 8 or not _B64_CHARS.match(candidate[: min(len(candidate), 200)]):
        return None, "plain"

    padded = _pad(candidate)
    for label, fn in (
        ("base64", lambda s: base64.b64decode(s, validate=False)),
        ("base64_urlsafe", lambda s: base64.urlsafe_b64decode(s)),
    ):
        try:
            decoded = _decode_bytes(fn(padded))
            if decoded is None:
                continue
            # reject trivial decode (same as input)
            if decoded.strip() == raw_in.strip():
                continue
            hint = f"{prefix}_{label}".strip("_") if prefix else label
            return decoded, hint
        except (binascii.Error, ValueError):
            continue
    return None, "plain"


def _extract_from_request_json(event: dict[str, Any]) -> tuple[str | None, str | None]:
    """Some WAF sources keep the full request in a JSON string field named `request`."""
    raw = event.get("request")
    if not raw or str(raw).strip() in ("", "null", "None"):
        return None, None
    text = str(raw).strip()
    if not text.startswith("{"):
        return None, None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None, None
    if not isinstance(obj, dict):
        return None, None
    body = obj.get("body") or obj.get("Body")
    if body is not None and str(body).strip() not in ("", "null", "None"):
        return str(body), "request.json.body"
    return None, None


def _request_json_object(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("request")
    if isinstance(raw, dict):
        return raw
    if not raw or str(raw).strip() in ("", "null", "None"):
        return {}
    text = str(raw).strip()
    if not text.startswith("{"):
        return {}
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return obj if isinstance(obj, dict) else {}


def extract_waf_request_method(event: dict[str, Any]) -> str | None:
    """Extract HTTP method from normalized WAF fields or nested request JSON."""
    for key in ("method", "request_method", "http_method", "request.method"):
        value = event.get(key)
        if value not in (None, "", "-"):
            return str(value).upper()
    req = _request_json_object(event)
    for key in ("method", "request_method", "http_method"):
        value = req.get(key)
        if value not in (None, "", "-"):
            return str(value).upper()
    return None


def resolve_waf_payload(event: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Pick body for triage; decode base64 when applicable.

    Returns (payload_for_analysis, metadata).
    """
    meta: dict[str, Any] = {}
    msg = event.get("message")
    if msg and str(msg).strip() not in ("", "null", "None"):
        meta["gateway_message"] = str(msg)

    candidates: list[tuple[str, str]] = []
    for key in ("payload", "request.body", "request_body", "body"):
        val = event.get(key)
        if val is not None and str(val).strip() not in ("", "null", "None"):
            candidates.append((key, str(val)))

    req_body, req_src = _extract_from_request_json(event)
    if req_body:
        candidates.insert(0, (req_src or "request.json.body", req_body))

    if not candidates:
        url = str(event.get("url") or "")
        return url, meta

    source_key, raw = candidates[0]
    meta["payload_source"] = source_key
    meta["payload_raw"] = raw[:500] if len(raw) > 500 else raw

    decoded, hint = try_decode_base64_text(raw)
    if decoded is not None:
        meta["payload_encoding"] = hint
        meta["payload_decoded"] = True
        return decoded, meta

    meta["payload_encoding"] = "plain"
    meta["payload_decoded"] = False
    return raw, meta
