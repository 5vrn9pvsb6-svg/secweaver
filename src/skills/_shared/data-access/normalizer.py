"""Normalize fetch events: evidence_id, timestamp ISO, field aliases, masking."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from dataasset_paths import DATAASSET_ROOT

EVIDENCE_SPEC_PATH = DATAASSET_ROOT / "configure" / "evidence-minimum-fields.json"

_SPEC_CACHE: dict[str, Any] | None = None

# syslog-style: Jun 21 08:15:01
SYSLOG_TS = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})$"
)
# nginx/gateway upstream_addr often appears as ip:port
UPSTREAM_HOST_IP = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):\d+$")


def _strip_upstream_host_ip(value: str) -> str:
    m = UPSTREAM_HOST_IP.match(value.strip())
    return m.group("ip") if m else value.strip()


def normalize_ip(value: Any) -> str | None:
    """Return a canonical IP while tolerating gateway quoting and IPv4 ports.

    Some gateway exports preserve a leading CSV quote (for example,
    ``"39.144.124.34``) and some access fields include ``:port``.  All
    cross-source joins must use this function so a formatting artifact cannot
    split one attacker into multiple identities. Invalid or placeholder values
    are rejected instead of being used as correlation keys.
    """
    if value in (None, "", "-"):
        return None
    text = str(value).strip().strip('"\'').strip()
    if not text or text.lower() in {"-", "null", "none", "unknown"}:
        return None
    if ":" in text and "." in text:
        host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            text = host.strip().strip('"\'').strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def normalize_event_source_ips(event: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize source-IP aliases after asset field mapping.

    Only known source address fields are changed; invalid values remain intact
    for forensic visibility but cannot participate in IP-based correlation.
    This preserves raw evidence while making canonical fields safe for joins.
    """
    for field in ("src_ip", "source_ip", "remote_addr", "client_ip", "ip", "rhost"):
        if field not in event or event[field] in (None, ""):
            continue
        normalized = normalize_ip(event[field])
        if normalized:
            event[field] = normalized
    return event


def load_evidence_spec() -> dict[str, Any]:
    global _SPEC_CACHE
    if _SPEC_CACHE is None:
        with EVIDENCE_SPEC_PATH.open(encoding="utf-8") as f:
            _SPEC_CACHE = json.load(f)
    return _SPEC_CACHE


def field_aliases(asset: dict[str, Any] | None = None) -> dict[str, str]:
    merged = dict(load_evidence_spec().get("field_aliases") or {})
    if asset:
        per = asset.get("field_aliases") or {}
        if isinstance(per, dict):
            merged.update({str(k): str(v) for k, v in per.items()})
    return merged


def apply_aliases(event: dict[str, Any], asset: dict[str, Any] | None = None) -> dict[str, Any]:
    aliases = field_aliases(asset)
    out = dict(event)
    for src, dst in aliases.items():
        if src in out and dst not in out:
            out[dst] = out[src]
    if "ts" in out and "timestamp" not in out:
        out["timestamp"] = out["ts"]
    return out


def get_time_correction(asset: dict[str, Any] | None = None) -> dict[str, Any]:
    """Per-asset clock skew / timezone fix from schema.time_correction."""
    if not asset:
        return {}
    schema = asset.get("schema") or {}
    tc = schema.get("time_correction")
    return dict(tc) if isinstance(tc, dict) else {}


def parse_timezone(name: str) -> timezone | ZoneInfo:
    text = str(name).strip()
    if not text:
        raise ValueError("empty timezone")
    if text.upper() in ("UTC", "Z"):
        return timezone.utc
    m = re.match(r"^([+-])(\d{2}):?(\d{2})$", text)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))
    return ZoneInfo(text)


def apply_time_correction(iso_ts: str | None, correction: dict[str, Any] | None) -> str | None:
    if not iso_ts or not correction:
        return iso_ts
    offset = int(correction.get("offset_minutes") or 0)
    if offset == 0:
        return iso_ts
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    except ValueError:
        return iso_ts
    return (dt + timedelta(minutes=offset)).isoformat()


def normalize_timestamp(value: Any, *, assume_timezone: str | None = None) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).astimezone().isoformat()
        except (OSError, OverflowError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        try:
            ts = int(text)
            if ts > 1_000_000_000_000:
                ts /= 1000.0
            return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat()
        except (OSError, OverflowError, ValueError):
            pass
    m = SYSLOG_TS.match(text)
    if m:
        year = datetime.now().year
        try:
            dt = datetime.strptime(
                f"{year} {m.group('month')} {m.group('day')} {m.group('time')}",
                "%Y %b %d %H:%M:%S",
            )
            if assume_timezone:
                return dt.replace(tzinfo=parse_timezone(assume_timezone)).isoformat()
            return dt.astimezone().isoformat()
        except ValueError:
            return text
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%d/%b/%Y:%H:%M:%S %z",
    ):
        try:
            if fmt.endswith("%z") and len(text) >= 6 and text[-6] in "+-" and ":" not in text[-6:]:
                # 2026-06-21T08:15:01+0800 → +08:00
                fixed = text[:-2] + ":" + text[-2:]
                return datetime.strptime(fixed, fmt).isoformat()
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None and assume_timezone:
                return dt.replace(tzinfo=parse_timezone(assume_timezone)).isoformat()
            return dt.astimezone().isoformat()
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None and assume_timezone:
            return dt.replace(tzinfo=parse_timezone(assume_timezone)).isoformat()
        return dt.astimezone().isoformat()
    except ValueError:
        return text


def _get_mask_target(event: dict[str, Any], field: str) -> tuple[bool, Any]:
    if field in event:
        return True, event[field]
    current: Any = event
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _set_mask_target(event: dict[str, Any], field: str, value: Any) -> None:
    if field in event:
        event[field] = value
        return
    current: Any = event
    parts = field.split(".")
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            return
        current = current[part]
    if isinstance(current, dict) and parts[-1] in current:
        current[parts[-1]] = value


def _truncate_text(value: Any, limit: int) -> str:
    text = str(value)
    return text[:limit] + "…" if len(text) > limit else text


def _partial_mask(value: Any, keep_start: int = 0, keep_end: int = 0, mask: str = "*") -> str:
    text = str(value)
    keep_start = max(0, int(keep_start or 0))
    keep_end = max(0, int(keep_end or 0))
    if keep_start + keep_end >= len(text):
        return text
    masked_len = len(text) - keep_start - keep_end
    return f"{text[:keep_start]}{mask * masked_len}{text[len(text) - keep_end:]}"


def _mask_phone(value: Any) -> str:
    text = str(value)
    return re.sub(r"(?<!\d)(1[3-9]\d)\d{4}(\d{4})(?!\d)", r"\1****\2", text)


def _mask_id_card(value: Any) -> str:
    text = str(value)
    return re.sub(r"(?<![0-9Xx])(\d{6})\d{8}(\d{3}[0-9Xx])(?![0-9Xx])", r"\1********\2", text)


def _apply_mask_rule(value: Any, rule: Any) -> Any:
    if rule == "redact":
        return "[REDACTED]"
    if isinstance(rule, str) and rule.startswith("truncate_"):
        try:
            limit = int(rule.split("_", 1)[1])
        except (IndexError, ValueError):
            limit = 500
        return _truncate_text(value, limit)
    if rule == "phone":
        return _mask_phone(value)
    if rule == "id_card":
        return _mask_id_card(value)
    if not isinstance(rule, dict):
        return value

    method = rule.get("method") or rule.get("type")
    if method == "redact":
        return "[REDACTED]"
    if method == "truncate":
        return _truncate_text(value, int(rule.get("limit") or 500))
    if method == "partial":
        return _partial_mask(
            value,
            keep_start=int(rule.get("keep_start") or 0),
            keep_end=int(rule.get("keep_end") or 0),
            mask=str(rule.get("mask") or "*"),
        )
    if method == "phone":
        return _mask_phone(value)
    if method in ("id_card", "idcard"):
        return _mask_id_card(value)
    if method == "regex_replace":
        pattern = rule.get("pattern")
        if not pattern:
            return value
        replacement = str(rule.get("replacement", "[MASKED]"))
        try:
            return re.sub(str(pattern), replacement, str(value))
        except re.error:
            return value
    return value


def apply_masking(event: dict[str, Any], asset: dict[str, Any]) -> dict[str, Any]:
    masking = asset.get("masking") or {}
    if not masking:
        return event
    out = copy.deepcopy(event)
    for field, rule in masking.items():
        exists, value = _get_mask_target(out, str(field))
        if not exists or value is None:
            continue
        _set_mask_target(out, str(field), _apply_mask_rule(value, rule))
    return out


def source_event_digest(asset: dict[str, Any], event: dict[str, Any]) -> str | None:
    """Identify replayed native events without collapsing distinct audit records.

    Require a native ID, host and event time; hash the full source payload so
    records sharing an audit ID (e.g. different file operations) stay distinct.
    Only known transport/analysis metadata is excluded. Explicit evidence IDs
    remain caller-owned; consumers may use this digest for counting old exports.
    """
    if not (event.get("audit_id") or event.get("event_id")):
        return None
    if not (event.get("host_ip") or event.get("host")) or not (event.get("time") or event.get("timestamp")):
        return None
    ignored = {"evidence_id", "_sls_timestamp", "__time__", "__tag__:__receive_time__",
               "__tag__:__pack_id__", "_original_normalized_timestamp", "_analysis_timestamp_source"}
    identity = {key: value for key, value in event.items() if key not in ignored}
    # Old exports can contain an ingestion-derived timestamp beside source time.
    if event.get("time"):
        identity["timestamp"] = event["time"]
    namespace = [event.get("_source_asset_id") or asset.get("asset_id") or "",
                 event.get("_source_connector_id") or asset.get("connector_id") or "",
                 asset.get("asset_type") or "event"]
    encoded = json.dumps([namespace, identity], sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()[:32]


def make_evidence_id(asset: dict[str, Any], event: dict[str, Any], seq: int) -> str:
    """Preserve caller IDs; generate source-scoped identities independent of order.

    ES document IDs are only unique within an index. Other connectors use a
    canonical content digest; identical records without a native identity cannot
    be distinguished. Keep ``seq`` in the API for older callers, but never hash
    the position in a query response. Hash before masking so redaction does not
    collapse distinct evidence. Native audit/event IDs use v3 replay-resistant
    identities; other generated IDs retain v2 compatibility.
    """
    existing = event.get("evidence_id")
    if existing not in (None, ""):
        return str(existing)
    asset_type = asset.get("asset_type", "event")
    prefix = asset_type.replace("_", "-")
    native_digest = source_event_digest(asset, event)
    if native_digest and not event.get("_es_id"):
        return f"{prefix}-v3-{native_digest}"
    namespace = [
        event.get("_source_asset_id") or asset.get("asset_id") or "",
        event.get("_source_connector_id") or asset.get("connector_id") or "",
        asset_type,
    ]
    if event.get("_es_id") not in (None, "") and event.get("_es_index"):
        identity = {"es_index": event["_es_index"], "es_id": event["_es_id"]}
    else:
        identity = {key: value for key, value in event.items() if key != "evidence_id"}
    encoded = json.dumps([namespace, identity], sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    digest = hashlib.sha256(encoded.encode()).hexdigest()[:32]
    return f"{prefix}-v2-{digest}"


def canonicalize_host(event: dict[str, Any], *, asset_type: str = "") -> dict[str, Any]:
    target_ip = event.get("target_ip")
    if target_ip:
        event["target_ip"] = _strip_upstream_host_ip(str(target_ip))

    host_ip = event.get("host_ip") or event.get("log_source") or event.get("_victim_host") or event.get("__source__")
    if host_ip:
        host_ip = _strip_upstream_host_ip(str(host_ip))
        event["host_ip"] = host_ip
    host = event.get("host") or event.get("host_name") or event.get("hostname")
    generic_hosts = {
        "localhost",
        "localhost.localdomain",
        "127.0.0.1",
        "::1",
    }
    if asset_type == "waf_alert":
        if event.get("target_ip"):
            if not host or str(host).lower() in generic_hosts:
                event["host"] = str(event["target_ip"])
        elif event.get("http_host") or event.get("victim_host"):
            vh = event.get("http_host") or event.get("victim_host")
            if not host or str(host).lower() in generic_hosts:
                event["host"] = str(vh)
        return event
    if asset_type == "web_access_log" and event.get("target_ip"):
        if not host or str(host).lower() in generic_hosts:
            event["host"] = str(event["target_ip"])
        return event
    if host_ip:
        if not host or str(host).lower() in generic_hosts:
            event["host"] = str(host_ip)
    elif host:
        event.setdefault("host_ip", host)
    return event


def normalize_event(event: dict[str, Any], asset: dict[str, Any], seq: int) -> dict[str, Any]:
    """Normalize source time first; fall back to transport time only if invalid.

    The declared schema time field takes priority over incidental aliases. Keep
    the SLS fallback separately for troubleshooting delayed or replayed uploads.
    """
    out = apply_aliases(event, asset)
    from trace_profile import repair_event, resolve_trace_profile

    profile = resolve_trace_profile(asset)
    if profile:
        out = repair_event(out, profile)
    out = normalize_event_source_ips(out)
    if asset.get("asset_type") == "waf_alert":
        from waf_enrich import canonicalize_waf_victim

        out = canonicalize_waf_victim(out)
    out = canonicalize_host(out, asset_type=str(asset.get("asset_type") or ""))
    if asset.get("asset_type") == "waf_alert":
        from waf_payload import resolve_waf_payload

        payload, meta = resolve_waf_payload(out)
        if payload:
            out["payload"] = payload
        if meta:
            out["payload_meta"] = meta
    correction = get_time_correction(asset)
    assume_tz = correction.get("assume_timezone")
    ts = None
    time_field = (asset.get("schema") or {}).get("time_field")
    for field in (time_field, "timestamp", "time", "__time__", "_sls_timestamp"):
        candidate = normalize_timestamp(out.get(field), assume_timezone=assume_tz)
        if not candidate:
            continue
        try:
            datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            continue
        ts = candidate
        break
    if ts:
        out["timestamp"] = apply_time_correction(ts, correction)
    out["evidence_id"] = make_evidence_id(asset, out, seq)
    out.pop("__time__", None)
    return apply_masking(out, asset)


def normalize_events(events: list[dict[str, Any]], asset: dict[str, Any]) -> list[dict[str, Any]]:
    return [normalize_event(ev, asset, i + 1) for i, ev in enumerate(events)]
