"""Bounded attacker-window narrowing and evidence filtering for trace fetches."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from fetch_summary import summarize_attacker_ip_log_time_range


ATTACKER_WINDOW_PADDING_SECONDS = 300


def parse_trace_datetime(value: Any) -> datetime | None:
    """Parse supported trace timestamps without guessing non-ISO text formats."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value)).astimezone()
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        try:
            return datetime.fromtimestamp(float(text)).astimezone()
        except (OverflowError, OSError, ValueError):
            return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def maybe_narrow_attacker_window(
    params: dict[str, Any],
    evidence: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Narrow follow-up scans around observed activity without widening scope.

    Padding is clamped to the caller's original bounds. Missing or unparseable
    activity keeps the original window, and callers may explicitly opt out.
    """
    if params.get("auto_narrow_attacker_window") is False:
        return params, None
    summary = summarize_attacker_ip_log_time_range(
        {"params": params, "evidence_bundles": evidence}
    )
    if not summary or not summary.get("first_seen") or not summary.get("last_seen"):
        return params, None

    first_seen = parse_trace_datetime(summary.get("first_seen"))
    last_seen = parse_trace_datetime(summary.get("last_seen"))
    if not first_seen or not last_seen:
        return params, None

    try:
        before_seconds = int(params.get("attacker_window_before_seconds", ATTACKER_WINDOW_PADDING_SECONDS))
    except (TypeError, ValueError):
        before_seconds = ATTACKER_WINDOW_PADDING_SECONDS
    try:
        after_seconds = int(params.get("attacker_window_after_seconds", ATTACKER_WINDOW_PADDING_SECONDS))
    except (TypeError, ValueError):
        after_seconds = ATTACKER_WINDOW_PADDING_SECONDS

    narrowed_start = first_seen - timedelta(seconds=max(before_seconds, 0))
    narrowed_end = last_seen + timedelta(seconds=max(after_seconds, 0))
    original_start = parse_trace_datetime(params.get("time_start"))
    original_end = parse_trace_datetime(params.get("time_end"))
    if original_start and narrowed_start < original_start:
        narrowed_start = original_start
    if original_end and narrowed_end > original_end:
        narrowed_end = original_end
    if narrowed_end < narrowed_start:
        return params, None

    narrowed = dict(params)
    narrowed["time_start"] = narrowed_start.isoformat()
    narrowed["time_end"] = narrowed_end.isoformat()
    if narrowed.get("time_start") == params.get("time_start") and narrowed.get("time_end") == params.get("time_end"):
        return params, None
    return narrowed, {
        "enabled": True,
        "source": "attacker_ip_log_time_range",
        "attacker_ip": summary.get("attacker_ip"),
        "first_seen": summary.get("first_seen"),
        "last_seen": summary.get("last_seen"),
        "source_bundles": summary.get("source_bundles") or [],
        "event_count": summary.get("event_count"),
        "padding_before_seconds": max(before_seconds, 0),
        "padding_after_seconds": max(after_seconds, 0),
        "original_time_start": params.get("time_start"),
        "original_time_end": params.get("time_end"),
        "narrowed_time_start": narrowed["time_start"],
        "narrowed_time_end": narrowed["time_end"],
    }


def _event_trace_time(event: dict[str, Any]) -> datetime | None:
    for key in (
        "timestamp",
        "@timestamp",
        "event_time",
        "log_time",
        "time",
        "__time__",
        "gmt_create",
        "date",
    ):
        parsed = parse_trace_datetime(event.get(key))
        if parsed:
            return parsed
    return None


def _dt_before(left: datetime, right: datetime) -> bool:
    if left.tzinfo and right.tzinfo:
        return left < right.astimezone(left.tzinfo)
    if left.tzinfo and not right.tzinfo:
        return left.replace(tzinfo=None) < right
    if not left.tzinfo and right.tzinfo:
        return left < right.replace(tzinfo=None)
    return left < right


def _dt_after(left: datetime, right: datetime) -> bool:
    if left.tzinfo and right.tzinfo:
        return left > right.astimezone(left.tzinfo)
    if left.tzinfo and not right.tzinfo:
        return left.replace(tzinfo=None) > right
    if not left.tzinfo and right.tzinfo:
        return left > right.replace(tzinfo=None)
    return left > right


def filter_evidence_by_time_window(
    evidence: dict[str, list[dict[str, Any]]],
    params: dict[str, Any],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any] | None]:
    """Drop timestamped out-of-window rows while retaining uncertain evidence.

    Rows without a usable timestamp remain visible and are counted separately;
    filtering therefore cannot turn missing time metadata into apparent absence.
    """
    start = parse_trace_datetime(params.get("time_start"))
    end = parse_trace_datetime(params.get("time_end"))
    if not start and not end:
        return evidence, None

    filtered: dict[str, list[dict[str, Any]]] = {}
    original_count = 0
    kept_count = 0
    dropped_count = 0
    dropped_by_asset_type: dict[str, int] = {}
    dropped_by_asset_id: dict[str, int] = {}
    kept_untimestamped_count = 0

    for asset_type, events in evidence.items():
        kept_events: list[dict[str, Any]] = []
        for event in events or []:
            original_count += 1
            if not isinstance(event, dict):
                kept_events.append(event)
                kept_count += 1
                kept_untimestamped_count += 1
                continue
            ts = _event_trace_time(event)
            if not ts:
                kept_events.append(event)
                kept_count += 1
                kept_untimestamped_count += 1
                continue
            if (start and _dt_before(ts, start)) or (end and _dt_after(ts, end)):
                dropped_count += 1
                dropped_by_asset_type[asset_type] = dropped_by_asset_type.get(asset_type, 0) + 1
                asset_id = str(event.get("_source_asset_id") or "").strip()
                if asset_id:
                    dropped_by_asset_id[asset_id] = dropped_by_asset_id.get(asset_id, 0) + 1
                continue
            kept_events.append(event)
            kept_count += 1
        filtered[asset_type] = kept_events

    if not dropped_count:
        return evidence, None
    return filtered, {
        "original_event_count": original_count,
        "kept_event_count": kept_count,
        "dropped_event_count": dropped_count,
        "kept_untimestamped_event_count": kept_untimestamped_count,
        "dropped_by_asset_type": dropped_by_asset_type,
        "dropped_by_asset_id": dropped_by_asset_id,
    }
