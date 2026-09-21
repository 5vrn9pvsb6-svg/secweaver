"""Shared timestamp helpers for risk-identification scripts."""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    return _parse_ts_cached(str(value))


@lru_cache(maxsize=8192)
def _parse_ts_cached(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def in_time_window(value: str | None, start: str | None, end: str | None) -> bool:
    """Keep only events provably inside a requested investigation window.

    Unparseable or timezone-ambiguous evidence cannot establish membership in
    an explicit window. Unbounded offline analysis keeps legacy input behavior.
    """
    if not start and not end:
        return True
    bounds = [("time_start", start), ("time_end", end)]
    parsed = {}
    for name, raw in bounds:
        if not raw:
            continue
        parsed[name] = parse_ts(raw)
        if parsed[name] is None or parsed[name].tzinfo is None:
            raise ValueError(f"{name} must be an ISO 8601 timestamp with timezone offset")
    timestamp = parse_ts(value)
    if timestamp is None or timestamp.tzinfo is None:
        return False
    return not (
        ("time_start" in parsed and timestamp < parsed["time_start"])
        or ("time_end" in parsed and timestamp > parsed["time_end"])
    )
