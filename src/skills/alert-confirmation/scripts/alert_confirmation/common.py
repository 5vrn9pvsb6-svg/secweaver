"""Shared input, time, host, and pattern helpers."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

from .paths import DATA_ACCESS_PATH

def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def parse_ts(value: str | int | float | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value)
        except (OSError, ValueError, OverflowError):
            return None
    text = str(value).strip()
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text))
        except (OSError, ValueError, OverflowError):
            return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def event_timestamp(ev: dict) -> datetime | None:
    for key in ("timestamp", "time", "__time__"):
        ts = parse_ts(ev.get(key))
        if ts is not None:
            return ts
    return None


def alert_timestamp(alert: dict) -> datetime | None:
    for key in ("timestamp", "time", "__time__"):
        ts = parse_ts(alert.get(key))
        if ts is not None:
            return ts
    return None


def victim_host_keys(alert: dict, params: dict | None = None) -> set[str]:
    keys: set[str] = set()
    for source in (alert, params or {}):
        if not source:
            continue
        for field in ("target_ip", "host_ip", "_victim_host", "victim_ip"):
            val = source.get(field)
            if val is None:
                continue
            text = str(val).strip()
            if text and text.lower() not in {"null", "none"}:
                keys.add(text)
        host = source.get("host")
        if host:
            text = str(host).strip()
            if text and "://" not in text and not text.endswith(":30443"):
                keys.add(text)
    return keys


def event_host_keys(ev: dict) -> set[str]:
    keys: set[str] = set()
    for field in ("host", "host_ip", "host_name", "_victim_host", "log_source"):
        val = ev.get(field)
        if val is None:
            continue
        text = str(val).strip()
        if text and text.lower() not in {"null", "none"}:
            keys.add(text)
    return keys


def host_matches_victim(ev: dict, victim_keys: set[str]) -> bool:
    if not victim_keys:
        return True
    return bool(victim_keys & event_host_keys(ev))


def investigation_time_bounds(params: dict | None) -> tuple[datetime | None, datetime | None]:
    if not params:
        return None, None
    return parse_ts(params.get("time_start")), parse_ts(params.get("time_end"))


def _ts_epoch(ts: datetime | None) -> float | None:
    if ts is None:
        return None
    try:
        return ts.timestamp()
    except (OSError, ValueError, OverflowError):
        return None


def event_in_investigation_window(ev: dict, params: dict | None) -> bool:
    ts = event_timestamp(ev)
    start, end = investigation_time_bounds(params)
    ts_epoch = _ts_epoch(ts)
    start_epoch = _ts_epoch(start)
    end_epoch = _ts_epoch(end)
    if ts_epoch is None:
        return True
    if start_epoch is not None and ts_epoch < start_epoch:
        return False
    if end_epoch is not None and ts_epoch > end_epoch:
        return False
    return True


def text_blob(alert: dict) -> str:
    parts = [
        alert.get("payload") or "",
        alert.get("url") or "",
        alert.get("request_body") or "",
        alert.get("query_string") or "",
    ]
    return " ".join(str(p) for p in parts if p)


def cmd_text(ev: dict) -> str:
    parts: list[str] = []
    line = ev.get("command_line") or ev.get("cmdline")
    if line:
        parts.append(str(line))
    cmd = ev.get("command")
    if isinstance(cmd, list):
        parts.append(" ".join(str(c) for c in cmd))
    elif cmd:
        parts.append(str(cmd))
    if ev.get("comm"):
        parts.append(str(ev.get("comm")))
    return " ".join(parts)


def match_patterns(text: str, patterns: list[str]) -> list[str]:
    lower = text.lower()
    return [p for p in patterns if p.lower() in lower]


def in_correlation_window(ev_ts: datetime | None, alert_ts: datetime | None, before_min: int, after_min: int) -> bool:
    ev_epoch = _ts_epoch(ev_ts)
    alert_epoch = _ts_epoch(alert_ts)
    if ev_epoch is None or alert_epoch is None:
        return False
    return alert_epoch - before_min * 60 <= ev_epoch <= alert_epoch + after_min * 60


def attack_success_window() -> tuple[int, int]:
    """Read attack_success time window from correlation-matrix."""
    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    from correlation_engine import time_window_spec

    spec = time_window_spec("attack_success")
    return int(spec.get("before_minutes", 5)), int(spec.get("after_minutes", 30))

