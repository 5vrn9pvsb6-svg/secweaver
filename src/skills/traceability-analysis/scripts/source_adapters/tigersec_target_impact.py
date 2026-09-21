"""Post-lateral impact signals from high-risk host_exec on the target host."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Any

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from heuristic_rules import (  # noqa: E402
    compile_high_risk_exec_rules,
    format_template,
    heuristic_time_window_bounds,
    heuristic_time_window_deltas,
    section,
)


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _cmd_text(ev: dict[str, Any]) -> str:
    for key in ("command_line", "command", "message", "raw_line"):
        value = ev.get(key)
        if value not in (None, "", "null"):
            if isinstance(value, list):
                return " ".join(str(x) for x in value)
            return str(value)
    return ""


def _event_host(ev: dict[str, Any]) -> str | None:
    for key in ("host_ip", "_victim_host", "host", "__source__"):
        value = ev.get(key)
        if value not in (None, "", "null"):
            text = str(value).strip()
            if text.lower() not in {"localhost", "localhost.localdomain"}:
                return text
    return None


def classify_high_risk_exec(command: str, *, rules: dict[str, Any] | None = None) -> list[str]:
    text = command or ""
    categories: list[str] = []
    seen: set[str] = set()
    for _rule_id, pattern, category in compile_high_risk_exec_rules(rules=rules):
        if category in seen:
            continue
        if pattern.search(text):
            seen.add(category)
            categories.append(category)
    return categories


def find_post_lateral_target_exec_signals(
    host_exec_events: list[dict[str, Any]],
    lateral_stages: list[dict[str, Any]],
    *,
    rules: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    cfg = section("target_exec_lateral", rules=rules)
    if cfg.get("enabled") is False:
        return []

    _, window_after_min = heuristic_time_window_deltas("target_exec_lateral", rules=rules)
    min_events = int(cfg.get("min_high_risk_events") or 3)
    min_categories = int(cfg.get("min_risk_categories") or 2)
    min_hits_floor = int(cfg.get("min_hits_floor") or 2)
    lateral_class = str(cfg.get("lateral_class") or "likely_lateral")

    suspected_pairs: dict[tuple[str, str], dict[str, Any]] = {}
    for stage in lateral_stages or []:
        if stage.get("lateral_class") not in {"suspected_lateral", "likely_lateral"}:
            continue
        src = str(stage.get("source_host") or "").strip()
        dst = str(stage.get("host") or "").strip()
        if not src or not dst:
            continue
        key = (src, dst)
        ts = parse_ts(stage.get("timestamp"))
        existing = suspected_pairs.get(key)
        if existing is None or (ts and parse_ts(existing.get("timestamp")) and ts < parse_ts(existing.get("timestamp"))):
            suspected_pairs[key] = dict(stage)

    if not suspected_pairs:
        return []

    signals: list[dict[str, Any]] = []
    for (source_host, target_host), lat in suspected_pairs.items():
        anchor = parse_ts(lat.get("timestamp"))
        if not anchor:
            continue
        window_start, window_end = heuristic_time_window_bounds(
            anchor, "target_exec_lateral", rules=rules
        )

        hits: list[dict[str, Any]] = []
        categories: set[str] = set()
        for ev in host_exec_events or []:
            host = _event_host(ev)
            if host != target_host:
                continue
            ts = parse_ts(ev.get("timestamp"))
            if not ts or ts < window_start or ts > window_end:
                continue
            cats = classify_high_risk_exec(_cmd_text(ev), rules=rules)
            if not cats:
                continue
            hits.append(
                {
                    "timestamp": ev.get("timestamp"),
                    "categories": cats,
                    "evidence_id": ev.get("evidence_id"),
                    "command_preview": _cmd_text(ev)[:120],
                }
            )
            categories.update(cats)

        if len(hits) < min_hits_floor:
            continue
        if len(hits) < min_events and len(categories) < min_categories:
            continue

        bonus_cap = float(cfg.get("confidence_bonus_cap") or 0.04)
        per_extra = float(cfg.get("confidence_per_extra_event") or 0.008)
        bonus = min(bonus_cap, max(0, len(hits) - min_events) * per_extra)
        confidence = round(
            min(float(cfg.get("confidence_cap") or 0.9), float(cfg.get("confidence_base") or 0.86) + bonus),
            2,
        )
        first_ts = hits[0]["timestamp"] if hits else lat.get("timestamp")
        cat_text = ", ".join(sorted(categories))
        signals.append(
            {
                "stage": "lateral_movement",
                "mitre_id": str(cfg.get("mitre_id") or "T1021.004"),
                "timestamp": first_ts,
                "host": target_host,
                "source_host": source_host,
                "user": lat.get("user"),
                "lateral_class": lateral_class,
                "description": format_template(
                    str(cfg.get("description_template") or ""),
                    target=target_host,
                    source=source_host,
                    event_count=len(hits),
                    categories=cat_text,
                ),
                "evidence_refs": [h["evidence_id"] for h in hits if h.get("evidence_id")][:12],
                "join_ids": [str(cfg.get("join_id") or "lateral_from_target_exec")],
                "confidence": confidence,
                "correlation_source": str(cfg.get("correlation_source") or "exec_inferred+target_host_exec"),
                "impact_signal": str(cfg.get("impact_signal") or "target_high_risk_exec_burst"),
                "high_risk_summary": {
                    "event_count": len(hits),
                    "categories": sorted(categories),
                    "window_minutes_after_lateral": window_after_min,
                },
            }
        )
    return signals


def upgrade_suspected_lateral_with_target_exec(
    lateral_stages: list[dict[str, Any]],
    target_exec_signals: list[dict[str, Any]],
    *,
    rules: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    cfg = section("target_exec_lateral", rules=rules)
    likely_class = str(cfg.get("lateral_class") or "likely_lateral")
    signal_by_pair = {
        (s.get("source_host"), s.get("host")): s
        for s in target_exec_signals
        if s.get("lateral_class") == likely_class
    }
    if not signal_by_pair:
        return lateral_stages

    join_id = str(cfg.get("join_id") or "lateral_from_target_exec")
    upgrade_note = str(cfg.get("upgrade_note") or "")
    suspected_floor = float(cfg.get("suspected_confidence_floor") or 0.78)

    upgraded: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str]] = set()
    for stage in lateral_stages:
        row = dict(stage)
        pair = (row.get("source_host"), row.get("host"))
        signal = signal_by_pair.get(pair)
        if signal and row.get("lateral_class") == "suspected_lateral":
            row["lateral_class"] = likely_class
            row["confidence"] = max(float(row.get("confidence") or suspected_floor), float(signal.get("confidence") or 0.86))
            row["correlation_source"] = str(cfg.get("correlation_source") or "exec_inferred+target_host_exec")
            joins = list(row.get("join_ids") or [])
            if join_id not in joins:
                joins.append(join_id)
            row["join_ids"] = joins
            refs = list(dict.fromkeys((row.get("evidence_refs") or []) + (signal.get("evidence_refs") or [])))
            row["evidence_refs"] = refs
            row["high_risk_summary"] = signal.get("high_risk_summary")
            if upgrade_note:
                row["description"] = f"{row.get('description', '')}；{upgrade_note}".strip("；")
            seen_pairs.add(pair)
        upgraded.append(row)

    for pair, signal in signal_by_pair.items():
        if pair in seen_pairs:
            continue
        upgraded.append(dict(signal))
    return upgraded


def impacted_note_for_likely_lateral(stage: dict[str, Any], *, rules: dict[str, Any] | None = None) -> str:
    cfg = section("target_exec_lateral", rules=rules)
    summary = stage.get("high_risk_summary") or {}
    return format_template(
        str(cfg.get("impacted_note_template") or ""),
        event_count=summary.get("event_count", "?"),
        categories=", ".join(summary.get("categories") or []),
    )
