"""Traceability heuristics for syslog_risk_alert → lateral / impact on target hosts."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

DATA_ACCESS = Path(__file__).resolve().parents[3] / "_shared" / "data-access"
SCRIPTS = Path(__file__).resolve().parents[1]
if str(DATA_ACCESS) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS))
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from heuristic_rules import format_template, heuristic_time_window_deltas, section  # noqa: E402
from syslog_risk_normalize import (  # noqa: E402
    is_null_field,
    repair_syslog_risk_event,
    syslog_victim_host,
    syslog_to_ssh_auth_event,
)


def parse_ts(value: str | None) -> datetime | None:
    if not value or is_null_field(value):
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _syslog_cfg(rules: dict[str, Any] | None = None) -> dict[str, Any]:
    return section("syslog_lateral", rules=rules)


def _ssh_success_types(rules: dict[str, Any] | None = None) -> set[str]:
    auth = section("ssh_auth_result", rules=rules)
    return {str(x).lower() for x in auth.get("syslog_success_event_types") or ["ssh_login_success"]}


def _impact_types(rules: dict[str, Any] | None = None) -> set[str]:
    cfg = _syslog_cfg(rules)
    return {str(x).lower() for x in cfg.get("impact_event_types") or []}


def find_lateral_confirmations_from_syslog(
    syslog_events: list[dict[str, Any]],
    *,
    source_hosts: set[str],
    target_hosts: set[str],
    anchor: datetime | None,
    t_end: datetime | None,
    rules: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    cfg = _syslog_cfg(rules)
    if cfg.get("enabled") is False:
        return []

    window_before_min, _window_after_min = heuristic_time_window_deltas(
        "syslog_lateral", rules=rules
    )
    confirmed_cfg = dict(cfg.get("confirmed_lateral") or {})
    success_types = _ssh_success_types(rules)
    impact_types = _impact_types(rules)

    confirmations: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for raw in syslog_events or []:
        ev = repair_syslog_risk_event(raw)
        target = syslog_victim_host(ev)
        if not target or target not in target_hosts:
            continue

        ts = parse_ts(ev.get("timestamp"))
        if anchor and ts and ts < anchor - timedelta(minutes=window_before_min):
            continue
        if t_end and ts and ts > t_end:
            continue

        event_type = str(ev.get("event_type") or "").lower()
        src_ip = str(ev.get("src_ip") or ev.get("fields.src_ip") or "").strip()
        user = str(ev.get("user") or ev.get("fields.user") or "?")
        if event_type in success_types and (not src_ip or user == "?"):
            # Accepted SSH identity may be present only in message; use the
            # shared derivation so lateral confirmation matches auth bundles.
            derived = syslog_to_ssh_auth_event(ev) or {}
            src_ip = src_ip or str(derived.get("src_ip") or "").strip()
            user = user if user != "?" else str(derived.get("user") or "?")
        ref = ev.get("evidence_id") or ev.get("_ref") or ""

        if event_type in success_types and src_ip in source_hosts:
            key = (target, src_ip, user, "lateral_login")
            if key in seen:
                continue
            seen.add(key)
            confirmations.append(
                {
                    "stage": "lateral_movement",
                    "mitre_id": str(confirmed_cfg.get("mitre_id") or "T1021.004"),
                    "timestamp": ts.isoformat() if ts else ev.get("timestamp"),
                    "attempt_timestamp": None,
                    "confirmed_timestamp": ts.isoformat() if ts else ev.get("timestamp"),
                    "host": target,
                    "source_host": src_ip,
                    "user": None if user == "?" else user,
                    "lateral_class": str(confirmed_cfg.get("lateral_class") or "confirmed_lateral"),
                    "description": format_template(
                        str(confirmed_cfg.get("description_template") or ""),
                        src_ip=src_ip,
                        target=target,
                        user=user,
                    ),
                    "evidence_refs": [ref] if ref else [],
                    "join_ids": [str(confirmed_cfg.get("join_id") or "lateral_from_syslog")],
                    "confidence": float(confirmed_cfg.get("confidence") or 0.92),
                    "correlation_source": "syslog_risk_alert",
                    "impact_signal": event_type,
                }
            )
            continue

        if event_type in impact_types and src_ip in source_hosts:
            key = (target, src_ip, user, event_type)
            if key in seen:
                continue
            seen.add(key)
            confirmations.append(
                {
                    "stage": "impact",
                    "mitre_id": str(confirmed_cfg.get("impact_mitre_id") or "T1078"),
                    "timestamp": ts.isoformat() if ts else ev.get("timestamp"),
                    "host": target,
                    "source_host": src_ip,
                    "user": None if user == "?" else user,
                    "lateral_class": "confirmed_impact",
                    "description": format_template(
                        str(confirmed_cfg.get("impact_description_template") or ""),
                        target=target,
                        src_ip=src_ip,
                        event_type=event_type,
                    ),
                    "evidence_refs": [ref] if ref else [],
                    "join_ids": [str(confirmed_cfg.get("impact_join_id") or "impact_from_syslog")],
                    "confidence": float(confirmed_cfg.get("impact_confidence") or 0.88),
                    "correlation_source": "syslog_risk_alert",
                    "impact_signal": event_type,
                }
            )

    return confirmations


def upgrade_suspected_lateral_with_syslog(
    lateral_stages: list[dict[str, Any]],
    syslog_confirmations: list[dict[str, Any]],
    *,
    rules: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    cfg = _syslog_cfg(rules)
    upgrade = dict(cfg.get("upgrade_suspected") or {})
    confirmed_class = str((cfg.get("confirmed_lateral") or {}).get("lateral_class") or "confirmed_lateral")
    confirmed_by_pair: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
    for confirmation in syslog_confirmations:
        if confirmation.get("lateral_class") != confirmed_class:
            continue
        pair = (confirmation.get("source_host"), confirmation.get("host"))
        confirmed_by_pair.setdefault(pair, []).append(confirmation)
    confirmed_pairs = set(confirmed_by_pair)
    if not confirmed_pairs:
        return lateral_stages

    upgraded: list[dict[str, Any]] = []
    for stage in lateral_stages:
        row = dict(stage)
        pair = (row.get("source_host"), row.get("host"))
        if row.get("lateral_class") == "suspected_lateral" and pair in confirmed_pairs:
            row["attempt_timestamp"] = row.get("attempt_timestamp") or row.get("timestamp")
            row["lateral_class"] = "confirmed_lateral"
            row["confidence"] = max(
                float(row.get("confidence") or float(upgrade.get("suspected_confidence_floor") or 0.78)),
                float(upgrade.get("confirmed_confidence_floor") or 0.92),
            )
            row["correlation_source"] = str(upgrade.get("correlation_source") or "exec_inferred+syslog_risk_alert")
            join_ids = list(row.get("join_ids") or [])
            join_id = str((cfg.get("confirmed_lateral") or {}).get("join_id") or "lateral_from_syslog")
            if join_id not in join_ids:
                join_ids.append(join_id)
            evidence_refs = list(row.get("evidence_refs") or [])
            pair_confirmations = confirmed_by_pair.get(pair, [])
            confirmation_times = [
                confirmation.get("confirmed_timestamp") or confirmation.get("timestamp")
                for confirmation in pair_confirmations
                if confirmation.get("confirmed_timestamp") or confirmation.get("timestamp")
            ]
            if confirmation_times:
                row["confirmed_timestamp"] = min(str(value) for value in confirmation_times)
            for confirmation in pair_confirmations:
                for ref in confirmation.get("evidence_refs") or []:
                    if ref and ref not in evidence_refs:
                        evidence_refs.append(ref)
                for confirmation_join_id in confirmation.get("join_ids") or []:
                    if confirmation_join_id and confirmation_join_id not in join_ids:
                        join_ids.append(confirmation_join_id)
            row["join_ids"] = join_ids
            row["evidence_refs"] = evidence_refs
            note = str(upgrade.get("note") or "")
            if note:
                row["description"] = f"{row.get('description', '')}；{note}".strip("；")
        upgraded.append(row)
    return upgraded
