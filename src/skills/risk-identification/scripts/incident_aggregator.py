"""Aggregate raw risk_items into incident summaries for reporting."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any

from exec_rules import SEVERITY_RANK

LOCALHOST_RE = re.compile(r"https?://127\.0\.0\.1|https?://localhost\b", re.I)


def command_fingerprint(command: Any) -> str:
    if isinstance(command, list):
        text = " ".join(str(part) for part in command)
    else:
        text = str(command or "")
    text = text.strip()
    if not text:
        return ""
    text = LOCALHOST_RE.sub("http://127.0.0.1/", text)
    text = re.sub(r"sshpass -p \S+", "sshpass -p *", text)
    text = re.sub(r"\s+", " ", text)
    return text[:160]


def incident_signature(item: dict[str, Any]) -> tuple[str, ...]:
    rules = item.get("matched_rules") or []
    rule_hint = str(item.get("policy_rule_id") or (rules[0] if rules else ""))
    return (
        str(item.get("host") or ""),
        str(item.get("risk_module") or ""),
        rule_hint,
        str(item.get("listener_process") or ""),
        str(item.get("listener_port") or ""),
        command_fingerprint(item.get("command")),
        str(item.get("src_ip") or ""),
    )


def _best_severity(items: list[dict[str, Any]]) -> str:
    severities = [str(it.get("severity") or "P3") for it in items]
    return min(severities, key=lambda s: SEVERITY_RANK.get(s, 9))


def _timestamp_bounds(items: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    stamps = sorted(str(it.get("timestamp") or "") for it in items if it.get("timestamp"))
    if not stamps:
        return None, None
    return stamps[0], stamps[-1]


def make_incident_id(signature: tuple[str, ...]) -> str:
    digest = hashlib.sha256("|".join(signature).encode()).hexdigest()[:10]
    return f"incident-{digest}"


def aggregate_incidents(
    items: list[dict[str, Any]],
    *,
    top_n: int = 20,
    alerting_only: bool = False,
) -> list[dict[str, Any]]:
    """Group risk_items by signature; rank by alert_required, severity, volume."""
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        groups[incident_signature(item)].append(item)

    summaries: list[dict[str, Any]] = []
    for signature, group in groups.items():
        alerting_items = [
            it for it in group if it.get("alert_required", True) and not it.get("alert_suppressed")
        ]
        if alerting_only and not alerting_items:
            continue
        representative = alerting_items[0] if alerting_items else group[0]
        first_seen, last_seen = _timestamp_bounds(group)
        severity = _best_severity(alerting_items or group)
        summaries.append(
            {
                "incident_id": make_incident_id(signature),
                "host": signature[0] or representative.get("host"),
                "risk_module": signature[1] or representative.get("risk_module"),
                "policy_rule_id": representative.get("policy_rule_id"),
                "listener_process": signature[3] or representative.get("listener_process"),
                "listener_port": signature[4] or representative.get("listener_port"),
                "severity": severity,
                "alert_required": bool(alerting_items),
                "event_count": len(group),
                "alert_count": len(alerting_items),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "summary": representative.get("summary"),
                "command_sample": command_fingerprint(representative.get("command")) or None,
                "src_ip": representative.get("src_ip"),
                "fail_count": representative.get("fail_count"),
                "sample_risk_ids": [it.get("risk_id") for it in group[:5] if it.get("risk_id")],
                "mitre_attack": representative.get("mitre_attack"),
            }
        )

    def sort_key(row: dict[str, Any]) -> tuple[int, int, int, int]:
        alert_rank = 0 if row.get("alert_required") else 1
        sev_rank = SEVERITY_RANK.get(str(row.get("severity") or "P3"), 9)
        return (alert_rank, sev_rank, -int(row.get("alert_count") or 0), -int(row.get("event_count") or 0))

    summaries.sort(key=sort_key)
    return summaries[: max(1, top_n)]


def incidents_from_params(params: dict[str, Any]) -> tuple[int, bool]:
    top_n = int(params.get("incident_top_n") or 20)
    alerting_only = bool(params.get("incident_alerting_only", True))
    return top_n, alerting_only
