"""Repair and adapt syslog-risk-json (syslog_risk_alert) events for cross-skill use."""

from __future__ import annotations

from typing import Any

from trace_profile import (
    impact_on_target_types as _impact_on_target_types,
    is_null_field,
    load_trace_profile_template,
    repair_event,
    resolve_trace_profile,
    syslog_to_ssh_auth_event as _syslog_to_ssh_auth_event,
    syslog_victim_host as _syslog_victim_host,
)

# Backward-compatible constants (sourced from default TigerSec template).
_DEFAULT_PROFILE = load_trace_profile_template("secweaver-syslog-risk-alert")
_ssh = _DEFAULT_PROFILE.get("ssh_auth_derivation") or {}
SSH_SUCCESS_TYPES = frozenset(str(x) for x in (_ssh.get("success_event_types") or []))
SSH_FAILED_TYPES = frozenset(str(x) for x in (_ssh.get("failed_event_types") or []))
IMPACT_ON_TARGET_TYPES = _impact_on_target_types(_DEFAULT_PROFILE)


def apply_syslog_host_identity(event: dict[str, Any]) -> dict[str, Any]:
    """SLS syslog-risk-json：受害主机 IP 在 __source__，映射为 host_ip/host 供关联引擎使用。"""
    return repair_event(event, _DEFAULT_PROFILE)


def repair_syslog_risk_event(event: dict[str, Any], asset: dict[str, Any] | None = None) -> dict[str, Any]:
    """Unwrap JSON-in-content / SLS null columns into flat syslog-risk-json fields."""
    profile = resolve_trace_profile(asset) or _DEFAULT_PROFILE
    return repair_event(event, profile)


def syslog_victim_host(ev: dict[str, Any], asset: dict[str, Any] | None = None) -> str | None:
    """Return victim host IP; __source__ is authoritative when host_ip is absent in SLS."""
    profile = resolve_trace_profile(asset) or _DEFAULT_PROFILE
    return _syslog_victim_host(ev, profile)


def syslog_to_ssh_auth_event(ev: dict[str, Any], asset: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Map syslog-risk-json SSH events to ssh_auth bundle shape for matrix / BFS joins."""
    return _syslog_to_ssh_auth_event(ev, asset=asset)


def inject_ssh_auth_from_syslog_risk(
    bundles: dict[str, list[dict[str, Any]]],
    *,
    accepted_only: bool = False,
) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Append synthetic ssh_auth events derived from syslog_risk_alert (dedupe by evidence_id)."""
    out = dict(bundles or {})
    syslog_events = list(out.get("syslog_risk_alert") or [])
    if not syslog_events:
        return out, 0

    repaired_syslog: list[dict[str, Any]] = []
    ssh_auth = list(out.get("ssh_auth") or [])
    seen: set[str] = set()
    for ev in ssh_auth:
        eid = str(ev.get("evidence_id") or ev.get("_source_syslog_event_id") or "")
        if eid:
            seen.add(eid)

    injected = 0
    for ev in syslog_events:
        fixed = repair_syslog_risk_event(ev)
        repaired_syslog.append(fixed)
        ssh_ev = syslog_to_ssh_auth_event(fixed)
        if not ssh_ev:
            continue
        if accepted_only and ssh_ev.get("result") != "accepted":
            continue
        eid = str(ssh_ev.get("evidence_id") or ssh_ev.get("_source_syslog_event_id") or "")
        if eid and eid in seen:
            continue
        if eid:
            seen.add(eid)
        ssh_auth.append(ssh_ev)
        injected += 1

    out["syslog_risk_alert"] = repaired_syslog
    if ssh_auth:
        out["ssh_auth"] = ssh_auth
    return out, injected
