"""TigerSec / audit-port-execmon log shape adapter for traceability heuristics."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

SCRIPTS = Path(__file__).resolve().parents[1]
DATA_ACCESS = SCRIPTS.parents[1] / "_shared" / "data-access"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
if str(DATA_ACCESS) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS))

from heuristic_rules import policy_block, section  # noqa: E402
from risk_rules_bridge import web_listeners_from_exec_rules  # noqa: E402
from trace_profile import (  # noqa: E402
    exec_session_signals as _exec_session_signals,
    extract_host_ip_from_event as _extract_host_ip_from_event,
    extract_ssh_lateral_targets as _extract_ssh_lateral_targets,
    is_non_interactive_exec as _is_non_interactive_exec,
    is_web_listener_exec as _is_web_listener_exec,
    load_trace_profile_template,
    resolve_trace_profile,
)

_DEFAULT_EXEC_PROFILE = load_trace_profile_template("secweaver-host-exec")

# Backward-compatible module-level names (from template).
HOST_IP_FIELD_CANDIDATES = tuple(
    (_DEFAULT_EXEC_PROFILE.get("host_identity") or {}).get("ip_fields")
    or ["host_ip", "_victim_host", "log_source", "__source__"]
)
_session = _DEFAULT_EXEC_PROFILE.get("session_signals") or {}
NON_TTY_TTY_VALUES = frozenset(_session.get("non_interactive_tty_values") or ["(none)", "none", "?"])


def _profile_for_asset(asset: dict[str, Any] | None = None) -> dict[str, Any]:
    return resolve_trace_profile(asset) or _DEFAULT_EXEC_PROFILE


def _listener_policy() -> dict[str, Any]:
    return policy_block("listener")


def _web_listeners() -> frozenset[str]:
    listeners = web_listeners_from_exec_rules()
    if listeners:
        return listeners
    cfg = _DEFAULT_EXEC_PROFILE.get("web_entry_inference") or {}
    return frozenset(str(x).lower() for x in (cfg.get("fallback_web_listeners") or []))


def is_plausible_ip(value: Any) -> bool:
    from trace_profile import is_plausible_ip as _is_plausible_ip

    return _is_plausible_ip(value)


def extract_host_ip_from_event(ev: dict[str, Any], asset: dict[str, Any] | None = None) -> str | None:
    return _extract_host_ip_from_event(ev, _profile_for_asset(asset))


def extract_ssh_lateral_targets(text: str, asset: dict[str, Any] | None = None) -> list[tuple[str, str]]:
    """Parse exec command text for ssh/sshpass lateral targets → [(user, dst_ip), ...]."""
    return _extract_ssh_lateral_targets(text, _profile_for_asset(asset))


def exec_session_signals(ev: dict[str, Any], asset: dict[str, Any] | None = None) -> dict[str, Any]:
    """Derive TTY/session shape from audit-port-execmon fields (WebShell vs SSH ops)."""
    return _exec_session_signals(ev, _profile_for_asset(asset))


def is_non_interactive_exec(ev: dict[str, Any], asset: dict[str, Any] | None = None) -> bool | None:
    """True when WebShell/RCE-like (no PTY); False for interactive SSH; None if unknown."""
    return _is_non_interactive_exec(ev, _profile_for_asset(asset))


def initial_access_inference_note(
    ev: dict[str, Any],
    *,
    base: str | None = None,
    rules: dict[str, Any] | None = None,
) -> str:
    cfg = section("initial_access_exec_inferred", rules=rules)
    base = base or str(cfg.get("inference_note_base") or "无 WAF/WEB 日志，由 nginx/listener 子进程 exec 推断 Web 入口")
    non_interactive = is_non_interactive_exec(ev)
    if non_interactive is True:
        suffix = str(cfg.get("inference_note_non_interactive_suffix") or "has_tty=false（无交互终端，符合 WebShell/RCE 特征）")
        return f"{base}；{suffix}"
    if non_interactive is False:
        suffix = str(cfg.get("inference_note_interactive_suffix") or "has_tty=true（交互式 SSH 会话，非典型 Web 入口）")
        return f"{base}；{suffix}"
    return base


def is_web_listener_exec(
    ev: dict[str, Any],
    webshell_patterns: list[str],
    asset: dict[str, Any] | None = None,
) -> bool:
    return _is_web_listener_exec(ev, webshell_patterns, _profile_for_asset(asset))


from trace_profile import command_blob as _command_blob  # noqa: E402


def infer_initial_access_from_exec_event(
    ev: dict[str, Any],
    *,
    webshell_patterns: list[str] | None = None,
    host: str,
) -> dict[str, Any]:
    """Build exec_inferred initial_access dict from a single host_exec event."""
    text = _command_blob(ev, _DEFAULT_EXEC_PROFILE)
    vector = "webshell" if any(p in text for p in ("s.phtml", "webshell", "uploads/")) else "web_exploit"
    url = "/uploads/s.phtml" if "s.phtml" in text else "/uploads/"
    return {
        "host": host,
        "timestamp": ev.get("timestamp"),
        "vector": vector,
        "url": url if vector == "webshell" else None,
        "attacker_ip": None,
        "primary_evidence_refs": [ev.get("_ref") or ev.get("evidence_id")],
        "supporting_evidence_refs": [],
        "evidence_refs": [ev.get("_ref") or ev.get("evidence_id")],
        "correlation_source": "exec_inferred",
        "inference_note": initial_access_inference_note(ev),
        "session_signals": exec_session_signals(ev),
    }
