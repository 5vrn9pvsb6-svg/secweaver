"""Declarative trace_profile engine — interprets dataasset/trace-profiles/*.json."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from dataasset_paths import DATAASSET_ROOT, REPO_ROOT

_NULL_SENTINELS = frozenset({None, "", "null", "None", "NULL"})

_TRACE_PROFILES_DIR = DATAASSET_ROOT / "trace-profiles"

_PROFILE_ID_COMPATIBILITY_ALIASES = {
    "secweaver-host-exec": "tigersec-host-exec",
    "secweaver-syslog-risk-alert": "tigersec-syslog-risk-alert",
}
_RISK_RULES_DIR = REPO_ROOT / "src" / "skills" / "risk-identification" / "rules"
_HEURISTIC_RULES_PATH = (
    REPO_ROOT / "src" / "skills" / "traceability-analysis" / "heuristic-rules.json"
)
_SSH_ACCEPTED_MESSAGE = re.compile(
    r"\bAccepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3})\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

_DEFAULT_PROFILE_BY_ASSET_TYPE = {
    "syslog_risk_alert": "secweaver-syslog-risk-alert",
    "host_exec": "secweaver-host-exec",
}


def is_null_field(value: Any) -> bool:
    if isinstance(value, (list, dict, set, tuple)):
        return False
    if value in _NULL_SENTINELS:
        return True
    return isinstance(value, str) and value.strip().lower() in {"null", "none"}


def _parse_json_blob(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not (text.startswith("{") and text.endswith("}")):
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return data


@lru_cache(maxsize=32)
def load_trace_profile_template(profile_id: str) -> dict[str, Any]:
    path = _TRACE_PROFILES_DIR / f"{profile_id}.json"
    if not path.is_file() and profile_id in _PROFILE_ID_COMPATIBILITY_ALIASES:
        path = _TRACE_PROFILES_DIR / f"{_PROFILE_ID_COMPATIBILITY_ALIASES[profile_id]}.json"
    if not path.is_file():
        raise FileNotFoundError(f"trace profile template not found: {path}")
    return _load_json(path)


def resolve_trace_profile(asset: dict[str, Any] | None) -> dict[str, Any] | None:
    if not asset:
        return None
    inline = asset.get("trace_profile")
    profile_id = asset.get("trace_profile_id")
    base: dict[str, Any] | None = None
    if profile_id:
        base = load_trace_profile_template(str(profile_id))
    elif inline and isinstance(inline, dict):
        base = dict(inline)
    else:
        default_id = _DEFAULT_PROFILE_BY_ASSET_TYPE.get(str(asset.get("asset_type") or ""))
        if default_id:
            base = load_trace_profile_template(default_id)
    if base is None:
        return None
    if inline and isinstance(inline, dict) and profile_id:
        return _deep_merge(base, inline)
    return base


def _first_field(event: dict[str, Any], fields: list[str]) -> Any:
    for key in fields:
        if key in event and not is_null_field(event.get(key)):
            return event.get(key)
    return None


def _ssh_message_fields(event: dict[str, Any]) -> dict[str, str]:
    """Extract only missing SSH auth fields from an Accepted message."""
    text = " ".join(
        str(event.get(field) or "")
        for field in ("message", "raw_behavior", "raw_line")
    )
    match = _SSH_ACCEPTED_MESSAGE.search(text)
    return match.groupdict() if match else {}


@lru_cache(maxsize=16)
def _load_exec_rules() -> dict[str, Any]:
    return _load_json(_RISK_RULES_DIR / "exec-rules.json")


@lru_cache(maxsize=4)
def _load_heuristic_rules() -> dict[str, Any]:
    return _load_json(_HEURISTIC_RULES_PATH)


def resolve_config_ref(ref: str) -> Any:
    if ref == "exec-rules.web_listeners":
        cfg = _load_exec_rules()
        listeners = cfg.get("web_listeners") or []
        return frozenset(str(x).lower() for x in listeners)
    if ref.startswith("heuristic-rules.policy."):
        path = ref.split(".", 2)[2] if ref.count(".") >= 2 else ""
        policy = _load_heuristic_rules().get("policy") or {}
        node: Any = policy
        for part in path.split("."):
            if not isinstance(node, dict):
                return None
            node = node.get(part)
        if isinstance(node, list):
            return node
        return node
    return None


def _unwrap_json_in_fields(event: dict[str, Any], step: dict[str, Any]) -> dict[str, Any]:
    skip_key = str(step.get("skip_if_set") or "event_type")
    if not is_null_field(event.get(skip_key)):
        return event
    out = dict(event)
    for key in step.get("fields") or []:
        parsed = _parse_json_blob(out.get(key))
        if not parsed:
            continue
        for pk, pv in parsed.items():
            if is_null_field(out.get(pk)) and not is_null_field(pv):
                out[pk] = pv
        if not is_null_field(out.get(skip_key)):
            break
    return out


def _fallback_timestamp(event: dict[str, Any], step: dict[str, Any]) -> dict[str, Any]:
    if not is_null_field(event.get("timestamp")):
        return event
    out = dict(event)
    for key in step.get("fields") or []:
        raw = out.get(key)
        if raw not in _NULL_SENTINELS and raw is not None:
            out["timestamp"] = raw
            break
    return out


def _map_source_to_host(event: dict[str, Any], step: dict[str, Any]) -> dict[str, Any]:
    out = dict(event)
    source_field = str(step.get("source_field") or "__source__")
    source = out.get(source_field)
    if is_null_field(source):
        return out
    victim = str(source).strip()
    generic = frozenset(str(x).lower() for x in (step.get("generic_hosts") or []))
    set_fields = list(step.get("set_fields") or ["host_ip", "host"])
    if set_fields:
        out.setdefault(set_fields[0], victim)
        host_field = set_fields[1] if len(set_fields) > 1 else set_fields[0]
        if is_null_field(out.get(host_field)) or str(out.get(host_field) or "").lower() in generic:
            out[host_field] = victim
    marker = step.get("victim_marker")
    if marker:
        out.setdefault(str(marker), victim)
    return out


def apply_event_repairs(event: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    out = dict(event)
    for step in profile.get("event_repairs") or []:
        step_type = step.get("type")
        if step_type == "unwrap_json_in_fields":
            out = _unwrap_json_in_fields(out, step)
        elif step_type == "fallback_timestamp":
            out = _fallback_timestamp(out, step)
        elif step_type == "map_source_to_host":
            out = _map_source_to_host(out, step)
    return out


def apply_host_identity(event: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    host_identity = profile.get("host_identity") or {}
    repairs = profile.get("event_repairs") or []
    if any(step.get("type") == "map_source_to_host" for step in repairs):
        return event
    step = {
        "type": "map_source_to_host",
        "source_field": "__source__",
        "set_fields": ["host_ip", "host"],
        "generic_hosts": host_identity.get("generic_hosts") or [],
        "victim_marker": "_victim_host",
    }
    return _map_source_to_host(event, step)


def repair_event(
    event: dict[str, Any],
    profile: dict[str, Any] | None = None,
    *,
    asset: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved = profile or resolve_trace_profile(asset)
    if not resolved:
        return dict(event)
    if not is_null_field(event.get("event_type")) and not (resolved.get("event_repairs") or []):
        out = dict(event)
    else:
        out = apply_event_repairs(event, resolved)
    return apply_host_identity(out, resolved)


def is_plausible_ip(value: Any) -> bool:
    if value in (None, ""):
        return False
    try:
        parts = str(value).strip().split(".")
        if len(parts) != 4:
            return False
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def extract_host_ip_from_event(ev: dict[str, Any], profile: dict[str, Any] | None = None) -> str | None:
    host_identity = (profile or {}).get("host_identity") or {}
    fields = host_identity.get("ip_fields") or ["host_ip", "_victim_host", "log_source", "__source__"]
    for key in fields:
        val = ev.get(key)
        if is_plausible_ip(val):
            return str(val).strip()
    return None


def exec_session_signals(ev: dict[str, Any], profile: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = (profile or {}).get("session_signals") or {}
    has_tty_field = str(cfg.get("has_tty_field") or "has_tty")
    tty_field = str(cfg.get("tty_field") or "tty")
    non_tty_values = frozenset(str(x).lower() for x in (cfg.get("non_interactive_tty_values") or []))
    interactive_prefixes = tuple(str(x) for x in (cfg.get("interactive_tty_prefixes") or ["pts"]))

    has_tty = ev.get(has_tty_field)
    tty = ev.get(tty_field)
    tty_str = str(tty).strip().lower() if tty not in (None, "") else ""
    non_interactive: bool | None = None
    if has_tty is False:
        non_interactive = True
    elif has_tty is True:
        non_interactive = False
    elif tty_str in non_tty_values:
        non_interactive = True
    elif any(tty_str.startswith(prefix) for prefix in interactive_prefixes):
        non_interactive = False
    return {"has_tty": has_tty, "tty": tty, "non_interactive": non_interactive}


def is_non_interactive_exec(ev: dict[str, Any], profile: dict[str, Any] | None = None) -> bool | None:
    return exec_session_signals(ev, profile).get("non_interactive")


def command_blob(ev: dict[str, Any], profile: dict[str, Any] | None = None) -> str:
    cfg = (profile or {}).get("web_entry_inference") or (profile or {}).get("lateral_parse") or {}
    fields = cfg.get("command_fields") or ["command_line", "command", "comm"]
    cmd = _first_field(ev, list(fields)) or ""
    if isinstance(cmd, list):
        return " ".join(str(c) for c in cmd).lower()
    return str(cmd).lower()


def _resolve_listener_sets(profile: dict[str, Any]) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    cfg = profile.get("web_entry_inference") or {}
    web_ref = resolve_config_ref(str(cfg.get("web_listeners_ref") or ""))
    ssh_ref = resolve_config_ref(str(cfg.get("ssh_listeners_ref") or ""))
    ports_ref = resolve_config_ref(str(cfg.get("web_ports_ref") or ""))

    web_listeners = web_ref if isinstance(web_ref, frozenset) else frozenset()
    if not web_listeners:
        web_listeners = frozenset(str(x).lower() for x in (cfg.get("fallback_web_listeners") or []))

    ssh_listeners: frozenset[str]
    if isinstance(ssh_ref, list):
        ssh_listeners = frozenset(str(x).lower() for x in ssh_ref)
    else:
        ssh_listeners = frozenset(str(x).lower() for x in (cfg.get("fallback_ssh_listeners") or []))

    web_ports: frozenset[str]
    if isinstance(ports_ref, list):
        web_ports = frozenset(str(x) for x in ports_ref)
    else:
        web_ports = frozenset(str(x) for x in (cfg.get("fallback_web_ports") or []))
    return web_listeners, ssh_listeners, web_ports


def _indirect_webshell_command(text: str, profile: dict[str, Any]) -> bool:
    cfg = profile.get("web_entry_inference") or {}
    for rule in cfg.get("indirect_webshell_rules") or []:
        parts = rule.get("substrings_all") or []
        if parts and all(part in text for part in parts):
            return True
    return False


def is_web_listener_exec(
    ev: dict[str, Any],
    webshell_patterns: list[str],
    profile: dict[str, Any] | None = None,
) -> bool:
    if profile is None:
        profile = load_trace_profile_template("secweaver-host-exec")
    cfg = profile.get("web_entry_inference") or {}
    listener_fields = cfg.get("listener_fields") or ["listener_process", "pid_name"]
    listener = str(_first_field(ev, list(listener_fields)) or "").lower()
    port = str(ev.get(str(cfg.get("port_field") or "listener_port")) or "")
    text = command_blob(ev, profile)

    shell_tokens = cfg.get("shell_invoke_tokens") or ["sh", "-c", "bash"]
    shell_invocation = "sh" in text and any(token in text for token in shell_tokens if token != "sh")
    indirect_ws = _indirect_webshell_command(text, profile)
    non_interactive = is_non_interactive_exec(ev, profile)
    web_listeners, ssh_listeners, web_ports = _resolve_listener_sets(profile)

    if listener in ssh_listeners or port == "22":
        if not indirect_ws:
            return False
        return non_interactive is not False

    webshell_substrings = cfg.get("webshell_substrings") or ["s.phtml", "webshell", "/uploads/"]
    if listener in web_listeners or port in web_ports:
        if shell_invocation or any(part in text for part in webshell_substrings):
            return True
        if any(p.lower() in text for p in webshell_patterns):
            return True
    if indirect_ws:
        return non_interactive is not False
    return False


@lru_cache(maxsize=8)
def _compiled_lateral_patterns(profile_id: str) -> list[dict[str, Any]]:
    profile = load_trace_profile_template(profile_id)
    lateral = profile.get("lateral_parse") or {}
    compiled: list[dict[str, Any]] = []
    for item in lateral.get("patterns") or []:
        compiled.append(
            {
                "id": item.get("id"),
                "regex": re.compile(str(item.get("regex")), re.IGNORECASE),
                "groups": list(item.get("groups") or []),
                "default_user": str(item.get("default_user") or "?"),
            }
        )
    return compiled


def extract_ssh_lateral_targets(
    text: str,
    profile: dict[str, Any] | None = None,
) -> list[tuple[str, str]]:
    if profile is None:
        profile = load_trace_profile_template("secweaver-host-exec")
    profile_id = str(profile.get("profile_id") or "secweaver-host-exec")
    patterns = _compiled_lateral_patterns(profile_id)
    results: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for item in patterns:
        pattern_id = str(item.get("id") or "")
        regex = item["regex"]
        groups = item["groups"]
        default_user = item["default_user"]
        if pattern_id == "user_at_ip" and len(groups) >= 2:
            for user, ip in regex.findall(text or ""):
                if not is_plausible_ip(ip):
                    continue
                key = (user, ip)
                if key not in seen:
                    seen.add(key)
                    results.append(key)
            continue
        for match in regex.finditer(text or ""):
            if pattern_id == "user_at_ip":
                continue
            for ip in match.groups():
                if ip and is_plausible_ip(ip):
                    key = (default_user, ip)
                    if key not in seen:
                        seen.add(key)
                        results.append(key)
    return results


def syslog_victim_host(ev: dict[str, Any], profile: dict[str, Any] | None = None) -> str | None:
    if profile is None:
        profile = load_trace_profile_template("secweaver-syslog-risk-alert")
    host_identity = profile.get("host_identity") or {}
    generic = frozenset(str(x).lower() for x in (host_identity.get("generic_hosts") or []))
    row = repair_event(ev, profile)
    fields = host_identity.get("victim_host_fields") or host_identity.get("ip_fields") or []
    for key in fields:
        value = ev.get(key)
        if is_null_field(value):
            continue
        text = str(value).strip()
        if text.lower() in generic:
            continue
        return text
    host_name = row.get("host_name")
    if not is_null_field(host_name):
        text = str(host_name).strip()
        if text.lower() not in generic:
            return text
    return None


def syslog_to_ssh_auth_event(
    ev: dict[str, Any],
    profile: dict[str, Any] | None = None,
    *,
    asset: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Derive SSH auth evidence without dropping the source rule or raw message."""
    resolved = profile or resolve_trace_profile(asset) or load_trace_profile_template("secweaver-syslog-risk-alert")
    row = repair_event(ev, resolved)
    derive = resolved.get("ssh_auth_derivation") or {}
    success_types = frozenset(str(x).lower() for x in (derive.get("success_event_types") or []))
    failed_types = frozenset(str(x).lower() for x in (derive.get("failed_event_types") or []))
    event_type = str(row.get("event_type") or "").lower()
    if event_type in success_types:
        result = "accepted"
    elif event_type in failed_types:
        result = "failed"
    else:
        return None

    host = syslog_victim_host(row, resolved)
    src_ip = _first_field(row, list(derive.get("src_ip_fields") or ["src_ip", "fields.src_ip"]))
    if is_null_field(src_ip):
        src_ip = _ssh_message_fields(row).get("src_ip")
    message_fields = _ssh_message_fields(row)
    user = _first_field(row, list(derive.get("user_fields") or ["user", "fields.user"]))
    port = _first_field(row, list(derive.get("port_fields") or ["port", "fields.port"]))
    if is_null_field(user):
        user = message_fields.get("user")
    if is_null_field(port):
        port = message_fields.get("port")
    message = row.get("message") or row.get("raw_behavior") or row.get("raw_line")

    return {
        "timestamp": row.get("timestamp"),
        "host": host,
        "host_name": row.get("host_name") or host,
        "host_ip": host,
        "src_ip": src_ip,
        "user": user,
        "port": port,
        "message": message,
        "raw_behavior": row.get("raw_behavior") or message,
        "result": result,
        "event_type": event_type,
        "rule_id": row.get("rule_id"),
        "rule_name": row.get("rule_name"),
        "risk_level": row.get("risk_level"),
        "evidence_id": row.get("evidence_id"),
        "_derived_from": "syslog_risk_alert",
        "_source_syslog_event_id": row.get("evidence_id"),
    }


def impact_on_target_types(profile: dict[str, Any] | None = None) -> frozenset[str]:
    resolved = profile or load_trace_profile_template("secweaver-syslog-risk-alert")
    values = resolved.get("impact_on_target_types") or []
    return frozenset(str(x) for x in values)
