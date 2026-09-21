"""Load detection-layer rule packs from JSON (ops-editable, no hardcoded patterns in code)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SKILL_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = SKILL_ROOT / "rules"

PACK_ENGINE: dict[str, str] = {
    "exec-rules.json": "pipeline",
    "connect-rules.json": "chain",
    "dns-rules.json": "aggregate",
    "persistence-rules.json": "chain",
    "syslog-rules.json": "chain",
    "ssh-rules.json": "aggregate",
}

VALID_ENGINES = frozenset({"pipeline", "chain", "aggregate"})


def rules_dir() -> Path:
    return DEFAULT_RULES_DIR


def rule_file(name: str) -> Path:
    return rules_dir() / name


def compile_flags(flags: str) -> int:
    value = 0
    text = (flags or "").lower()
    if "i" in text:
        value |= re.I
    if "m" in text:
        value |= re.M
    if "s" in text:
        value |= re.S
    return value


def entry_enabled(entry: dict[str, Any]) -> bool:
    return entry.get("enabled", True) is not False


VALID_EXEC_MATCH_FIELDS = frozenset(
    {"command", "command_line", "exe", "comm", "cwd", "listener_process"}
)


def _validate_exec_match_field(field: str, label: str) -> None:
    if field not in VALID_EXEC_MATCH_FIELDS:
        raise ValueError(
            f"{label}: invalid field {field!r}; must be one of {sorted(VALID_EXEC_MATCH_FIELDS)}"
        )


def compile_pattern_entries(entries: list[dict[str, Any]]) -> list[tuple[str, re.Pattern[str]]]:
    """Legacy: (rule_id, pattern) without field — prefer compile_field_pattern_entries."""
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for entry in entries:
        if not entry_enabled(entry):
            continue
        rule_id = str(entry["id"])
        pattern = str(entry["pattern"])
        flags = compile_flags(str(entry.get("flags") or "i"))
        compiled.append((rule_id, re.compile(pattern, flags)))
    return compiled


def compile_field_pattern_entries(
    entries: list[dict[str, Any]],
) -> list[tuple[str, str, re.Pattern[str]]]:
    compiled: list[tuple[str, str, re.Pattern[str]]] = []
    for entry in entries:
        if not entry_enabled(entry):
            continue
        rule_id = str(entry["id"])
        field = str(entry["field"])
        pattern = str(entry["pattern"])
        flags = compile_flags(str(entry.get("flags") or "i"))
        compiled.append((rule_id, field, re.compile(pattern, flags)))
    return compiled


def normalize_keyword_entries(
    entries: list[Any],
    *,
    default_id: str = "noise_command",
) -> list[tuple[str, str, str]]:
    """Accept legacy plain strings or {id, field, keyword} objects."""
    out: list[tuple[str, str, str]] = []
    for entry in entries or []:
        if isinstance(entry, str):
            out.append((default_id, "command", entry))
            continue
        if not isinstance(entry, dict):
            continue
        if not entry_enabled(entry):
            continue
        rule_id = str(entry.get("id") or default_id)
        field = str(entry.get("field") or "command")
        keyword = str(entry.get("keyword") or "")
        if keyword:
            out.append((rule_id, field, keyword))
    return out


def load_rule_pack(path: Path | None = None, *, default_name: str) -> dict[str, Any]:
    target = path or rule_file(default_name)
    if not target.is_file():
        raise FileNotFoundError(f"Rule pack not found: {target}")
    with target.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Rule pack must be a JSON object: {target}")
    validate_rule_pack(data, default_name, target)
    return data


def validate_rule_pack(data: dict[str, Any], pack_name: str, path: Path | None = None) -> None:
    """Lightweight structural validation (no external jsonschema dependency)."""
    label = str(path or pack_name)
    version = data.get("version")
    if version is None:
        raise ValueError(f"{label}: missing 'version'")
    _validate_engine_field(data, pack_name, label)
    if pack_name == "exec-rules.json":
        _validate_exec_pack(data, label)
    elif pack_name == "connect-rules.json":
        _validate_connect_pack(data, label)
    elif pack_name == "dns-rules.json":
        _validate_dns_pack(data, label)
    elif pack_name == "ssh-rules.json":
        _validate_ssh_pack(data, label)
    elif pack_name == "persistence-rules.json":
        _validate_syslog_pack(data, label)
    elif pack_name == "syslog-rules.json":
        _validate_syslog_pack(data, label)
    elif pack_name == "attck-map.json":
        _validate_attck_map(data, label)


def _validate_engine_field(data: dict[str, Any], pack_name: str, label: str) -> None:
    expected = PACK_ENGINE.get(pack_name)
    if expected is None:
        return
    engine = data.get("engine")
    if engine is None:
        raise ValueError(f"{label}: missing 'engine' (expected {expected!r})")
    if str(engine) not in VALID_ENGINES:
        raise ValueError(f"{label}: invalid engine {engine!r}; must be one of {sorted(VALID_ENGINES)}")
    if str(engine) != expected:
        raise ValueError(f"{label}: engine {engine!r} does not match pack {pack_name!r} (expected {expected!r})")


def _validate_exec_pattern_entry(entry: dict[str, Any], label: str) -> None:
    if "id" not in entry or "pattern" not in entry:
        raise ValueError(f"{label} requires id and pattern")
    if "field" not in entry:
        raise ValueError(f"{label} requires 'field' (e.g. command, exe, comm, cwd)")
    field = str(entry["field"])
    _validate_exec_match_field(field, label)
    _validate_regex(entry["pattern"], label)


def _validate_exec_keyword_entry(entry: dict[str, Any], label: str) -> None:
    if "keyword" not in entry:
        raise ValueError(f"{label} requires keyword")
    if "field" not in entry:
        raise ValueError(f"{label} requires 'field' (e.g. command, exe, comm, cwd)")
    _validate_exec_match_field(str(entry["field"]), label)


def _validate_exec_pack(data: dict[str, Any], label: str) -> None:
    for section in ("p0_regex", "p1_regex", "p1_keyword_regex"):
        for idx, entry in enumerate(data.get(section) or []):
            if not isinstance(entry, dict):
                raise ValueError(f"{label}: {section}[{idx}] must be an object")
            _validate_exec_pattern_entry(entry, f"{label}:{section}[{idx}]")
    for section in ("p1_keywords", "p3_keywords"):
        for idx, entry in enumerate(data.get(section) or []):
            if isinstance(entry, str):
                continue
            if not isinstance(entry, dict):
                raise ValueError(f"{label}: {section}[{idx}] must be string or object")
            _validate_exec_keyword_entry(entry, f"{label}:{section}[{idx}]")
    fallback = data.get("fallback") or {}
    if fallback:
        fb_field = fallback.get("field")
        if fb_field is not None:
            _validate_exec_match_field(str(fb_field), f"{label}:fallback")
        for idx, entry in enumerate(fallback.get("elevations") or []):
            if not isinstance(entry, dict):
                continue
            if entry.get("pattern") and "field" not in entry:
                raise ValueError(f"{label}:fallback.elevations[{idx}] requires 'field' when using pattern")
            if entry.get("keyword") and "field" not in entry:
                raise ValueError(f"{label}:fallback.elevations[{idx}] requires 'field' when using keyword")
            if "field" in entry:
                _validate_exec_match_field(str(entry["field"]), f"{label}:fallback.elevations[{idx}]")
            if "pattern" in entry:
                _validate_regex(entry["pattern"], f"{label}:fallback.elevations[{idx}]")


def _validate_connect_pack(data: dict[str, Any], label: str) -> None:
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError(f"{label}: 'rules' must be a non-empty array")
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"{label}: rules[{idx}] must be an object")
        if "id" not in rule or "severity" not in rule or "when" not in rule:
            raise ValueError(f"{label}: rules[{idx}] requires id, severity, when")


def _validate_ssh_pack(data: dict[str, Any], label: str) -> None:
    brute = data.get("brute_force")
    if not isinstance(brute, dict):
        raise ValueError(f"{label}: missing 'brute_force' object")
    rule = data.get("brute_force_rule")
    if not isinstance(rule, dict):
        raise ValueError(f"{label}: missing 'brute_force_rule' object")
    for key in ("matched_rule", "policy_rule_id"):
        if key not in rule:
            raise ValueError(f"{label}: brute_force_rule missing '{key}'")
    for block in ("risk_tags", "verdicts", "actions", "confidence_base"):
        if block not in data or not isinstance(data.get(block), dict):
            raise ValueError(f"{label}: missing '{block}' object")
    for field in ("fail_message_pattern", "success_message_pattern"):
        if field in data:
            _validate_regex(data[field], f"{label}:{field}")


def _validate_dns_pack(data: dict[str, Any], label: str) -> None:
    for block in ("nxdomain_burst", "domain_profile", "doh_dot", "risk_tags", "verdicts", "actions", "confidence_base"):
        if block not in data or not isinstance(data.get(block), dict):
            raise ValueError(f"{label}: missing '{block}' object")
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError(f"{label}: 'rules' must be a non-empty array")
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"{label}: rules[{idx}] must be an object")
        if "id" not in rule or "severity" not in rule:
            raise ValueError(f"{label}: rules[{idx}] requires id and severity")


def _validate_syslog_pack(data: dict[str, Any], label: str) -> None:
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError(f"{label}: 'rules' must be a non-empty array")
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"{label}: rules[{idx}] must be an object")
        if "id" not in rule or "severity" not in rule or "when" not in rule:
            raise ValueError(f"{label}: rules[{idx}] requires id, severity, when")
    for idx, entry in enumerate(data.get("message_rules") or []):
        if not isinstance(entry, dict):
            raise ValueError(f"{label}: message_rules[{idx}] must be an object")
        if "id" not in entry or "pattern" not in entry or "severity" not in entry:
            raise ValueError(f"{label}: message_rules[{idx}] requires id, pattern, severity")
        _validate_regex(entry["pattern"], f"{label}:message_rules[{idx}]")


def _validate_attck_map(data: dict[str, Any], label: str) -> None:
    for section in ("matched_rules", "policy_rules"):
        block = data.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            raise ValueError(f"{label}: '{section}' must be an object")
        for key, entry in block.items():
            if not isinstance(entry, dict):
                raise ValueError(f"{label}: {section}[{key}] must be an object")
            techniques = entry.get("techniques")
            if techniques is None:
                continue
            if not isinstance(techniques, list):
                raise ValueError(f"{label}: {section}[{key}].techniques must be an array")
            for idx, tech in enumerate(techniques):
                if not isinstance(tech, dict) or not tech.get("id"):
                    raise ValueError(f"{label}: {section}[{key}].techniques[{idx}] requires id")


def _validate_regex(pattern: str, label: str) -> None:
    try:
        re.compile(str(pattern))
    except re.error as exc:
        raise ValueError(f"{label}: invalid regex {pattern!r}: {exc}") from exc


def configure_rules_dir(path: Path | str | None) -> None:
    """Override default rules directory (tests or custom deployment)."""
    global DEFAULT_RULES_DIR
    if path is None:
        DEFAULT_RULES_DIR = SKILL_ROOT / "rules"
    else:
        DEFAULT_RULES_DIR = Path(path)
