"""Post-detection whitelist handling for risk-identification outputs."""

from __future__ import annotations

import ipaddress
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

SEVERITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
DEFAULT_WHITELIST_PATH = Path(__file__).resolve().parents[1] / "whitelist.json"
EXAMPLE_WHITELIST_PATH = Path(__file__).resolve().parents[1] / "whitelist.example.json"


def load_default_whitelist() -> dict[str, Any] | None:
    for path in (DEFAULT_WHITELIST_PATH, EXAMPLE_WHITELIST_PATH):
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return None
    return None


def whitelist_disabled(payload: dict[str, Any], policy_cfg: dict[str, Any]) -> bool:
    if policy_cfg.get("no_whitelist") or payload.get("no_whitelist"):
        return True
    if policy_cfg.get("whitelist_enabled") is False or payload.get("whitelist_enabled") is False:
        return True
    for key in ("whitelist", "risk_whitelist"):
        cfg = payload.get(key)
        if isinstance(cfg, dict) and cfg.get("enabled") is False:
            return True
    return False


def resolve_whitelist_config(
    payload: dict[str, Any],
    policy_cfg: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return whitelist JSON to apply, or None when opted out."""
    policy_cfg = policy_cfg or {}
    if whitelist_disabled(payload, policy_cfg):
        return None
    for key in ("risk_whitelist", "whitelist"):
        cfg = payload.get(key)
        if isinstance(cfg, dict) and cfg.get("rules"):
            return cfg
    custom_path = policy_cfg.get("whitelist_path") or payload.get("whitelist_path")
    if custom_path:
        path = Path(custom_path)
        if not path.is_absolute():
            path = Path(__file__).resolve().parents[1] / path
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return None
    return load_default_whitelist()


def command_text(item: dict[str, Any]) -> str:
    value = item.get("command")
    if isinstance(value, list):
        return " ".join(str(part) for part in value)
    return str(value or "")


def _as_list(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    return [value]


def _string_any(value: Any, candidates: list[Any]) -> bool:
    if not candidates:
        return True
    text = str(value or "").lower()
    return any(text == str(candidate).lower() for candidate in candidates)


def _int_any(value: Any, candidates: list[Any]) -> bool:
    if not candidates:
        return True
    try:
        number = int(value)
    except (TypeError, ValueError):
        return False
    allowed = set()
    for candidate in candidates:
        try:
            allowed.add(int(candidate))
        except (TypeError, ValueError):
            continue
    return number in allowed


def _regex_match(pattern: str | None, text: Any) -> bool:
    if not pattern:
        return True
    try:
        return re.search(pattern, str(text or ""), re.I) is not None
    except re.error:
        return False


def _cidr_match(value: Any, cidrs: list[Any]) -> bool:
    if not cidrs:
        return True
    try:
        addr = ipaddress.ip_address(str(value or ""))
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def _exe_prefix_match(value: Any, prefixes: list[Any]) -> bool:
    if not prefixes:
        return True
    exe = str(value or "")
    return any(exe.startswith(str(prefix)) for prefix in prefixes)


def _severity_at_or_above(value: Any, floor: str | None) -> bool:
    if not floor:
        return True
    return SEVERITY_RANK.get(str(value or "P3"), 99) <= SEVERITY_RANK.get(str(floor), 99)


def rule_matches(item: dict[str, Any], rule: dict[str, Any]) -> bool:
    if not rule.get("enabled", True):
        return False
    scope = rule.get("scope") or {}
    if not _string_any(item.get("risk_module"), _as_list(scope.get("risk_modules"))):
        return False
    if not _string_any(item.get("host"), _as_list(scope.get("hosts"))):
        return False
    if not _string_any(item.get("listener_process"), _as_list(scope.get("listener_process"))):
        return False
    if not _int_any(item.get("listener_port"), _as_list(scope.get("listener_ports"))):
        return False
    if not _int_any(item.get("dst_port"), _as_list(scope.get("dst_ports"))):
        return False
    if not _cidr_match(item.get("dst_ip"), _as_list(scope.get("dst_cidrs"))):
        return False
    matched_rules = set(str(r) for r in item.get("matched_rules") or [])
    exclude_rules = set(str(r) for r in _as_list(scope.get("exclude_matched_rules_any")))
    if exclude_rules and not matched_rules.isdisjoint(exclude_rules):
        return False
    any_rules = set(str(r) for r in _as_list(scope.get("matched_rules_any")))
    if any_rules and matched_rules.isdisjoint(any_rules):
        return False
    all_rules = set(str(r) for r in _as_list(scope.get("matched_rules_all")))
    if all_rules and not all_rules.issubset(matched_rules):
        return False
    if not _severity_at_or_above(item.get("severity"), scope.get("severity_at_or_above")):
        return False
    if not _regex_match(scope.get("command_regex"), command_text(item)):
        return False
    if not _regex_match(scope.get("exe_regex"), item.get("exe")):
        return False
    if not _exe_prefix_match(item.get("exe"), _as_list(scope.get("exe_prefixes"))):
        return False
    if not _regex_match(scope.get("summary_regex"), item.get("summary")):
        return False
    return True


def apply_rule(item: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any]:
    """Apply post-policy noise reduction without overriding mandatory alerts.

    Downgrades must update severity, action and delivery together. They may
    retain an existing alert at P0/P1, but must never reactivate a suppressed one.
    """
    out = deepcopy(item)
    if item.get("policy_tier") in {"hard_guardrail", "force_alert"} or item.get("policy_forced_alert"):
        return out
    original = {
        "severity": out.get("severity"),
        "verdict": out.get("verdict"),
        "recommended_action": out.get("recommended_action"),
        "confidence": out.get("confidence"),
    }
    action = str(rule.get("action") or "downgrade")
    out["whitelisted"] = True
    out["whitelist_rule_id"] = rule.get("id")
    out["whitelist_action"] = action
    out["whitelist_reason"] = rule.get("reason") or rule.get("description") or rule.get("id")
    out["pre_whitelist_risk"] = original
    out.setdefault("original_risk", original)
    out.setdefault("matched_rules", [])
    out.setdefault("alert_suppressed", False)
    if rule.get("id"):
        out["matched_rules"] = list(out["matched_rules"]) + [f"whitelist:{rule['id']}"]

    target_severity = rule.get("target_severity") or ("P3" if action == "suppress" else out.get("severity"))
    target_verdict = rule.get("target_verdict") or ("benign" if action == "suppress" else out.get("verdict"))
    default_action = {"P2": "observe", "P3": "log_only"}.get(str(target_severity), out.get("recommended_action"))
    target_action = rule.get("target_action") or ("log_only" if action == "suppress" else default_action)
    out["severity"] = target_severity
    out["verdict"] = target_verdict
    out["recommended_action"] = target_action
    out["alert_required"] = bool(item.get("alert_required", True) and not out["alert_suppressed"]
                                 and target_severity in {"P0", "P1"})
    if action == "suppress":
        out["alert_suppressed"] = True
        out["alert_required"] = False
        out["confidence"] = min(float(out.get("confidence") or 0), float(rule.get("target_confidence", 0.2)))
    elif "target_confidence" in rule:
        out["confidence"] = float(rule["target_confidence"])
    return out


def apply_whitelist(items: list[dict[str, Any]], whitelist: dict[str, Any] | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Apply first matching noise rule only after mandatory policy boundaries."""
    if not whitelist or not (whitelist.get("defaults") or {}).get("enabled", True):
        return [{**item, "alert_required": item.get("alert_required", True), "alert_suppressed": item.get("alert_suppressed", False)} for item in items], []
    rules = [rule for rule in whitelist.get("rules") or [] if rule.get("enabled", True)]
    out: list[dict[str, Any]] = []
    hits: list[dict[str, Any]] = []
    for item in items:
        if item.get("policy_tier") in {"hard_guardrail", "force_alert"} or item.get("policy_forced_alert"):
            out.append(deepcopy(item))
            continue
        applied = None
        for rule in rules:
            if rule_matches(item, rule):
                applied = rule
                break
        if applied:
            new_item = apply_rule(item, applied)
            hits.append({
                "risk_id": item.get("risk_id"),
                "rule_id": applied.get("id"),
                "action": applied.get("action") or "downgrade",
                "reason": new_item.get("whitelist_reason"),
            })
            out.append(new_item)
        else:
            clean_item = dict(item)
            clean_item.setdefault("alert_required", True)
            clean_item.setdefault("alert_suppressed", False)
            out.append(clean_item)
    return out, hits
