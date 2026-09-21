"""Load traceability heuristic-rules.json (ops-editable, no code deploy for rule tweaks)."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

SKILL_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_PATH = SKILL_ROOT / "heuristic-rules.json"
DATA_ACCESS_PATH = Path(__file__).resolve().parents[2] / "_shared" / "data-access"
DEFAULT_HEURISTIC_TIME_WINDOW = "lateral_movement"


def _compile_flags(flags: str) -> int:
    value = 0
    text = (flags or "").lower()
    if "i" in text:
        value |= re.I
    if "m" in text:
        value |= re.M
    if "s" in text:
        value |= re.S
    return value


def _entry_enabled(entry: dict[str, Any]) -> bool:
    return entry.get("enabled", True) is not False


@lru_cache(maxsize=4)
def load_heuristic_rules(path: str | None = None) -> dict[str, Any]:
    target = Path(path) if path else DEFAULT_RULES_PATH
    if not target.is_file():
        raise FileNotFoundError(f"heuristic-rules not found: {target}")
    with target.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"heuristic-rules must be a JSON object: {target}")
    return data


def rules_path() -> Path:
    return DEFAULT_RULES_PATH


def section(name: str, *, rules: dict[str, Any] | None = None) -> dict[str, Any]:
    doc = rules or load_heuristic_rules()
    block = doc.get(name)
    return dict(block) if isinstance(block, dict) else {}


def policy_block(name: str | None = None, *, rules: dict[str, Any] | None = None) -> dict[str, Any]:
    """Sub-block under heuristic-rules.json → policy (no separate trace-policy file)."""
    policy = section("policy", rules=rules)
    if not name:
        return policy
    block = policy.get(name)
    return dict(block) if isinstance(block, dict) else {}


def policy_verdict_rules(*, rules: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = section("policy", rules=rules)
    raw = policy.get("verdict_rules") or []
    return [dict(item) for item in raw if isinstance(item, dict)]


def match_verdict_conditions(conditions: dict[str, Any], context: dict[str, bool]) -> bool:
    if conditions.get("blocked") is True and not context.get("blocked"):
        return False
    for key in ("has_initial", "has_execution", "has_lateral", "has_exec"):
        if key in conditions and bool(conditions[key]) != bool(context.get(key)):
            return False
    return True


def resolve_verdict_from_policy(
    context: dict[str, bool],
    *,
    rules: dict[str, Any] | None = None,
) -> str:
    for rule in policy_verdict_rules(rules=rules):
        if match_verdict_conditions(dict(rule.get("conditions") or {}), context):
            return str(rule.get("verdict") or "insufficient_evidence")
    return "insufficient_evidence"


def lateral_join_ids(*, rules: dict[str, Any] | None = None) -> frozenset[str]:
    doc = rules or load_heuristic_rules()
    values = doc.get("lateral_join_ids") or []
    return frozenset(str(v) for v in values)


def compile_high_risk_exec_rules(*, rules: dict[str, Any] | None = None) -> list[tuple[str, re.Pattern[str], str]]:
    block = section("target_exec_lateral", rules=rules)
    compiled: list[tuple[str, re.Pattern[str], str]] = []
    for entry in block.get("high_risk_exec_rules") or []:
        if not isinstance(entry, dict) or not _entry_enabled(entry):
            continue
        rule_id = str(entry.get("id") or entry.get("category") or "rule")
        pattern = str(entry["pattern"])
        category = str(entry["category"])
        flags = _compile_flags(str(entry.get("flags") or "i"))
        compiled.append((rule_id, re.compile(pattern, flags), category))
    return compiled


def format_template(template: str, **kwargs: Any) -> str:
    try:
        return template.format(**kwargs)
    except KeyError:
        return template


def ssh_result_from_rules(ev: dict[str, Any], *, rules: dict[str, Any] | None = None) -> str:
    block = section("ssh_auth_result", rules=rules)
    result = str(ev.get("result") or "").lower()
    accepted = {str(x).lower() for x in block.get("accepted_tokens") or []}
    failed = {str(x).lower() for x in block.get("failed_tokens") or []}
    if result in failed or any(sub in result for sub in block.get("failed_substrings") or []):
        return "failed"
    if result in accepted or any(sub in result for sub in block.get("accepted_substrings") or []):
        return "accepted"
    event_type = str(ev.get("event_type") or "").lower()
    failed_types = {str(x).lower() for x in block.get("syslog_failed_event_types") or []}
    success_types = {str(x).lower() for x in block.get("syslog_success_event_types") or []}
    if event_type in failed_types:
        return "failed"
    if event_type in success_types:
        return "accepted"
    return result or "unknown"


def ssh_lateral_confirmed(ev: dict[str, Any], *, rules: dict[str, Any] | None = None) -> bool:
    return ssh_result_from_rules(ev, rules=rules) == "accepted"


def clear_rules_cache() -> None:
    load_heuristic_rules.cache_clear()


def _ensure_data_access_path() -> None:
    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))


def heuristic_time_window_id(
    section_name: str,
    *,
    rules: dict[str, Any] | None = None,
    default: str = DEFAULT_HEURISTIC_TIME_WINDOW,
) -> str:
    """Matrix time_windows key for a heuristic section (minutes live in correlation-matrix.json)."""
    block = section(section_name, rules=rules)
    return str(block.get("time_window") or default)


def matrix_window_deltas(
    window_id: str,
    *,
    matrix: dict[str, Any] | None = None,
) -> tuple[int, int]:
    """Return (before_minutes, after_minutes) for a correlation-matrix time_windows id."""
    _ensure_data_access_path()
    from correlation_engine import load_matrix, time_window_spec  # noqa: WPS433

    spec = time_window_spec(window_id, matrix or load_matrix())
    before = int(spec.get("before_minutes") or 0) + int(spec.get("before_hours") or 0) * 60
    after = int(spec.get("after_minutes") or 0) + int(spec.get("after_hours") or 0) * 60
    return before, after

def heuristic_time_window_deltas(
    section_name: str,
    *,
    rules: dict[str, Any] | None = None,
    matrix: dict[str, Any] | None = None,
    default_window_id: str = DEFAULT_HEURISTIC_TIME_WINDOW,
) -> tuple[int, int]:
    """Return (before_minutes, after_minutes) from correlation-matrix time_windows."""
    window_id = heuristic_time_window_id(
        section_name, rules=rules, default=default_window_id
    )
    return matrix_window_deltas(window_id, matrix=matrix)


def heuristic_time_window_bounds(
    anchor: datetime,
    section_name: str,
    *,
    rules: dict[str, Any] | None = None,
    matrix: dict[str, Any] | None = None,
    default_window_id: str = DEFAULT_HEURISTIC_TIME_WINDOW,
) -> tuple[datetime, datetime]:
    """Absolute [start, end] around anchor using matrix time_windows."""
    _ensure_data_access_path()
    from correlation_engine import load_matrix, time_window_bounds  # noqa: WPS433

    window_id = heuristic_time_window_id(
        section_name, rules=rules, default=default_window_id
    )
    return time_window_bounds(anchor, window_id, matrix or load_matrix())
