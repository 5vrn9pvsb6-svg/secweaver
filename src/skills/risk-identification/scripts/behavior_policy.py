"""Apply behavior-policy alert policy to risk items via declarative policy_engine."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from exec_rules import SEVERITY_RANK

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "behavior-policy.md"
RULE_HEADER_RE = re.compile(r"^###\s+([A-Z0-9-]+)\｜", re.M)


def _report_path(path: Path | str) -> str:
    """Keep repository-owned policy metadata portable across checkouts."""
    candidate = Path(path)
    try:
        return candidate.resolve().relative_to(REPO_ROOT).as_posix()
    except (OSError, ValueError):
        return candidate.as_posix()


@dataclass(frozen=True)
class PolicyDecision:
    rule_id: str
    tier: str
    severity: str
    alert_required: bool
    alert_suppressed: bool
    verdict: str
    recommended_action: str
    reason: str

    @property
    def priority(self) -> tuple[int, int]:
        tier_order = {"force_alert": 0, "downgrade": 1, "default": 2, "hard_guardrail": 3}
        return (tier_order.get(self.tier, 9), SEVERITY_RANK.get(self.severity, 9))


def command_argv(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(part) for part in value]
    text = str(value or "").strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(part) for part in parsed]
        except json.JSONDecodeError:
            pass
    return [text]


def command_text(item: dict[str, Any]) -> str:
    return " ".join(command_argv(item.get("command")))


def listener_port(item: dict[str, Any]) -> int | None:
    raw = item.get("listener_port")
    if raw in (None, ""):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def matched_rules(item: dict[str, Any]) -> set[str]:
    return {str(r) for r in item.get("matched_rules") or []}


def default_decision(item: dict[str, Any]) -> PolicyDecision:
    severity = str(item.get("severity") or "P3")
    if severity in ("P0", "P1"):
        return PolicyDecision(
            rule_id="DEFAULT-ALERT",
            tier="default",
            severity=severity,
            alert_required=True,
            alert_suppressed=False,
            verdict=str(item.get("verdict") or "suspicious"),
            recommended_action=str(item.get("recommended_action") or "investigate"),
            reason="第一节默认：P0/P1 需要告警",
        )
    if severity == "P2":
        return PolicyDecision(
            rule_id="DEFAULT-OBSERVE",
            tier="default",
            severity="P2",
            alert_required=False,
            alert_suppressed=False,
            verdict=str(item.get("verdict") or "suspicious"),
            recommended_action=str(item.get("recommended_action") or "observe"),
            reason="第一节默认：P2 仅观察",
        )
    return PolicyDecision(
        rule_id="DEFAULT-LOG",
        tier="default",
        severity="P3",
        alert_required=False,
        alert_suppressed=False,
        verdict=str(item.get("verdict") or "likely_false_positive"),
        recommended_action=str(item.get("recommended_action") or "log_only"),
        reason="第一节默认：P3 仅留痕",
    )


def pick_best_decision(
    *,
    hard: PolicyDecision | None,
    force: list[PolicyDecision],
    downgrade: list[PolicyDecision],
    default: PolicyDecision,
) -> PolicyDecision:
    if force:
        return min(force, key=lambda d: (d.priority[1], d.priority[0]))
    if downgrade and hard is None:
        suppress = [d for d in downgrade if d.alert_suppressed]
        if suppress:
            return suppress[0]
        return downgrade[0]
    if hard is not None:
        return hard
    return default


def apply_decision(item: dict[str, Any], decision: PolicyDecision) -> dict[str, Any]:
    out = deepcopy(item)
    out["original_risk"] = {
        "severity": item.get("severity"),
        "verdict": item.get("verdict"),
        "recommended_action": item.get("recommended_action"),
        "confidence": item.get("confidence"),
    }
    out["policy_rule_id"] = decision.rule_id
    out["policy_tier"] = decision.tier
    out["policy_reason"] = decision.reason
    out["severity"] = decision.severity
    out["verdict"] = decision.verdict
    out["recommended_action"] = decision.recommended_action
    out["alert_required"] = decision.alert_required
    out["alert_suppressed"] = decision.alert_suppressed
    if decision.tier == "downgrade":
        out["policy_downgraded"] = True
    if decision.tier == "force_alert":
        out["policy_forced_alert"] = True
    return out


def evaluate_item(
    item: dict[str, Any],
    *,
    rules_path: Path | str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    from policy_engine import evaluate_item_with_engine

    return evaluate_item_with_engine(item, rules_path=rules_path)


def load_policy_document(path: Path | None = None) -> dict[str, Any]:
    policy_path = path or DEFAULT_POLICY_PATH
    if not policy_path.is_file():
        return {"enabled": False, "path": _report_path(policy_path), "rule_ids": [], "document": ""}
    text = policy_path.read_text(encoding="utf-8")
    rule_ids = RULE_HEADER_RE.findall(text)
    enabled = True
    if text.startswith("---"):
        front = text.split("---", 2)
        if len(front) >= 3 and "enabled: false" in front[1]:
            enabled = False
    return {
        "enabled": enabled,
        "path": _report_path(policy_path),
        "format": "natural_language_v1",
        "rule_ids": rule_ids,
        "document_chars": len(text),
    }


def apply_behavior_policy(
    items: list[dict[str, Any]],
    *,
    policy_path: Path | None = None,
    rules_path: Path | str | None = None,
    enabled: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    from policy_engine import get_policy_rules, resolve_rules_path

    resolved_rules = resolve_rules_path(rules_path)
    meta = load_policy_document(policy_path)
    pack = get_policy_rules(resolved_rules)
    meta["rules_pack"] = _report_path(resolved_rules)
    meta["rules_pack_id"] = pack.get("policy_id")
    meta["rules_engine"] = "policy_engine_v3"

    if not enabled or not meta.get("enabled", True):
        normalized = []
        for item in items:
            clean = dict(item)
            clean.setdefault("alert_required", clean.get("severity") in ("P0", "P1"))
            clean.setdefault("alert_suppressed", False)
            normalized.append(clean)
        meta["applied"] = False
        return normalized, [], meta

    out_items: list[dict[str, Any]] = []
    hits: list[dict[str, Any]] = []
    for item in items:
        updated, hit = evaluate_item(item, rules_path=resolved_rules)
        out_items.append(updated)
        hits.append(hit)
    meta["applied"] = True
    meta["hits"] = len(hits)
    return out_items, hits, meta
