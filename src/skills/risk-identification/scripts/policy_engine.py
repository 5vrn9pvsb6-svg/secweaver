"""Declarative behavior-policy rule engine (CLI/CI single source with behavior-policy.rules.json)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from shared_conditions import (
    ConditionPack,
    condition_pack_from_config,
    eval_condition,
    _eval_guardrail_matched,
)

SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES_PATH = SKILL_ROOT / "rules" / "behavior-policy.rules.json"


def resolve_rules_path(path: Path | str | None = None) -> Path:
    if path is None:
        return DEFAULT_RULES_PATH
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = SKILL_ROOT / candidate
    return candidate.resolve()


def load_policy_rules(path: Path | str | None = None) -> dict[str, Any]:
    target = resolve_rules_path(path)
    with target.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {target}")
    return data


@lru_cache(maxsize=8)
def _cached_rules(path_str: str) -> dict[str, Any]:
    return load_policy_rules(path_str)


def get_policy_rules(path: Path | str | None = None) -> dict[str, Any]:
    target = resolve_rules_path(path)
    return _cached_rules(str(target))


def build_engine_context(pack: dict[str, Any]) -> ConditionPack:
    return condition_pack_from_config(pack)


def _module_allowed(item: dict[str, Any], modules: list[str] | None) -> bool:
    if not modules:
        return True
    return str(item.get("risk_module") or "") in modules


def _rule_matches(item: dict[str, Any], rule: dict[str, Any], pack: ConditionPack) -> bool:
    if rule.get("enabled") is False:
        return False
    if not _module_allowed(item, rule.get("modules")):
        return False
    when = rule.get("when") or {}
    if when.get("type") == "guardrail_matched":
        ok, _ = _eval_guardrail_matched(item, when, pack)
        if not ok:
            return False
    elif not eval_condition(item, when, pack):
        return False
    for unless in rule.get("unless") or []:
        if eval_condition(item, unless, pack):
            return False
    return True


def _resolve_severity(item: dict[str, Any], decision: dict[str, Any], pack: ConditionPack) -> str:
    for entry in decision.get("severity_when") or []:
        if eval_condition(item, entry.get("when") or {}, pack):
            return str(entry.get("severity") or decision.get("severity") or "P3")
    if decision.get("inherit_severity"):
        return str(item.get("severity") or decision.get("severity") or "P3")
    return str(decision.get("severity") or "P3")


def _build_decision(
    item: dict[str, Any],
    rule: dict[str, Any],
    pack: ConditionPack,
    *,
    matched_rule: str | None = None,
) -> Any:
    import behavior_policy as bp

    spec = rule.get("decision") or {}
    rule_id = str(rule.get("id") or "")
    if rule.get("id_template") and matched_rule:
        rule_id = str(rule["id_template"]).replace("{matched_rule}", matched_rule.upper())
    reason = str(spec.get("reason") or "")
    if matched_rule:
        reason = reason.replace("{matched_rule}", matched_rule)

    verdict = str(item.get("verdict") or spec.get("verdict") or "suspicious")
    if not spec.get("inherit_verdict"):
        verdict = str(spec.get("verdict") or verdict)

    action = str(item.get("recommended_action") or spec.get("recommended_action") or "observe")
    if not spec.get("inherit_recommended_action"):
        action = str(spec.get("recommended_action") or action)

    return bp.PolicyDecision(
        rule_id=rule_id,
        tier=str(rule.get("tier") or "default"),
        severity=_resolve_severity(item, spec, pack),
        alert_required=bool(spec.get("alert_required")),
        alert_suppressed=bool(spec.get("alert_suppressed", False)),
        verdict=verdict,
        recommended_action=action,
        reason=reason,
    )


def _default_decision(item: dict[str, Any], rules_doc: dict[str, Any], pack: ConditionPack) -> Any:
    import behavior_policy as bp

    for rule in rules_doc.get("default_behavior", {}).get("rules") or []:
        if eval_condition(item, rule.get("when") or {}, pack):
            return _build_decision(
                item,
                {"id": rule["id"], "tier": "default", "decision": rule["decision"]},
                pack,
            )
    return bp.default_decision(item)


def evaluate_item_declarative(
    item: dict[str, Any],
    pack: dict[str, Any] | None = None,
    *,
    rules_path: Path | str | None = None,
) -> Any:
    """Return PolicyDecision using behavior-policy.rules.json."""
    import behavior_policy as bp

    rules_doc = pack or get_policy_rules(rules_path)
    cond_pack = build_engine_context(rules_doc)
    hard: Any | None = None
    force: list[Any] = []
    downgrade: list[Any] = []

    for rule in rules_doc.get("rules") or []:
        tier = str(rule.get("tier") or "")
        when = rule.get("when") or {}
        if when.get("type") == "guardrail_matched":
            ok, matched_rule = _eval_guardrail_matched(item, when, cond_pack)
            if not ok or hard is not None:
                continue
            unless_blocked = any(eval_condition(item, u, cond_pack) for u in (rule.get("unless") or []))
            if unless_blocked:
                continue
            hard = _build_decision(item, rule, cond_pack, matched_rule=matched_rule)
            continue
        if not _rule_matches(item, rule, cond_pack):
            continue
        decision = _build_decision(item, rule, cond_pack)
        if tier == "hard_guardrail" and hard is None:
            hard = decision
        elif tier == "force_alert":
            force.append(decision)
        elif tier == "downgrade":
            downgrade.append(decision)

    default = _default_decision(item, rules_doc, cond_pack)
    return bp.pick_best_decision(hard=hard, force=force, downgrade=downgrade if not force else [], default=default)


def evaluate_item_with_engine(
    item: dict[str, Any],
    *,
    rules_path: Path | str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Drop-in replacement for behavior_policy.evaluate_item using declarative rules."""
    import behavior_policy as bp

    pack = get_policy_rules(rules_path)
    decision = evaluate_item_declarative(item, pack, rules_path=rules_path)
    updated = bp.apply_decision(item, decision)
    hit_record = {
        "risk_id": item.get("risk_id"),
        "rule_id": decision.rule_id,
        "tier": decision.tier,
        "action": "force_alert"
        if decision.alert_required
        else ("suppress" if decision.alert_suppressed else "observe"),
        "reason": decision.reason,
        "original_severity": item.get("severity"),
        "final_severity": decision.severity,
    }
    return updated, hit_record


def list_rule_ids(pack: dict[str, Any] | None = None, *, rules_path: Path | str | None = None) -> set[str]:
    doc = pack or get_policy_rules(rules_path)
    ids: set[str] = set()
    for rule in doc.get("rules") or []:
        if rule.get("id"):
            ids.add(str(rule["id"]))
    for rule in doc.get("default_behavior", {}).get("rules") or []:
        if rule.get("id"):
            ids.add(str(rule["id"]))
    return ids


def list_predicate_names(pack: dict[str, Any] | None = None, *, rules_path: Path | str | None = None) -> set[str]:
    doc = pack or get_policy_rules(rules_path)
    return set(str(k) for k in (doc.get("predicates") or {}).keys())
