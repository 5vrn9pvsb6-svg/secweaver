"""Shared declarative condition evaluator for policy / connect / syslog rule packs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

EvalContext = dict[str, Any]
WhenHandler = Callable[[EvalContext, Any], bool]


@dataclass
class ConditionPack:
    predicates: dict[str, dict[str, Any]] = field(default_factory=dict)
    when_handlers: dict[str, WhenHandler] = field(default_factory=dict)
    when_extensions: dict[str, dict[str, Any]] = field(default_factory=dict)


def command_text(item: dict[str, Any]) -> str:
    from behavior_policy import command_argv

    argv = command_argv(item.get("command"))
    return " ".join(argv)


def matched_rules(item: dict[str, Any]) -> set[str]:
    return {str(r) for r in item.get("matched_rules") or []}


def listener_port_value(item: dict[str, Any], field_name: str = "listener_port") -> int | None:
    raw = item.get(field_name)
    if raw in (None, ""):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _field_value(item: dict[str, Any], field_name: str) -> Any:
    if field_name in item:
        return item.get(field_name)
    if field_name == "command_text":
        return command_text(item)
    return item.get(field_name)


def _eval_guardrail_matched(item: dict[str, Any], cond: dict[str, Any], pack: ConditionPack) -> tuple[bool, str | None]:
    rules = matched_rules(item)
    candidates = frozenset(str(x) for x in (cond.get("matched_rules_any") or []))
    hit = rules & candidates
    if not hit:
        return False, None
    matched_rule = sorted(hit)[0]
    skip_cfg = cond.get("skip_persistence_when") or {}
    skip_rule = str(skip_cfg.get("matched_rule") or "")
    if matched_rule == skip_rule:
        unless = list(skip_cfg.get("unless_predicates_any") or [])
        for name in unless:
            if eval_predicate(item, name, pack):
                return False, None
    return True, matched_rule


def eval_predicate(item: dict[str, Any], name: str, pack: ConditionPack) -> bool:
    custom = pack.predicates.get(name)
    if custom is not None:
        return eval_condition(item, custom, pack)
    return False


def eval_condition(item: dict[str, Any], cond: dict[str, Any], pack: ConditionPack) -> bool:
    """Evaluate declarative predicates, including shared command write semantics.

    Policy must not restore path-only persistence false positives removed by
    detection. The explicit condition type keeps custom policy intent visible.
    """
    if not cond:
        return True
    text = command_text(item)
    lower = text.lower()

    if cond.get("type") == "guardrail_matched":
        ok, _ = _eval_guardrail_matched(item, cond, pack)
        return ok
    if cond.get("type") == "shell_exe":
        from exec_rules import is_shell_exe

        return bool(is_shell_exe(item))
    if cond.get("type") == "persistence_write":
        from command_semantics import rule_semantics_match

        return rule_semantics_match("persistence_modify", item.get("command"))

    if "all" in cond:
        return all(eval_condition(item, sub, pack) for sub in cond["all"])
    if "any" in cond:
        return any(eval_condition(item, sub, pack) for sub in cond["any"])
    if "not" in cond:
        return not eval_condition(item, cond["not"], pack)

    if "risk_module" in cond:
        mod = cond["risk_module"]
        current = str(item.get("risk_module") or "")
        if isinstance(mod, list):
            return current in mod
        return current == mod

    if "matched_rules_any" in cond:
        rules = matched_rules(item)
        return bool(rules & set(cond["matched_rules_any"]))
    if "matched_rules_all" in cond:
        rules = matched_rules(item)
        needed = set(cond["matched_rules_all"])
        return needed.issubset(rules)

    if "command_regex" in cond:
        pattern = str(cond["command_regex"])
        flags = re.I if "i" in str(cond.get("flags") or "i").lower() else 0
        return bool(re.search(pattern, text, flags))

    if "command_contains" in cond:
        return str(cond["command_contains"]).lower() in lower

    if "event_type" in cond:
        current = str(item.get("event_type") or "")
        et = cond["event_type"]
        if isinstance(et, list):
            return current in et
        return current == et

    if "event_type_in" in cond:
        current = str(item.get("event_type") or "")
        return current in {str(x) for x in (cond.get("event_type_in") or [])}

    if "field_equals" in cond:
        spec = cond["field_equals"]
        field_name = str(spec.get("field") or "")
        expected = spec.get("value")
        actual = _field_value(item, field_name)
        if isinstance(expected, list):
            return actual in expected
        return actual == expected

    if "field_regex" in cond:
        spec = cond["field_regex"]
        field_name = str(spec.get("field") or "command_text")
        pattern = str(spec.get("pattern") or "")
        flags = re.I if "i" in str(spec.get("flags") or "i").lower() else 0
        value = str(_field_value(item, field_name) or "")
        return bool(re.search(pattern, value, flags))

    if "predicate" in cond:
        return eval_predicate(item, str(cond["predicate"]), pack)

    if "listener_port_in" in cond:
        port = listener_port_value(item, str(cond.get("port_field") or "listener_port"))
        return port is not None and port in set(cond["listener_port_in"])

    if "dst_port_in" in cond:
        port = listener_port_value(item, "dst_port")
        return port is not None and port in set(cond["dst_port_in"])

    if "dst_ip_in" in cond:
        return str(item.get("dst_ip") or "") in set(cond["dst_ip_in"])

    if "severity_in" in cond:
        return str(item.get("severity") or "") in set(cond["severity_in"])

    if cond.get("web_listener_process"):
        from exec_rules import WEB_LISTENERS

        proc = str(item.get("listener_process") or "").lower()
        return bool(proc) and any(w in proc for w in WEB_LISTENERS)

    if "rule_id" in cond:
        return str(item.get("rule_id") or "") == str(cond["rule_id"])

    if "rule_id_in" in cond:
        return str(item.get("rule_id") or "") in {str(x) for x in (cond.get("rule_id_in") or [])}

    if "risk_level_in" in cond:
        levels = set()
        for key in ("risk_level", "severity"):
            value = str(item.get(key) or "").lower()
            if value:
                levels.add(value)
        needed = {str(x).lower() for x in (cond.get("risk_level_in") or [])}
        return bool(levels.intersection(needed))

    if "program_in" in cond:
        return str(item.get("program") or "") in {str(x) for x in (cond.get("program_in") or [])}

    if "tags_contains" in cond:
        tags = item.get("tags") or []
        if isinstance(tags, str):
            tag_set = {tags.lower()}
        else:
            tag_set = {str(t).lower() for t in tags}
        needed = {str(x).lower() for x in (cond.get("tags_contains") or [])}
        return bool(tag_set.intersection(needed))

    if "user" in cond:
        return str(item.get("user") or "") == str(cond["user"])

    if "message_regex" in cond:
        pattern = str(cond["message_regex"])
        flags = re.I if "i" in str(cond.get("flags") or "i").lower() else 0
        blob = " ".join(
            str(item.get(k) or "")
            for k in ("command", "message", "rule_name")
        )
        return bool(re.search(pattern, blob, flags))

    return False


def eval_flat_when(
    when: dict[str, Any],
    *,
    item: dict[str, Any],
    ctx: EvalContext,
    pack: ConditionPack,
) -> bool:
    """Evaluate legacy flat when maps plus when_extensions plugin entries."""
    for key, expected in when.items():
        handler = pack.when_handlers.get(key)
        if handler is not None:
            if not handler(ctx, expected):
                return False
            continue
        extension = pack.when_extensions.get(key)
        if extension is not None:
            merged = dict(item)
            for ctx_key, ctx_val in ctx.items():
                if ctx_key in ("ev", "_matched", "_best"):
                    continue
                merged.setdefault(ctx_key, ctx_val)
            if not eval_condition(merged, extension, pack):
                return False
            continue
        raise ValueError(f"Unknown when condition: {key}")
    return True


def condition_pack_from_config(config: dict[str, Any]) -> ConditionPack:
    raw_pred = config.get("predicates") or {}
    raw_ext = config.get("when_extensions") or {}
    return ConditionPack(
        predicates={str(k): v for k, v in raw_pred.items() if isinstance(v, dict)},
        when_extensions={str(k): v for k, v in raw_ext.items() if isinstance(v, dict)},
    )
