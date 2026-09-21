"""Ordered rules[] detection engine shared by connect and syslog modules."""

from __future__ import annotations

import re
from typing import Any, Literal

from detection_output import DetectionOutput
from rule_loader import compile_flags, entry_enabled
from shared_conditions import (
    ConditionPack,
    condition_pack_from_config,
    eval_condition,
    eval_flat_when,
)

WhenMode = Literal["flat_handlers", "flat_clauses"]


class RuleChainEngine:
    """Evaluate config.rules[] sequentially; tighten severity on each hit."""

    def __init__(
        self,
        config: dict[str, Any],
        *,
        when_mode: WhenMode = "flat_clauses",
        when_handlers: dict[str, Any] | None = None,
    ) -> None:
        self.config = config
        self.severity_rank = dict(config.get("severity_rank") or {"P0": 0, "P1": 1, "P2": 2, "P3": 3})
        self.rules = list(config.get("rules") or [])
        self.output = DetectionOutput(config)
        self.when_mode = when_mode
        self._when_handlers = dict(when_handlers or {})
        self._cond_pack = condition_pack_from_config(config)

    @property
    def risk_tags(self) -> dict[str, Any]:
        return self.output.risk_tags

    @property
    def verdicts(self) -> dict[str, Any]:
        return self.output.verdicts

    @property
    def actions(self) -> dict[str, Any]:
        return self.output.actions

    @property
    def confidence_base(self) -> dict[str, Any]:
        return self.output.confidence_base

    def severity_worse_than(self, current: str, threshold: str) -> bool:
        return self.severity_rank.get(current, 9) > self.severity_rank.get(threshold, 0)

    def apply_rule(
        self,
        rule: dict[str, Any],
        *,
        matched: list[str],
        best: str,
    ) -> str:
        rule_id = str(rule["id"])
        severity = str(rule["severity"])
        if rule_id not in matched:
            matched.append(rule_id)
        keep_if = rule.get("keep_severity_if")
        if keep_if and best == keep_if:
            return best
        if self.severity_rank.get(severity, 9) < self.severity_rank.get(best, 9):
            return severity
        return best

    def when_matches(
        self,
        when: dict[str, Any],
        ev: dict[str, Any],
        ctx: dict[str, Any],
        matched: list[str],
        best: str,
    ) -> bool:
        if self.when_mode == "flat_handlers":
            pack = self._bind_when_handlers()
            eval_ctx = dict(ctx)
            eval_ctx["_matched"] = matched
            eval_ctx["_best"] = best
            item = eval_ctx.get("ev") or ev
            return eval_flat_when(when, item=item, ctx=eval_ctx, pack=pack)
        return self._when_matches_flat_clauses(when, ev)

    def _bind_when_handlers(self) -> ConditionPack:
        pack = ConditionPack(
            predicates=dict(self._cond_pack.predicates),
            when_handlers=dict(self._when_handlers),
            when_extensions=dict(self._cond_pack.when_extensions),
        )
        return pack

    def _when_matches_flat_clauses(self, when: dict[str, Any], ev: dict[str, Any]) -> bool:
        if not when:
            return True
        clauses: list[dict[str, Any]] = []
        for key, expected in when.items():
            if key in self._cond_pack.when_extensions:
                clauses.append(self._cond_pack.when_extensions[key])
            else:
                clauses.append({key: expected})
        if len(clauses) == 1:
            return eval_condition(ev, clauses[0], self._cond_pack)
        return eval_condition(ev, {"all": clauses}, self._cond_pack)

    def match_rules(
        self,
        ev: dict[str, Any],
        ctx: dict[str, Any] | None = None,
    ) -> tuple[str, list[str], list[str]]:
        eval_ctx = ctx if ctx is not None else {"ev": ev}
        matched: list[str] = []
        best = "P3"
        for rule in self.rules:
            if not entry_enabled(rule):
                continue
            when = rule.get("when") or {}
            if self.when_matches(when, ev, eval_ctx, matched, best):
                best = self.apply_rule(rule, matched=matched, best=best)
        return best, matched, self.output.tags_for(matched)

    def match_message_rules(
        self,
        *,
        text: str,
        event_type: str,
        message_rules: list[dict[str, Any]],
        matched: list[str],
        best: str,
    ) -> str:
        lower = text.lower()
        for entry in message_rules:
            if not entry_enabled(entry):
                continue
            allowed = entry.get("event_types") or []
            if allowed and event_type not in {str(x) for x in allowed}:
                continue
            pattern = str(entry.get("pattern") or "")
            if not pattern:
                continue
            if re.search(pattern, lower, compile_flags(str(entry.get("flags") or "i"))):
                best = self.apply_rule(entry, matched=matched, best=best)
        return best
