"""Shared detection-layer output helpers (tags, verdict, action, confidence)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

ConfidenceAdjust = Callable[[float, str, list[str], bool], float]


class DetectionOutput:
    def __init__(self, config: dict[str, Any]) -> None:
        self.risk_tags = dict(config.get("risk_tags") or {})
        self.verdicts = dict(config.get("verdicts") or {})
        self.actions = dict(config.get("actions") or {})
        self.confidence_base = dict(config.get("confidence_base") or {})

    def tags_for(self, matched: list[str]) -> list[str]:
        tags: list[str] = []
        for rule_id in matched:
            for tag in self.risk_tags.get(rule_id, []):
                if tag not in tags:
                    tags.append(tag)
        return tags

    def verdict_for(
        self,
        severity: str,
        matched: list[str],
        *,
        matched_verdict: dict[str, str] | None = None,
        default_p3: str = "likely_false_positive",
    ) -> str:
        if matched_verdict:
            for rule_id, verdict_key in matched_verdict.items():
                if rule_id in matched:
                    return self.verdicts.get(verdict_key, default_p3)
        if severity == "P0":
            return self.verdicts.get("P0", "confirmed_attack")
        if severity == "P1":
            return self.verdicts.get("P1", "suspicious")
        if severity == "P2":
            return self.verdicts.get("P2", "suspicious")
        return self.verdicts.get("P3", default_p3)

    def action_for(self, severity: str, *, default: str = "observe") -> str:
        return self.actions.get(severity, default)

    def confidence_for(
        self,
        severity: str,
        matched: list[str],
        ceiling: float,
        *,
        in_chain: bool = False,
        adjust: ConfidenceAdjust | None = None,
    ) -> float:
        base = float(self.confidence_base.get(severity, 0.5))
        if adjust is not None:
            base = adjust(base, severity, matched, in_chain)
        return round(min(ceiling, base), 2)
