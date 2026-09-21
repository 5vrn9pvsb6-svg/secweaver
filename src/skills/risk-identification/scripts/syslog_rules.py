"""Syslog risk alert rules — loaded from rules/syslog-rules.json (ops-editable)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from detection_rule_chain import RuleChainEngine
from exec_rules import SEVERITY_RANK
from rule_loader import load_rule_pack, rule_file
from time_utils import in_time_window

DEFAULT_SYSLOG_RULES_PATH = rule_file("syslog-rules.json")

_engine: SyslogRulesEngine | None = None


def default_syslog_rules_path() -> Path:
    return rule_file("syslog-rules.json")


class SyslogRulesEngine:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.exclude_event_types = frozenset(config.get("exclude_event_types") or [])
        self.message_rules = list(config.get("message_rules") or [])
        self._chain = RuleChainEngine(config, when_mode="flat_clauses")

    @classmethod
    def from_path(cls, path: Path | None = None) -> SyslogRulesEngine:
        return cls(load_rule_pack(path, default_name="syslog-rules.json"))

    @property
    def risk_tags(self) -> dict[str, Any]:
        return self._chain.risk_tags

    def event_host(self, ev: dict[str, Any]) -> str:
        generic = {"localhost", "localhost.localdomain", "null"}
        for key in ("_victim_host", "host", "host_ip", "host_name"):
            value = ev.get(key)
            if value not in (None, "", "null") and str(value).lower() not in generic:
                return str(value)
        source = ev.get("__source__")
        if source not in (None, "", "null"):
            return str(source)
        return ""

    def event_timestamp(self, ev: dict[str, Any]) -> str | None:
        for key in ("timestamp", "time", "ts"):
            value = ev.get(key)
            if value not in (None, "", "null"):
                return str(value)
        return None

    def event_text(self, ev: dict[str, Any]) -> str:
        parts = [
            str(ev.get("command") or ""),
            str(ev.get("message") or ""),
            str(ev.get("rule_name") or ""),
        ]
        return " ".join(p for p in parts if p).strip()

    def is_excluded(self, ev: dict[str, Any]) -> bool:
        return str(ev.get("event_type") or "").lower() in self.exclude_event_types

    def match_event(self, ev: dict[str, Any]) -> tuple[str, list[str], list[str]]:
        best, matched, tags = self._chain.match_rules(ev)
        text = self.event_text(ev)
        event_type = str(ev.get("event_type") or "")
        best = self._chain.match_message_rules(
            text=text,
            event_type=event_type,
            message_rules=self.message_rules,
            matched=matched,
            best=best,
        )
        if best != "P3" or matched:
            tags = self._chain.output.tags_for(matched)
        return best, matched, tags

    def verdict_for(self, severity: str, matched: list[str]) -> str:
        return self._chain.output.verdict_for(severity, matched, default_p3="log_only")

    def action_for(self, severity: str) -> str:
        return self._chain.output.action_for(severity)

    def confidence_for(self, severity: str, matched: list[str], ceiling: float) -> float:
        def adjust(base: float, _sev: str, rules: list[str], _chain: bool) -> float:
            if len(rules) >= 2:
                return min(0.95, base + 0.05)
            return base

        return self._chain.output.confidence_for(severity, matched, ceiling, adjust=adjust)

    def build_summary(self, ev: dict[str, Any], severity: str, matched: list[str]) -> str:
        host = self.event_host(ev) or "?"
        event_type = ev.get("event_type") or "?"
        user = ev.get("user") or ""
        src_ip = ev.get("src_ip") or ""
        rule_name = ev.get("rule_name") or (matched[0] if matched else "")
        snippet = self.event_text(ev)[:120]
        if len(self.event_text(ev)) > 120:
            snippet += "…"
        who = f" user={user}" if user else ""
        src = f" from {src_ip}" if src_ip else ""
        return f"{host} syslog {event_type}{who}{src} ({severity}/{rule_name}): {snippet}"


def get_syslog_rules_engine(path: Path | str | None = None) -> SyslogRulesEngine:
    global _engine
    if path is not None:
        return SyslogRulesEngine.from_path(Path(path))
    if _engine is None:
        _engine = SyslogRulesEngine.from_path(default_syslog_rules_path())
    return _engine


def configure_syslog_rules(path: Path | str | None = None) -> SyslogRulesEngine:
    global _engine
    if path is None:
        _engine = SyslogRulesEngine.from_path(default_syslog_rules_path())
    else:
        _engine = SyslogRulesEngine.from_path(Path(path))
    return _engine


def filter_syslog_events(events: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    engine = get_syslog_rules_engine()
    expected_hosts = {
        str(value)
        for value in (params.get("host"), params.get("host_ip"), params.get("host_name"))
        if value not in (None, "")
    }
    expected_hosts.update(str(h) for h in (params.get("hosts") or []))

    out: list[dict[str, Any]] = []
    for ev in events:
        if engine.is_excluded(ev):
            continue
        host = engine.event_host(ev)
        if expected_hosts and host and host not in expected_hosts:
            continue
        if not in_time_window(engine.event_timestamp(ev), params.get("time_start"), params.get("time_end")):
            continue
        if not ev.get("event_type"):
            continue
        out.append(ev)
    return out


def assess_syslog_events(
    events: list[dict[str, Any]],
    *,
    ceiling: float,
    severity_floor: str,
    warnings: list[str],
) -> list[dict[str, Any]]:
    engine = get_syslog_rules_engine()
    items: list[dict[str, Any]] = []
    for i, ev in enumerate(events):
        severity, matched, tags = engine.match_event(ev)
        if SEVERITY_RANK.get(severity, 9) > SEVERITY_RANK.get(severity_floor, 9):
            continue
        if not matched:
            continue
        host = engine.event_host(ev)
        ts = engine.event_timestamp(ev)
        text = engine.event_text(ev)
        items.append(
            {
                "risk_id": f"risk-syslog-{ev.get('event_id') or i}",
                "risk_module": "syslog",
                "alert_type": "syslog_risk_alert",
                "severity": severity,
                "confidence": engine.confidence_for(severity, matched, ceiling),
                "verdict": engine.verdict_for(severity, matched),
                "host": host,
                "timestamp": ts,
                "event_type": ev.get("event_type"),
                "rule_id": ev.get("rule_id"),
                "rule_name": ev.get("rule_name"),
                "risk_level": ev.get("risk_level"),
                "user": ev.get("user"),
                "src_ip": ev.get("src_ip"),
                "program": ev.get("program"),
                "command": text,
                "matched_rules": matched,
                "risk_tags": tags,
                "recommended_action": engine.action_for(severity),
                "summary": engine.build_summary(ev, severity, matched),
                "evidence_refs": [ev.get("evidence_id")] if ev.get("evidence_id") else [],
            }
        )
    return items


_engine = SyslogRulesEngine.from_path(default_syslog_rules_path())
