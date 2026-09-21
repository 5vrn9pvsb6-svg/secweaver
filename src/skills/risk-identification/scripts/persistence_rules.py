"""Host persistence risk rules — loaded from rules/persistence-rules.json."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from detection_rule_chain import RuleChainEngine
from exec_rules import SEVERITY_RANK
from rule_loader import load_rule_pack, rule_file
from time_utils import in_time_window

DEFAULT_PERSISTENCE_RULES_PATH = rule_file("persistence-rules.json")

_engine: PersistenceRulesEngine | None = None


def default_persistence_rules_path() -> Path:
    return rule_file("persistence-rules.json")


class PersistenceRulesEngine:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self._chain = RuleChainEngine(config, when_mode="flat_clauses")

    @classmethod
    def from_path(cls, path: Path | None = None) -> PersistenceRulesEngine:
        return cls(load_rule_pack(path, default_name="persistence-rules.json"))

    @property
    def risk_tags(self) -> dict[str, Any]:
        return self._chain.risk_tags

    def event_host(self, ev: dict[str, Any]) -> str:
        generic = {"localhost", "localhost.localdomain", "null", "unknown"}
        for key in ("_victim_host", "host", "host_ip", "log_source", "__source__", "host_name"):
            value = ev.get(key)
            if value not in (None, "", "null") and str(value).lower() not in generic:
                return str(value)
        return ""

    def event_timestamp(self, ev: dict[str, Any]) -> str | None:
        for key in ("timestamp", "time", "__time__", "mod_time"):
            value = ev.get(key)
            if value not in (None, "", "null"):
                return str(value)
        return None

    def event_text(self, ev: dict[str, Any]) -> str:
        parts: list[str] = []
        for key in ("action", "persistence_type", "path", "process", "exe", "command", "message"):
            value = ev.get(key)
            if isinstance(value, list):
                parts.append(" ".join(str(x) for x in value))
            elif value not in (None, ""):
                parts.append(str(value))
        return " ".join(parts).strip()

    def match_event(self, ev: dict[str, Any]) -> tuple[str, list[str], list[str]]:
        severity, matched, tags = self._chain.match_rules(ev)
        if matched:
            tags = self._chain.output.tags_for(matched)
        return severity, matched, tags

    def verdict_for(self, severity: str, matched: list[str]) -> str:
        return self._chain.output.verdict_for(severity, matched, default_p3="log_only")

    def action_for(self, severity: str) -> str:
        return self._chain.output.action_for(severity)

    def confidence_for(self, severity: str, matched: list[str], ceiling: float) -> float:
        def adjust(base: float, _sev: str, rules: list[str], _chain: bool) -> float:
            if len(rules) >= 2:
                return min(0.96, base + 0.05)
            return base

        return self._chain.output.confidence_for(severity, matched, ceiling, adjust=adjust)

    def build_summary(self, ev: dict[str, Any], severity: str, matched: list[str]) -> str:
        host = self.event_host(ev) or "?"
        action = ev.get("action") or "changed"
        ptype = ev.get("persistence_type") or ev.get("category") or "persistence"
        path = ev.get("path") or "?"
        actor = ev.get("auid_name") or ev.get("user") or ev.get("uid")
        process = ev.get("process") or ev.get("comm") or ev.get("exe")
        rule_name = matched[0] if matched else "persistence_generic_change"
        actor_text = f" actor={actor}" if actor else ""
        proc_text = f" process={process}" if process else ""
        return f"{host} {ptype} {action}: {path} ({severity}/{rule_name}){actor_text}{proc_text}"


def get_persistence_rules_engine(path: Path | str | None = None) -> PersistenceRulesEngine:
    global _engine
    if path is not None:
        return PersistenceRulesEngine.from_path(Path(path))
    if _engine is None:
        _engine = PersistenceRulesEngine.from_path(default_persistence_rules_path())
    return _engine


def configure_persistence_rules(path: Path | str | None = None) -> PersistenceRulesEngine:
    global _engine
    if path is None:
        _engine = PersistenceRulesEngine.from_path(default_persistence_rules_path())
    else:
        _engine = PersistenceRulesEngine.from_path(Path(path))
    return _engine


def filter_persistence_events(events: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    engine = get_persistence_rules_engine()
    expected_hosts = {
        str(value)
        for value in (params.get("host"), params.get("host_ip"), params.get("host_name"))
        if value not in (None, "")
    }
    expected_hosts.update(str(h) for h in (params.get("hosts") or []))

    out: list[dict[str, Any]] = []
    for ev in events:
        host = engine.event_host(ev)
        if expected_hosts and host and host not in expected_hosts:
            continue
        if not in_time_window(engine.event_timestamp(ev), params.get("time_start"), params.get("time_end")):
            continue
        if not ev.get("path"):
            continue
        out.append(ev)
    return out


def assess_persistence_events(
    events: list[dict[str, Any]],
    *,
    ceiling: float,
    severity_floor: str,
    warnings: list[str],
) -> list[dict[str, Any]]:
    engine = get_persistence_rules_engine()
    items: list[dict[str, Any]] = []
    for i, ev in enumerate(events):
        severity, matched, tags = engine.match_event(ev)
        if SEVERITY_RANK.get(severity, 9) > SEVERITY_RANK.get(severity_floor, 9):
            continue
        if not matched:
            continue
        host = engine.event_host(ev)
        ts = engine.event_timestamp(ev)
        items.append(
            {
                "risk_id": f"risk-persistence-{ev.get('audit_id') or ev.get('evidence_id') or i}",
                "risk_module": "persistence",
                "alert_type": "host_persistence_change",
                "severity": severity,
                "confidence": engine.confidence_for(severity, matched, ceiling),
                "verdict": engine.verdict_for(severity, matched),
                "host": host,
                "timestamp": ts,
                "event_type": ev.get("event_type"),
                "action": ev.get("action"),
                "persistence_type": ev.get("persistence_type"),
                "path": ev.get("path"),
                "user": ev.get("user"),
                "uid": ev.get("uid"),
                "auid": ev.get("auid"),
                "auid_name": ev.get("auid_name"),
                "pid": ev.get("pid"),
                "ppid": ev.get("ppid"),
                "process": ev.get("process") or ev.get("comm"),
                "exe": ev.get("exe"),
                "command": ev.get("command"),
                "matched_rules": matched,
                "risk_tags": tags,
                "recommended_action": engine.action_for(severity),
                "summary": engine.build_summary(ev, severity, matched),
                "evidence_refs": [ev.get("evidence_id")] if ev.get("evidence_id") else [],
            }
        )
    return items


_engine = PersistenceRulesEngine.from_path(default_persistence_rules_path())
