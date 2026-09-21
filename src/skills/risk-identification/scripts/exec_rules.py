"""Exec event risk rules — patterns loaded from rules/exec-rules.json (ops-editable)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from rule_loader import (
    VALID_EXEC_MATCH_FIELDS,
    compile_field_pattern_entries,
    compile_flags,
    load_rule_pack,
    normalize_keyword_entries,
    rule_file,
)
from detection_output import DetectionOutput
from command_semantics import command_argv, rule_semantics_match

DEFAULT_EXEC_RULES_PATH = rule_file("exec-rules.json")

_engine: ExecRulesEngine | None = None


def default_exec_rules_path() -> Path:
    return rule_file("exec-rules.json")


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class ExecRulesEngine:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.web_listeners = frozenset(config.get("web_listeners") or [])
        self.shell_names = frozenset(str(x).lower() for x in (config.get("shell_names") or []))
        self.shell_exe_prefixes = tuple(config.get("shell_exe_prefixes") or ())
        self.severity_rank = dict(config.get("severity_rank") or {"P0": 0, "P1": 1, "P2": 2, "P3": 3})
        self._output = DetectionOutput(config)
        self.p0_regex = compile_field_pattern_entries(config.get("p0_regex") or [])
        self.p1_regex = compile_field_pattern_entries(config.get("p1_regex") or [])
        self.p1_keywords = normalize_keyword_entries(config.get("p1_keywords") or [], default_id="keyword_match")
        self.p1_keyword_regex = compile_field_pattern_entries(config.get("p1_keyword_regex") or [])
        self.p3_keywords = normalize_keyword_entries(config.get("p3_keywords") or [])
        listener_ctx = config.get("listener_context") or {}
        self.empty_process_is_web = bool(listener_ctx.get("empty_process_is_web", True))
        fallback = config.get("fallback") or {}
        self.fallback_field = str(fallback.get("field") or "command")
        self.fallback_plain = tuple(fallback.get("plain_commands") or ())
        self.fallback_default_severity = str(fallback.get("default_severity") or "P2")
        self.fallback_elevations = list(fallback.get("elevations") or [])
        boost = config.get("context_boost") or {}
        self.boost_web_ports = {
            port
            for port in (_int_or_none(value) for value in (boost.get("web_ports") or []))
            if port is not None
        }
        self.boost_cwd = tuple(boost.get("suspicious_cwd_contains") or ())
        self.boost_text_field = str(boost.get("text_field") or "command")
        self.boost_text = tuple(boost.get("suspicious_text_contains") or ())
        structural = config.get("structural_rules") or {}
        self.shell_exec_rule = structural.get("external_listener_shell_exec") or {}

    @classmethod
    def from_path(cls, path: Path | None = None) -> ExecRulesEngine:
        return cls(load_rule_pack(path, default_name="exec-rules.json"))

    @property
    def risk_tags(self) -> dict[str, Any]:
        return self._output.risk_tags

    @property
    def verdicts(self) -> dict[str, Any]:
        return self._output.verdicts

    @property
    def actions(self) -> dict[str, Any]:
        return self._output.actions

    @property
    def confidence_base(self) -> dict[str, Any]:
        return self._output.confidence_base

    def cmd_text(self, ev: dict[str, Any]) -> str:
        return self.field_text(ev, "command")

    def field_text(self, ev: dict[str, Any], field: str) -> str:
        """Render command argv consistently, including SLS JSON-encoded arrays."""
        if field not in VALID_EXEC_MATCH_FIELDS:
            field = "command"
        if field == "command":
            cmd = ev.get("command")
            text = " ".join(command_argv(cmd)) if isinstance(cmd, list) or str(cmd or "").lstrip().startswith("[") else str(cmd or "").strip()
            if text:
                return text
            return str(ev.get("comm") or "")
        if field == "command_line":
            raw = ev.get("command_line")
            if raw not in (None, ""):
                return str(raw)
            return self.cmd_text(ev)
        value = ev.get(field)
        if isinstance(value, list):
            return " ".join(str(c) for c in value)
        return str(value or "")

    def is_shell_exe(self, ev: dict[str, Any]) -> bool:
        exe = str(ev.get("exe") or "")
        comm = str(ev.get("comm") or "").lower()
        if comm in self.shell_names:
            return True
        return any(exe.startswith(p) for p in self.shell_exe_prefixes)

    def is_web_listener(self, ev: dict[str, Any]) -> bool:
        proc = str(ev.get("listener_process") or "").lower()
        if not proc:
            return self.empty_process_is_web
        return any(w in proc for w in self.web_listeners)

    def context_boost(
        self,
        severity: str,
        ev: dict[str, Any],
        has_connect: bool,
        has_file_op: bool,
    ) -> str:
        port = _int_or_none(ev.get("listener_port"))
        cwd = str(ev.get("cwd") or "")
        text = self.field_text(ev, self.boost_text_field)
        rank = self.severity_rank.get(severity, 9)

        if port in self.boost_web_ports and rank > self.severity_rank["P0"]:
            rank -= 1
        lp = ev.get("listener_pid")
        ppid = ev.get("ppid")
        if lp is not None and str(ppid) == str(lp) and rank > self.severity_rank["P1"]:
            rank -= 1
        if any(p in cwd for p in self.boost_cwd) and rank > self.severity_rank["P1"]:
            rank -= 1
        if any(x in text for x in self.boost_text) and rank > self.severity_rank["P1"]:
            rank -= 1
        if (has_connect or has_file_op) and rank > self.severity_rank["P0"]:
            rank -= 1

        for sev, value in self.severity_rank.items():
            if value == max(0, rank):
                return sev
        return severity

    def match_exec_rules(
        self,
        ev: dict[str, Any],
        *,
        has_connect: bool = False,
        has_file_op: bool = False,
    ) -> tuple[str, list[str], list[str]]:
        """Match candidates, then validate built-in command semantics before severity.

        Explicit non-command field rules keep their configured matching contract.
        Semantic exclusions do not suppress other structural or command rules.
        """
        matched: list[str] = []
        best = "P3"

        shell_rule = self.shell_exec_rule
        if shell_rule.get("enabled", True):
            if (
                (not shell_rule.get("requires_web_listener", True) or self.is_web_listener(ev))
                and (not shell_rule.get("requires_shell_exe", True) or self.is_shell_exe(ev))
            ):
                matched.append("external_listener_shell_exec")
                best = str(shell_rule.get("severity") or "P0")

        for rule_id, field, pat in self.p0_regex:
            if pat.search(self.field_text(ev, field)) and (field != "command" or rule_semantics_match(rule_id, ev.get("command"))):
                matched.append(rule_id)
                best = "P0"

        for rule_id, field, pat in self.p1_regex:
            if pat.search(self.field_text(ev, field)):
                if rule_id not in matched:
                    matched.append(rule_id)
                if self.severity_rank.get(best, 9) > self.severity_rank["P1"]:
                    best = "P1"

        for rule_id, field, keyword in self.p1_keywords:
            haystack = self.field_text(ev, field).lower()
            if keyword and keyword.lower() in haystack and rule_id not in matched and (field != "command" or rule_semantics_match(rule_id, ev.get("command"))):
                matched.append(rule_id)
                if self.severity_rank.get(best, 9) > self.severity_rank["P1"]:
                    best = "P1"

        for rule_id, field, pat in self.p1_keyword_regex:
            if rule_id in matched:
                continue
            haystack = self.field_text(ev, field).lower()
            if pat.search(haystack):
                matched.append(rule_id)
                if self.severity_rank.get(best, 9) > self.severity_rank["P1"]:
                    best = "P1"

        if not matched and self.fallback_plain:
            fallback_text = self.field_text(ev, self.fallback_field).lower()
            if any(re.search(rf"\b{p}\b", fallback_text) for p in self.fallback_plain):
                best = self.fallback_default_severity
                for elevation in self.fallback_elevations:
                    if elevation.get("enabled") is False:
                        continue
                    rule_id = str(elevation.get("id") or "")
                    severity = str(elevation.get("severity") or "P1")
                    field = str(elevation.get("field") or self.fallback_field)
                    pattern = elevation.get("pattern")
                    keyword = elevation.get("keyword")
                    haystack = self.field_text(ev, field)
                    if pattern and re.search(
                        str(pattern), haystack, compile_flags(str(elevation.get("flags") or "i"))
                    ):
                        best = severity
                        if rule_id:
                            matched.append(rule_id)
                        break
                    if keyword and str(keyword).lower() in haystack.lower():
                        if elevation.get("requires_web_listener") and not self.is_web_listener(ev):
                            continue
                        best = severity
                        if rule_id:
                            matched.append(rule_id)
                        break

        if best == "P3" and self.p3_keywords:
            for rule_id, field, kw in self.p3_keywords:
                if kw.lower() in self.field_text(ev, field).lower() and not matched:
                    matched.append(rule_id)
                    break

        best = self.context_boost(best, ev, has_connect, has_file_op)

        tags = self._output.tags_for(matched)
        if self.is_web_listener(ev) and "web_process_abuse" not in tags and best in ("P0", "P1", "P2"):
            tags.append("web_process_abuse")

        return best, matched, tags

    def verdict_for(self, severity: str, matched: list[str]) -> str:
        if severity == "P2":
            if not matched:
                return "likely_false_positive"
            return self._output.verdicts.get("P2", "suspicious")
        if matched and "noise_command" in matched:
            return "benign"
        return self._output.verdict_for(severity, matched, default_p3="log_only")

    def action_for(self, severity: str) -> str:
        return self._output.action_for(severity)

    def confidence_for(
        self,
        severity: str,
        matched: list[str],
        ceiling: float,
        in_chain: bool,
    ) -> float:
        def adjust(base: float, sev: str, rules: list[str], chain: bool) -> float:
            if sev == "P0":
                if len(rules) >= 2:
                    base = float(self._output.confidence_base.get("P0_multi_match", 0.88))
                else:
                    base = float(self._output.confidence_base.get("P0", 0.85))
            if chain:
                base = min(0.98, base + 0.08)
            if len(rules) >= 2 and sev == "P0":
                base = min(0.96, base + 0.05)
            return base

        return self._output.confidence_for(
            severity,
            matched,
            ceiling,
            in_chain=in_chain,
            adjust=adjust,
        )

    def build_exec_summary(self, ev: dict[str, Any], severity: str, matched: list[str]) -> str:
        port = ev.get("listener_port", "?")
        proc = ev.get("listener_process", "web")
        host = ev.get("host", "?")
        text = self.cmd_text(ev)
        snippet = text[:80] + ("…" if len(text) > 80 else "")
        if "download_and_execute" in matched:
            return f"{host} {port}/{proc} 子进程下载并执行远程内容: {snippet}"
        if "reverse_shell" in matched:
            return f"{host} {port}/{proc} 子进程疑似反弹 shell: {snippet}"
        if "external_listener_shell_exec" in matched:
            return f"{host} {port}/{proc} 对外监听进程子进程执行 shell/解释器: {snippet}"
        return f"{host} {port}/{proc} 执行可疑命令 ({severity}): {snippet}"


def get_exec_rules_engine(path: Path | str | None = None) -> ExecRulesEngine:
    global _engine
    if path is not None:
        return ExecRulesEngine.from_path(Path(path))
    if _engine is None:
        _engine = ExecRulesEngine.from_path(default_exec_rules_path())
    return _engine


def configure_exec_rules(path: Path | str | None = None) -> ExecRulesEngine:
    """Load or reload exec rules from JSON (assess payload / tests)."""
    global _engine
    if path is None:
        _engine = ExecRulesEngine.from_path(default_exec_rules_path())
    else:
        _engine = ExecRulesEngine.from_path(Path(path))
    _sync_module_exports(_engine)
    return _engine


def _sync_module_exports(engine: ExecRulesEngine) -> None:
    global WEB_LISTENERS, SHELL_NAMES, SEVERITY_RANK, RISK_TAGS
    WEB_LISTENERS = engine.web_listeners
    SHELL_NAMES = engine.shell_names
    SEVERITY_RANK = engine.severity_rank
    RISK_TAGS = engine.risk_tags


def cmd_text(ev: dict[str, Any]) -> str:
    return get_exec_rules_engine().cmd_text(ev)


def field_text(ev: dict[str, Any], field: str) -> str:
    return get_exec_rules_engine().field_text(ev, field)


def is_shell_exe(ev: dict[str, Any]) -> bool:
    return get_exec_rules_engine().is_shell_exe(ev)


def is_web_listener(ev: dict[str, Any]) -> bool:
    return get_exec_rules_engine().is_web_listener(ev)


def required_fields_ok(ev: dict[str, Any]) -> tuple[bool, list[str]]:
    missing = []
    for key in ("host", "timestamp", "command"):
        val = ev.get(key)
        if val in (None, ""):
            missing.append(key)
    if not ev.get("listener_port") and not ev.get("listener_process"):
        missing.append("listener_port|listener_process")
    return not missing, missing


def context_boost(severity: str, ev: dict[str, Any], has_connect: bool, has_file_op: bool) -> str:
    return get_exec_rules_engine().context_boost(severity, ev, has_connect, has_file_op)


def match_exec_rules(
    ev: dict[str, Any],
    *,
    has_connect: bool = False,
    has_file_op: bool = False,
) -> tuple[str, list[str], list[str]]:
    return get_exec_rules_engine().match_exec_rules(ev, has_connect=has_connect, has_file_op=has_file_op)


def verdict_for(severity: str, matched: list[str]) -> str:
    return get_exec_rules_engine().verdict_for(severity, matched)


def action_for(severity: str) -> str:
    return get_exec_rules_engine().action_for(severity)


def confidence_for(severity: str, matched: list[str], ceiling: float, in_chain: bool) -> float:
    return get_exec_rules_engine().confidence_for(severity, matched, ceiling, in_chain)


def build_exec_summary(ev: dict[str, Any], severity: str, matched: list[str]) -> str:
    return get_exec_rules_engine().build_exec_summary(ev, severity, matched)


# Initialize on import
_engine = ExecRulesEngine.from_path(default_exec_rules_path())
WEB_LISTENERS = _engine.web_listeners
SHELL_NAMES = _engine.shell_names
SEVERITY_RANK = _engine.severity_rank
RISK_TAGS = _engine.risk_tags
