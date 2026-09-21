"""Active connect event risk rules — loaded from rules/connect-rules.json."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from detection_rule_chain import RuleChainEngine
from rule_loader import compile_flags, load_rule_pack, rule_file

DEFAULT_CONNECT_RULES_PATH = rule_file("connect-rules.json")

_engine: ConnectRulesEngine | None = None


def default_connect_rules_path() -> Path:
    return rule_file("connect-rules.json")


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _int_set(values: list[Any]) -> frozenset[int]:
    return frozenset(port for port in (_int_or_none(value) for value in values) if port is not None)


class ConnectRulesEngine:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.web_ports = _int_set(config.get("web_ports") or [])
        self.web_listener_processes = frozenset(config.get("web_listener_processes") or [])
        self.private_nets = [
            ipaddress.ip_network(cidr) for cidr in (config.get("private_cidrs") or [])
        ]
        self.suspicious_ports = _int_set(config.get("suspicious_ports") or [])
        self.common_service_ports = _int_set(config.get("common_service_ports") or [])
        flags = compile_flags(str(config.get("exec_download_flags") or "i"))
        pattern = str(config.get("exec_download_pattern") or r"\b(curl|wget|fetch)\b")
        self.exec_download_re = re.compile(pattern, flags)
        self._chain = RuleChainEngine(
            config,
            when_mode="flat_handlers",
            when_handlers=self._connect_handlers(),
        )

    def _connect_handlers(self) -> dict[str, Any]:
        return {
            "web_context": lambda ctx, exp: bool(ctx["web_context"]) == bool(exp),
            "dst_private": lambda ctx, exp: bool(ctx["dst_private"]) == bool(exp),
            "dst_port_in": lambda ctx, exp: ctx["port"] in self._port_list(str(exp)),
            "exec_download_nearby": lambda ctx, exp: bool(ctx["exec_download_nearby"]) == bool(exp),
            "no_matched_rules": lambda ctx, exp: bool(not ctx.get("_matched")) == bool(exp),
            "severity_worse_than": lambda ctx, exp: self._chain.severity_worse_than(
                str(ctx.get("_best") or "P3"), str(exp)
            ),
        }

    @classmethod
    def from_path(cls, path: Path | None = None) -> ConnectRulesEngine:
        return cls(load_rule_pack(path, default_name="connect-rules.json"))

    @property
    def risk_tags(self) -> dict[str, Any]:
        return self._chain.risk_tags

    def is_private_ip(self, ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in self.private_nets)
        except ValueError:
            return False

    def is_web_listener_context(self, ev: dict[str, Any]) -> bool:
        listener_port = _int_or_none(ev.get("listener_port"))
        proc = str(ev.get("listener_process", "")).lower()
        if listener_port is not None and listener_port in self.web_ports:
            return True
        return any(p in proc for p in self.web_listener_processes)

    def has_exec_download_nearby(self, related_exec_texts: list[str]) -> bool:
        for text in related_exec_texts:
            if self.exec_download_re.search(text):
                return True
        return False

    def _port_list(self, name: str) -> frozenset[int]:
        if name == "suspicious_ports":
            return self.suspicious_ports
        if name == "common_service_ports":
            return self.common_service_ports
        return frozenset()

    def match_connect_rules(
        self,
        ev: dict[str, Any],
        *,
        related_exec_texts: list[str] | None = None,
    ) -> tuple[str, list[str], list[str]]:
        related_exec_texts = related_exec_texts or []
        dst = str(ev.get("dst_ip") or "")
        try:
            port = int(ev.get("dst_port") or 0)
        except (TypeError, ValueError):
            port = 0

        ctx = {
            "ev": ev,
            "web_context": self.is_web_listener_context(ev),
            "dst_private": self.is_private_ip(dst),
            "port": port,
            "exec_download_nearby": self.has_exec_download_nearby(related_exec_texts),
        }
        return self._chain.match_rules(ev, ctx)

    def verdict_for(self, severity: str, matched: list[str]) -> str:
        return self._chain.output.verdict_for(
            severity,
            matched,
            matched_verdict={"business_whitelist_connect": "business_whitelist"},
        )

    def action_for(self, severity: str) -> str:
        return self._chain.output.action_for(severity)

    def confidence_for(
        self,
        severity: str,
        matched: list[str],
        ceiling: float,
        in_chain: bool,
    ) -> float:
        def adjust(base: float, _sev: str, rules: list[str], chain: bool) -> float:
            if "exec_correlated_egress" in rules:
                base = min(
                    0.95,
                    base + float(self._chain.confidence_base.get("exec_correlated_bonus", 0.1)),
                )
            if chain:
                base = min(0.98, base + float(self._chain.confidence_base.get("chain_bonus", 0.06)))
            return base

        return self._chain.output.confidence_for(
            severity,
            matched,
            ceiling,
            in_chain=in_chain,
            adjust=adjust,
        )

    def build_connect_summary(self, ev: dict[str, Any], severity: str, matched: list[str]) -> str:
        host = ev.get("host", "?")
        dst = ev.get("dst_ip", "?")
        port = ev.get("dst_port", "?")
        lp = ev.get("listener_port", "?")
        if "external_c2_connect" in matched:
            return f"{host} 监听端口 {lp} 进程主动外连公网 {dst}:{port} ({severity})"
        return f"{host} 监听端口 {lp} 主动外连 {dst}:{port} ({severity})"


def get_connect_rules_engine(path: Path | str | None = None) -> ConnectRulesEngine:
    global _engine
    if path is not None:
        return ConnectRulesEngine.from_path(Path(path))
    if _engine is None:
        _engine = ConnectRulesEngine.from_path(default_connect_rules_path())
    return _engine


def configure_connect_rules(path: Path | str | None = None) -> ConnectRulesEngine:
    global _engine
    if path is None:
        _engine = ConnectRulesEngine.from_path(default_connect_rules_path())
    else:
        _engine = ConnectRulesEngine.from_path(Path(path))
    return _engine


def required_fields_ok(ev: dict[str, Any]) -> tuple[bool, list[str]]:
    missing = []
    for key in ("host", "timestamp", "dst_ip", "dst_port"):
        if ev.get(key) in (None, ""):
            missing.append(key)
    if not ev.get("listener_port") and not ev.get("listener_process"):
        missing.append("listener_port|listener_process")
    return not missing, missing


def match_connect_rules(
    ev: dict[str, Any],
    *,
    related_exec_texts: list[str] | None = None,
) -> tuple[str, list[str], list[str]]:
    return get_connect_rules_engine().match_connect_rules(ev, related_exec_texts=related_exec_texts)


def verdict_for(severity: str, matched: list[str]) -> str:
    return get_connect_rules_engine().verdict_for(severity, matched)


def action_for(severity: str) -> str:
    return get_connect_rules_engine().action_for(severity)


def confidence_for(severity: str, matched: list[str], ceiling: float, in_chain: bool) -> float:
    return get_connect_rules_engine().confidence_for(severity, matched, ceiling, in_chain)


def build_connect_summary(ev: dict[str, Any], severity: str, matched: list[str]) -> str:
    return get_connect_rules_engine().build_connect_summary(ev, severity, matched)


_engine = ConnectRulesEngine.from_path(default_connect_rules_path())
RISK_TAGS = _engine.risk_tags
