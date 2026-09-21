"""DNS query and DNS-privacy egress risk rules."""

from __future__ import annotations

import ipaddress
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from detection_output import DetectionOutput
from exec_rules import SEVERITY_RANK
from rule_loader import load_rule_pack, rule_file
from time_utils import in_time_window

DEFAULT_DNS_RULES_PATH = rule_file("dns-rules.json")

_engine: DnsRulesEngine | None = None


def default_dns_rules_path() -> Path:
    return rule_file("dns-rules.json")


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _is_private_ip(value: Any) -> bool:
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return False


def _first(ev: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = ev.get(key)
        if value not in (None, "", "null"):
            return str(value)
    return ""


def event_timestamp(ev: dict[str, Any]) -> str | None:
    for key in ("timestamp", "time", "ts"):
        value = ev.get(key)
        if value not in (None, "", "null"):
            return str(value)
    return None


def event_query(ev: dict[str, Any]) -> str:
    return _first(ev, ("query", "qname", "domain", "hostname")).rstrip(".").lower()


def event_client(ev: dict[str, Any]) -> str:
    return _first(ev, ("client_ip", "src_ip", "host_ip", "host"))


def event_ref(ev: dict[str, Any], seq: int) -> str:
    return str(ev.get("evidence_id") or ev.get("event_id") or ev.get("_ref") or f"dns-{seq}")


def _labels(domain: str) -> list[str]:
    return [label for label in domain.strip(".").split(".") if label]


def _tld(domain: str) -> str:
    labels = _labels(domain)
    return labels[-1].lower() if labels else ""


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {ch: text.count(ch) for ch in set(text)}
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class DnsRulesEngine:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.severity_rank = dict(config.get("severity_rank") or {"P0": 0, "P1": 1, "P2": 2, "P3": 3})
        self.rule_meta = {
            str(rule.get("id")): dict(rule)
            for rule in (config.get("rules") or [])
            if rule.get("enabled", True) is not False and rule.get("id")
        }
        self.nxdomain = dict(config.get("nxdomain_burst") or {})
        self.profile = dict(config.get("domain_profile") or {})
        self.doh_dot = dict(config.get("doh_dot") or {})
        self._output = DetectionOutput(config)

    @classmethod
    def from_path(cls, path: Path | None = None) -> DnsRulesEngine:
        return cls(load_rule_pack(path, default_name="dns-rules.json"))

    def severity_for_count(self, count: int) -> str:
        thresholds = [
            tier for tier in (self.nxdomain.get("thresholds") or []) if tier.get("enabled", True) is not False
        ]
        thresholds.sort(key=lambda item: int(item.get("min_count") or 0), reverse=True)
        for tier in thresholds:
            if count >= int(tier.get("min_count") or 0):
                return str(tier.get("severity") or "P2")
        return "P3"

    def severity_for_matched(self, matched: list[str]) -> str:
        best = "P3"
        for rule_id in matched:
            severity = str(self.rule_meta.get(rule_id, {}).get("severity") or "P3")
            if self.severity_rank.get(severity, 9) < self.severity_rank.get(best, 9):
                best = severity
        return best

    def is_nxdomain(self, ev: dict[str, Any]) -> bool:
        rcode = str(ev.get("rcode") or ev.get("response_code") or ev.get("status") or "").lower()
        return rcode in {"3", "nxdomain", "name_error", "no_such_domain"}

    def is_internal_domain(self, domain: str) -> bool:
        suffixes = [str(item).lower().strip(".") for item in (self.profile.get("internal_suffixes") or [])]
        return any(domain.endswith(f".{suffix}") or domain == suffix for suffix in suffixes)

    def is_uncommon_tld(self, domain: str) -> bool:
        tld = _tld(domain)
        if not tld or self.is_internal_domain(domain):
            return False
        uncommon = {str(item).lower().lstrip(".") for item in (self.profile.get("uncommon_tlds") or [])}
        return tld in uncommon

    def is_dga_like(self, domain: str) -> bool:
        if not domain or self.is_internal_domain(domain) or domain.endswith(".in-addr.arpa"):
            return False
        labels = _labels(domain)
        if not labels:
            return False
        candidate = max(labels[:-1] or labels, key=len)
        min_len = _int(self.profile.get("dga_min_label_length"), 16)
        min_entropy = _float(self.profile.get("dga_min_entropy"), 3.6)
        min_digit_ratio = _float(self.profile.get("dga_min_digit_ratio"), 0.25)
        digit_ratio = sum(1 for ch in candidate if ch.isdigit()) / max(len(candidate), 1)
        return len(candidate) >= min_len and (
            _entropy(candidate) >= min_entropy or digit_ratio >= min_digit_ratio
        )

    def is_tunnel_like(self, ev: dict[str, Any]) -> bool:
        domain = event_query(ev)
        labels = _labels(domain)
        longest = max((len(label) for label in labels), default=0)
        query_len = len(domain)
        qtype = str(ev.get("query_type") or ev.get("qtype") or "").upper()
        min_query = _int(self.profile.get("tunnel_min_query_length"), 90)
        min_label = _int(self.profile.get("tunnel_min_label_length"), 48)
        tunnel_qtypes = {str(item).upper() for item in (self.profile.get("tunnel_query_types") or [])}
        return query_len >= min_query or (longest >= min_label and (not tunnel_qtypes or qtype in tunnel_qtypes))

    def dns_privacy_match(self, ev: dict[str, Any]) -> str | None:
        port = _int(ev.get("dst_port") or ev.get("remote_port") or ev.get("target_port"))
        dst_ip = str(ev.get("dst_ip") or ev.get("remote_ip") or ev.get("target_ip") or "")
        dot_ports = {_int(item) for item in (self.doh_dot.get("dot_ports") or [])}
        doh_ports = {_int(item) for item in (self.doh_dot.get("doh_ports") or [])}
        doh_ips = {str(item) for item in (self.doh_dot.get("known_doh_resolver_ips") or [])}
        if port in dot_ports:
            return "dot_egress"
        if port in doh_ports and dst_ip in doh_ips:
            return "doh_egress"
        return None

    def verdict_for(self, severity: str, matched: list[str]) -> str:
        return self._output.verdict_for(severity, matched, default_p3="log_only")

    def action_for(self, severity: str) -> str:
        return self._output.action_for(severity)

    def confidence_for(self, severity: str, matched: list[str], ceiling: float, *, aggregate: bool = False) -> float:
        def adjust(base: float, _sev: str, rules: list[str], _chain: bool) -> float:
            if aggregate:
                base = min(0.94, base + _float(self.config.get("aggregate_bonus"), 0.05))
            if len(rules) >= 2:
                base = min(0.95, base + 0.04)
            return base

        return self._output.confidence_for(severity, matched, ceiling, adjust=adjust)

    def tags_for(self, matched: list[str]) -> list[str]:
        return self._output.tags_for(matched)

    def build_summary(self, ev: dict[str, Any], severity: str, matched: list[str]) -> str:
        host = event_client(ev) or ev.get("host") or ev.get("host_ip") or "?"
        query = event_query(ev) or ev.get("dst_ip") or "?"
        return f"{host} DNS profile matched {', '.join(matched)} on {query} ({severity})"


def get_dns_rules_engine(path: Path | str | None = None) -> DnsRulesEngine:
    global _engine
    if path is not None:
        return DnsRulesEngine.from_path(Path(path))
    if _engine is None:
        _engine = DnsRulesEngine.from_path(default_dns_rules_path())
    return _engine


def configure_dns_rules(path: Path | str | None = None) -> DnsRulesEngine:
    global _engine
    if path is None:
        _engine = DnsRulesEngine.from_path(default_dns_rules_path())
    else:
        _engine = DnsRulesEngine.from_path(Path(path))
    return _engine


def filter_dns_events(events: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    expected = {
        str(value)
        for value in (params.get("host"), params.get("host_ip"), params.get("target_ip"))
        if value not in (None, "")
    }
    expected.update(str(value) for value in (params.get("hosts") or []) if value not in (None, ""))
    out: list[dict[str, Any]] = []
    for ev in events:
        if not in_time_window(event_timestamp(ev), params.get("time_start"), params.get("time_end")):
            continue
        client = event_client(ev)
        if expected and client and client not in expected:
            continue
        if not event_query(ev):
            continue
        out.append(ev)
    return out


def _risk_id(module: str, host: str, marker: str) -> str:
    safe = "".join(ch if ch.isalnum() else "-" for ch in f"{host}-{marker}")[:80].strip("-")
    return f"risk-{module}-{safe or 'event'}"


def _make_item(
    *,
    engine: DnsRulesEngine,
    ev: dict[str, Any],
    seq: int,
    matched: list[str],
    severity: str,
    ceiling: float,
    aggregate: bool = False,
    evidence_refs: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    host = event_client(ev) or str(ev.get("host") or ev.get("host_ip") or "")
    query = event_query(ev)
    refs = evidence_refs or [event_ref(ev, seq)]
    item = {
        "risk_id": _risk_id("dns", host, refs[0] if refs else query),
        "risk_module": "dns",
        "alert_type": "dns_profile_anomaly",
        "severity": severity,
        "confidence": engine.confidence_for(severity, matched, ceiling, aggregate=aggregate),
        "verdict": engine.verdict_for(severity, matched),
        "host": host,
        "timestamp": event_timestamp(ev),
        "query": query,
        "domain": query,
        "query_type": ev.get("query_type") or ev.get("qtype"),
        "rcode": ev.get("rcode") or ev.get("response_code"),
        "matched_rules": matched,
        "risk_tags": engine.tags_for(matched),
        "recommended_action": engine.action_for(severity),
        "summary": engine.build_summary(ev, severity, matched),
        "evidence_refs": refs,
    }
    if _is_private_ip(host):
        item["client_scope"] = "internal"
    if extra:
        item.update(extra)
    return item


def assess_dns_events(
    events: list[dict[str, Any]],
    *,
    connect_events: list[dict[str, Any]],
    ceiling: float,
    severity_floor: str,
    warnings: list[str],
) -> list[dict[str, Any]]:
    engine = get_dns_rules_engine()
    items: list[dict[str, Any]] = []
    nxdomain_by_client: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for i, ev in enumerate(events):
        matched: list[str] = []
        query = event_query(ev)
        if engine.is_nxdomain(ev):
            nxdomain_by_client[event_client(ev) or "unknown"].append(ev)
        if engine.is_tunnel_like(ev):
            matched.append("dns_tunnel_suspected")
        if engine.is_dga_like(query):
            matched.append("suspected_dga_domain")
        if engine.is_uncommon_tld(query):
            matched.append("uncommon_tld_query")
        if not matched:
            continue
        severity = engine.severity_for_matched(matched)
        if SEVERITY_RANK.get(severity, 9) > SEVERITY_RANK.get(severity_floor, 9):
            continue
        items.append(
            _make_item(
                engine=engine,
                ev=ev,
                seq=i + 1,
                matched=matched,
                severity=severity,
                ceiling=ceiling,
            )
        )

    for client, group in nxdomain_by_client.items():
        severity = engine.severity_for_count(len(group))
        matched = ["high_nxdomain_burst"]
        if SEVERITY_RANK.get(severity, 9) > SEVERITY_RANK.get(severity_floor, 9):
            continue
        first = min(group, key=lambda ev: str(event_timestamp(ev) or ""))
        refs = [event_ref(ev, i + 1) for i, ev in enumerate(group[:20])]
        items.append(
            _make_item(
                engine=engine,
                ev={**first, "client_ip": client},
                seq=1,
                matched=matched,
                severity=severity,
                ceiling=ceiling,
                aggregate=True,
                evidence_refs=refs,
                extra={
                    "query_count": len(group),
                    "unique_queries": len({event_query(ev) for ev in group}),
                    "summary": f"{client} high NXDOMAIN burst: {len(group)} failed DNS queries ({severity})",
                },
            )
        )

    for i, ev in enumerate(connect_events):
        rule_id = engine.dns_privacy_match(ev)
        if not rule_id:
            continue
        matched = [rule_id]
        severity = engine.severity_for_matched(matched)
        if SEVERITY_RANK.get(severity, 9) > SEVERITY_RANK.get(severity_floor, 9):
            continue
        host = str(ev.get("host") or ev.get("host_ip") or "")
        dst = str(ev.get("dst_ip") or ev.get("remote_ip") or ev.get("target_ip") or "")
        port = ev.get("dst_port") or ev.get("remote_port") or ev.get("target_port")
        pseudo = {
            "timestamp": event_timestamp(ev),
            "client_ip": host,
            "query": dst,
            "evidence_id": ev.get("evidence_id") or ev.get("event_id") or f"connect-{i + 1}",
        }
        items.append(
            _make_item(
                engine=engine,
                ev=pseudo,
                seq=i + 1,
                matched=matched,
                severity=severity,
                ceiling=ceiling,
                extra={
                    "alert_type": "dns_privacy_egress",
                    "dst_ip": dst,
                    "dst_port": port,
                    "summary": f"{host} suspicious DNS privacy egress to {dst}:{port} ({rule_id}/{severity})",
                },
            )
        )

    return items


_engine = DnsRulesEngine.from_path(default_dns_rules_path())
