"""SSH auth / brute-force risk rules — loaded from rules/ssh-rules.json."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any

from time_utils import in_time_window, parse_ts
from detection_output import DetectionOutput
from exec_rules import SEVERITY_RANK
from rule_loader import compile_flags, load_rule_pack, rule_file

DEFAULT_SSH_RULES_PATH = rule_file("ssh-rules.json")

_engine: SshRulesEngine | None = None


def default_ssh_rules_path() -> Path:
    return rule_file("ssh-rules.json")


class SshRulesEngine:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        brute = config.get("brute_force") or {}
        self.default_window_sec = int(brute.get("window_sec") or 300)
        self.default_threshold = int(brute.get("threshold") or 10)
        self.suppress_self_loop = bool(brute.get("suppress_self_loop", True))
        self.confidence_cap = float(config.get("confidence_cap") or 0.92)
        self.default_severity = str(config.get("default_severity") or "P0")
        self.brute_force_rule = dict(config.get("brute_force_rule") or {})
        self.thresholds = list(config.get("thresholds") or [])
        self.fail_event_types = frozenset(config.get("fail_event_types") or [])
        self.success_event_types = frozenset(config.get("success_event_types") or [])
        self.fail_msg_re = re.compile(
            str(config.get("fail_message_pattern") or ""),
            compile_flags("i"),
        )
        self.success_msg_re = re.compile(
            str(config.get("success_message_pattern") or ""),
            compile_flags("i"),
        )
        self.src_ip_from_message_re = re.compile(
            str(config.get("src_ip_from_message_pattern") or ""),
            compile_flags("i"),
        )
        self.user_from_message_re = re.compile(
            str(config.get("user_from_message_pattern") or ""),
            compile_flags("i"),
        )
        self._output = DetectionOutput(config)

    @classmethod
    def from_path(cls, path: Path | None = None) -> SshRulesEngine:
        return cls(load_rule_pack(path, default_name="ssh-rules.json"))

    def verdict_for(self, severity: str, matched: list[str]) -> str:
        return self._output.verdict_for(severity, matched)

    def action_for(self, severity: str) -> str:
        return self._output.action_for(severity)

    def tags_for(self, matched: list[str]) -> list[str]:
        return self._output.tags_for(matched)

    def confidence_for_burst(self, severity: str, ceiling: float) -> float:
        base = float(self._output.confidence_base.get(severity, self.confidence_cap))
        return round(min(ceiling, base, self.confidence_cap), 2)

    def severity_for_count(self, count: int) -> str:
        active = [
            t for t in self.thresholds
            if t.get("enabled", True) is not False and t.get("min_count") is not None
        ]
        active.sort(key=lambda t: int(t["min_count"]), reverse=True)
        for tier in active:
            if count >= int(tier["min_count"]):
                return str(tier.get("severity") or self.default_severity)
        return self.default_severity


def get_ssh_rules_engine(path: Path | str | None = None) -> SshRulesEngine:
    global _engine
    if path is not None:
        return SshRulesEngine.from_path(Path(path))
    if _engine is None:
        _engine = SshRulesEngine.from_path(default_ssh_rules_path())
    return _engine


def configure_ssh_rules(path: Path | str | None = None) -> SshRulesEngine:
    global _engine
    if path is None:
        _engine = SshRulesEngine.from_path(default_ssh_rules_path())
    else:
        _engine = SshRulesEngine.from_path(Path(path))
    _sync_module_exports(_engine)
    return _engine


def _sync_module_exports(engine: SshRulesEngine) -> None:
    global FAIL_EVENT_TYPES, SUCCESS_EVENT_TYPES, DEFAULT_WINDOW_SEC, DEFAULT_FAIL_THRESHOLD
    global FAIL_MSG_RE, SUCCESS_MSG_RE
    FAIL_EVENT_TYPES = engine.fail_event_types
    SUCCESS_EVENT_TYPES = engine.success_event_types
    DEFAULT_WINDOW_SEC = engine.default_window_sec
    DEFAULT_FAIL_THRESHOLD = engine.default_threshold
    FAIL_MSG_RE = engine.fail_msg_re
    SUCCESS_MSG_RE = engine.success_msg_re


def event_timestamp(ev: dict[str, Any]) -> str | None:
    for key in ("timestamp", "time", "ts"):
        value = ev.get(key)
        if value not in (None, "", "null"):
            return str(value)
    return None


def normalize_ssh_event(ev: dict[str, Any], *, fallback_host: str | None = None) -> dict[str, Any] | None:
    engine = get_ssh_rules_engine()
    ts = event_timestamp(ev)
    if not ts:
        return None
    host = (
        ev.get("_victim_host")
        or ev.get("host")
        or ev.get("host_ip")
        or ev.get("host_name")
        or fallback_host
    )
    if host in (None, "", "null", "localhost", "null"):
        host = fallback_host
    src_ip = ev.get("src_ip")
    if src_ip in (None, "", "null"):
        msg = str(ev.get("message") or "")
        m = engine.src_ip_from_message_re.search(msg)
        if m:
            src_ip = m.group(1)
    user = ev.get("user")
    if user in (None, "", "null"):
        msg = str(ev.get("message") or "")
        m = engine.user_from_message_re.search(msg)
        if m:
            user = m.group(1)
    result = str(ev.get("result") or "").lower()
    event_type = str(ev.get("event_type") or "").lower()
    message = str(ev.get("message") or "")
    if not result:
        if event_type in engine.fail_event_types or engine.fail_msg_re.search(message):
            result = "failed"
        elif event_type in engine.success_event_types or engine.success_msg_re.search(message):
            result = "success"
        else:
            result = "unknown"
    if result not in ("failed", "failure", "fail"):
        return None
    return {
        **ev,
        "host": str(host or src_ip or ""),
        "timestamp": ts,
        "src_ip": str(src_ip or ""),
        "user": str(user or ""),
        "result": "failed",
    }


def collect_ssh_events(
    bundles: dict[str, list[dict[str, Any]]],
    *,
    fallback_hosts: list[str] | None = None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    fallbacks = fallback_hosts or []
    for key in ("ssh_auth", "syslog_risk_alert"):
        for ev in bundles.get(key) or []:
            fb = fallbacks[0] if len(fallbacks) == 1 else None
            norm = normalize_ssh_event(ev, fallback_host=fb)
            if norm:
                out.append(norm)
    return out


def host_matches(ev: dict[str, Any], params: dict[str, Any]) -> bool:
    event_hosts = {
        str(value)
        for value in (
            ev.get("host"),
            ev.get("host_ip"),
            ev.get("host_name"),
        )
        if value not in (None, "", "null")
    }
    expected = {
        str(value)
        for value in (params.get("host"), params.get("host_ip"), params.get("host_name"))
        if value not in (None, "")
    }
    if expected and event_hosts.isdisjoint(expected):
        hosts = params.get("hosts") or []
        if hosts and event_hosts.isdisjoint({str(h) for h in hosts}):
            return False
    return True


def event_belongs_to_victim(ev: dict[str, Any], victim_host: str) -> bool:
    if not victim_host:
        return True
    for key in ("host", "host_ip", "host_name"):
        if str(ev.get(key) or "") == victim_host:
            return True
    blob = " ".join(str(ev.get(k) or "") for k in ("message", "event_type", "user", "src_ip"))
    return victim_host in blob


def filter_ssh_events(events: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    expected_hosts = {
        str(value)
        for value in (params.get("host"), params.get("host_ip"), params.get("host_name"))
        if value not in (None, "")
    }
    expected_hosts.update(str(h) for h in (params.get("hosts") or []))
    single_victim = next(iter(expected_hosts)) if len(expected_hosts) == 1 else None
    out = []
    for ev in events:
        if single_victim and not event_belongs_to_victim(ev, single_victim):
            continue
        norm = dict(ev)
        host = str(norm.get("host") or norm.get("host_ip") or norm.get("host_name") or "")
        if host in ("", "null", "localhost", "localhost.localdomain") and single_victim:
            norm["host"] = single_victim
        if not host_matches(norm, params):
            continue
        if not in_time_window(event_timestamp(norm), params.get("time_start"), params.get("time_end")):
            continue
        out.append(norm)
    return out


def filter_ssh_events_for_hosts(
    bundles: dict[str, list[dict[str, Any]]],
    params: dict[str, Any],
) -> list[dict[str, Any]]:
    """Scope failures and preserve distinct native events within one second.

    Reuploads with a common native identity collapse, including copies exposed
    by both auth and syslog bundles. Legacy records without native IDs retain
    the host/source/time/user heuristic; their precision remains source-limited.
    """
    raw = collect_ssh_events(bundles)
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for ev in raw:
        norm = normalize_ssh_event(ev)
        if norm is None:
            continue
        if not host_matches(norm, params):
            continue
        if not in_time_window(event_timestamp(norm), params.get("time_start"), params.get("time_end")):
            continue
        key = (
                str(norm.get("host")),
                str(norm.get("src_ip")),
                str(event_timestamp(norm)),
                str(norm.get("user")),
                str(norm.get("audit_id") or norm.get("event_id") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(norm)
    return out


def detect_bruteforce_bursts(
    events: list[dict[str, Any]],
    *,
    window_sec: int | None = None,
    threshold: int | None = None,
) -> list[dict[str, Any]]:
    engine = get_ssh_rules_engine()
    window_sec = engine.default_window_sec if window_sec is None else window_sec
    threshold = engine.default_threshold if threshold is None else threshold
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        victim = str(ev.get("host") or "")
        src = str(ev.get("src_ip") or "")
        if not victim or not src:
            continue
        if engine.suppress_self_loop and victim == src:
            continue
        groups[(victim, src)].append(ev)

    bursts: list[dict[str, Any]] = []
    wave_counters: dict[tuple[str, str], int] = defaultdict(int)
    for (victim, src), group in groups.items():
        group.sort(key=lambda e: event_timestamp(e) or "")
        times = [parse_ts(event_timestamp(e)) for e in group]
        times = [t for t in times if t is not None]
        if len(times) < threshold:
            continue
        i = 0
        while i < len(times):
            j = i
            while j < len(times) and times[j] - times[i] <= timedelta(seconds=window_sec):
                j += 1
            count = j - i
            if count >= threshold:
                window_events = group[i:j]
                users = sorted({str(e.get("user") or "") for e in window_events if e.get("user")})
                wave_counters[(victim, src)] += 1
                bursts.append(
                    {
                        "victim_host": victim,
                        "src_ip": src,
                        "wave_index": wave_counters[(victim, src)],
                        "fail_count": count,
                        "window_sec": window_sec,
                        "users": users,
                        "first_seen": event_timestamp(window_events[0]),
                        "last_seen": event_timestamp(window_events[-1]),
                        "evidence_refs": [
                            e.get("evidence_id")
                            for e in window_events
                            if e.get("evidence_id")
                        ][:20],
                        "sample_message": str(window_events[0].get("message") or "")[:200],
                    }
                )
                i = j
            else:
                i += 1
    bursts.sort(key=lambda b: (b.get("first_seen") or "", b.get("victim_host") or ""))
    return bursts


def assess_ssh_bruteforce(
    events: list[dict[str, Any]],
    *,
    ceiling: float,
    severity_floor: str,
    window_sec: int | None = None,
    threshold: int | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    engine = get_ssh_rules_engine()
    window_sec = engine.default_window_sec if window_sec is None else window_sec
    threshold = engine.default_threshold if threshold is None else threshold
    bursts = detect_bruteforce_bursts(events, window_sec=window_sec, threshold=threshold)
    items: list[dict[str, Any]] = []
    rule_meta = engine.brute_force_rule
    matched_rule = str(rule_meta.get("matched_rule") or "ssh_bruteforce")
    for burst in bursts:
        fail_count = int(burst.get("fail_count") or 0)
        severity = engine.severity_for_count(fail_count)
        if SEVERITY_RANK.get(severity, 9) > SEVERITY_RANK.get(severity_floor, 9):
            continue
        users = burst.get("users") or []
        user_text = ", ".join(users[:5]) if users else "unknown"
        wave_idx = burst.get("wave_index") or 1
        wave_label = f"第{wave_idx}波" if wave_idx > 1 else "首波"
        matched = [matched_rule]
        items.append(
            {
                "risk_id": (
                    f"risk-ssh-brute-{burst['victim_host']}-{burst['src_ip']}-w{wave_idx}"
                ),
                "risk_module": "ssh",
                "alert_type": str(rule_meta.get("alert_type") or "ssh_bruteforce"),
                "severity": severity,
                "confidence": engine.confidence_for_burst(severity, ceiling),
                "verdict": engine.verdict_for(severity, matched),
                "host": burst["victim_host"],
                "timestamp": burst.get("first_seen"),
                "src_ip": burst["src_ip"],
                "fail_count": fail_count,
                "window_sec": burst["window_sec"],
                "wave_index": wave_idx,
                "target_users": users,
                "matched_rules": matched,
                "risk_tags": engine.tags_for(matched),
                "recommended_action": engine.action_for(severity),
                "summary": (
                    f"{burst['victim_host']} 遭受 SSH 暴力破解（{wave_label}）：{burst['src_ip']} "
                    f"{burst['window_sec']}s 内 {fail_count} 次失败"
                    f"（用户: {user_text}）"
                ),
                "evidence_refs": burst.get("evidence_refs") or [],
                "policy_rule_id": str(rule_meta.get("policy_rule_id") or "SSH-BRUTE-001"),
            }
        )
    return items, bursts


_engine = SshRulesEngine.from_path(default_ssh_rules_path())
FAIL_EVENT_TYPES = _engine.fail_event_types
SUCCESS_EVENT_TYPES = _engine.success_event_types
DEFAULT_WINDOW_SEC = _engine.default_window_sec
DEFAULT_FAIL_THRESHOLD = _engine.default_threshold
FAIL_MSG_RE = _engine.fail_msg_re
SUCCESS_MSG_RE = _engine.success_msg_re
