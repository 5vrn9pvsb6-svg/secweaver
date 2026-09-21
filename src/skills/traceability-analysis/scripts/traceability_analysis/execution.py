"""Execution-chain stage detection."""

from __future__ import annotations

from datetime import timedelta

from heuristic_rules import matrix_window_deltas, policy_block  # noqa: E402
from host_normalize import remote_execution_context  # noqa: E402

from .common import cmd_text, event_on_host, in_window, near, parse_ts

def dedupe_execution_stages(stages: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict] = []
    for stage in sorted(stages, key=lambda x: x.get("timestamp") or ""):
        key = (
            stage.get("stage", ""),
            stage.get("host", ""),
            (stage.get("timestamp") or "")[:19],
            tuple(sorted(stage.get("evidence_refs") or [])),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(stage)
    return out


def find_execution_chain(
    host: str,
    index: dict[str, dict],
    anchor: datetime | None,
    patterns: dict,
    t_end: datetime | None,
) -> list[dict]:
    chain: list[dict] = []
    download_pats = patterns.get("download_exec_patterns", [])
    mitre = patterns.get("stage_mitre_defaults", {})
    exec_policy = policy_block("execution_chain")
    lookback_min, _ = matrix_window_deltas(str(exec_policy.get("time_window") or "host_behavior_chain"))
    base_conf = float(exec_policy.get("base_confidence") or 0.85)
    connect_near = int(exec_policy.get("connect_near_seconds") or 120)
    connect_boost = float(exec_policy.get("connect_boost") or 0.08)
    conf_cap = float(exec_policy.get("confidence_cap") or 0.95)
    file_near = int(exec_policy.get("file_op_near_seconds") or 300)
    persistence_near = int(exec_policy.get("persistence_near_seconds") or 600)

    exec_events: list[tuple[datetime, dict]] = []
    for ref, ev in index.items():
        if ev["_bundle"] != "host_exec":
            continue
        if not event_on_host(ev, host):
            continue
        ts = parse_ts(ev.get("timestamp"))
        if anchor and ts and ts < anchor - timedelta(minutes=lookback_min):
            continue
        if not in_window(ts, None, t_end):
            continue
        if ts:
            exec_events.append((ts, ev))

    exec_events.sort(key=lambda x: x[0])

    for ts, ev in exec_events:
        text = cmd_text(ev).lower()
        refs = [ev["_ref"]]
        desc = f"主机 {host} 执行命令: {cmd_text(ev)[:120]}"
        conf = base_conf

        for ref2, cev in index.items():
            if cev["_bundle"] != "host_connect":
                continue
            if not event_on_host(cev, host):
                continue
            cts = parse_ts(cev.get("timestamp"))
            if near(ts, cts, connect_near):
                refs.append(cev["_ref"])
                conf = min(conf_cap, conf + connect_boost)
                desc += f"；主动外连 {cev.get('dst_ip')}:{cev.get('dst_port')}"

        for ref2, fev in index.items():
            if fev["_bundle"] != "host_file_op":
                continue
            if not event_on_host(fev, host):
                continue
            fts = parse_ts(fev.get("timestamp"))
            if near(ts, fts, file_near):
                refs.append(fev["_ref"])

        for ref2, pev in index.items():
            if pev["_bundle"] != "host_persistence":
                continue
            if not event_on_host(pev, host):
                continue
            pts = parse_ts(pev.get("timestamp"))
            if near(ts, pts, persistence_near):
                refs.append(pev["_ref"])

        stage = "execution"
        if any(p in text for p in download_pats):
            desc = f"{host} 监听进程子进程下载/执行: {cmd_text(ev)[:120]}"

        row = {
                "stage": stage,
                "mitre_id": mitre.get(stage, "T1059"),
                "timestamp": ts.isoformat(),
                "host": host,
                "description": desc,
                "evidence_refs": list(dict.fromkeys(refs)),
                "confidence": round(conf, 2),
            }
        row.update(remote_execution_context(cmd_text(ev), source_host=host))
        chain.append(row)

    return chain


def find_persistence_chain(
    host: str,
    index: dict[str, dict],
    anchor: datetime | None,
    patterns: dict,
    t_end: datetime | None,
) -> list[dict]:
    chain: list[dict] = []
    mitre = patterns.get("stage_mitre_defaults", {})
    exec_policy = policy_block("execution_chain")
    lookback_min, _ = matrix_window_deltas(str(exec_policy.get("time_window") or "host_behavior_chain"))
    base_conf = float(exec_policy.get("persistence_confidence") or 0.84)

    events: list[tuple[datetime, dict]] = []
    for ref, ev in index.items():
        if ev["_bundle"] != "host_persistence":
            continue
        if not event_on_host(ev, host):
            continue
        ts = parse_ts(ev.get("timestamp") or ev.get("time"))
        if anchor and ts and ts < anchor - timedelta(minutes=lookback_min):
            continue
        if not in_window(ts, None, t_end):
            continue
        if ts:
            events.append((ts, ev))

    events.sort(key=lambda x: x[0])
    for ts, ev in events:
        ptype = ev.get("persistence_type") or ev.get("category") or "persistence"
        action = ev.get("action") or ev.get("event_type") or "changed"
        path = ev.get("path") or "?"
        actor = ev.get("auid_name") or ev.get("user") or ev.get("uid")
        process = ev.get("process") or ev.get("comm") or ev.get("exe")
        detail = f"{host} 持久化变更: {ptype} {action} {path}"
        if actor:
            detail += f"；actor={actor}"
        if process:
            detail += f"；process={process}"
        chain.append(
            {
                "stage": "persistence",
                "mitre_id": mitre.get("persistence", "T1547"),
                "timestamp": ts.isoformat(),
                "host": host,
                "description": detail,
                "evidence_refs": [ev["_ref"]],
                "confidence": round(base_conf, 2),
            }
        )
    return chain
