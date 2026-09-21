"""Lateral movement detection and BFS helpers."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

from heuristic_rules import (  # noqa: E402
    format_template,
    heuristic_time_window_deltas,
    policy_block,
    section,
    ssh_result_from_rules,
)
from host_normalize import (  # noqa: E402
    extract_ssh_lateral_targets,
    investigation_host_set,
    victim_host_from_event,
)

from .common import cmd_text, in_window, near, parse_ts

ACCEPTED_SSH = {"accepted", "success", "successful"}
FAILED_SSH = {"failed", "failure", "invalid"}

def find_lateral_from_exec(
    index: dict[str, dict],
    source_hosts: list[str],
    host_ip_map: dict[str, str],
    anchor: datetime | None,
    t_end: datetime | None,
    params: dict[str, Any] | None = None,
) -> tuple[list[dict], list[dict]]:
    """Detect lateral movement from sshpass/ssh patterns in host_exec (TigerSec src_ip gap)."""
    cfg = section("lateral_from_exec")
    if cfg.get("enabled") is False:
        return [], []

    lookback_min, _ = heuristic_time_window_deltas("lateral_from_exec")
    lateral: list[dict] = []
    graph_edges: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    source_set = set(source_hosts)
    allowed_targets = investigation_host_set(params or {}, host_ip_map)

    for ref, ev in index.items():
        if ev["_bundle"] != "host_exec":
            continue
        source = victim_host_from_event(ev, host_ip_map)
        if not source or source not in source_set:
            continue
        ts = parse_ts(ev.get("timestamp"))
        if anchor and ts and ts < anchor - timedelta(minutes=lookback_min):
            continue
        if not in_window(ts, None, t_end):
            continue
        text = cmd_text(ev)
        if "ssh" not in text.lower() and "sshpass" not in text.lower():
            continue
        for user, dst_ip in extract_ssh_lateral_targets(text):
            if dst_ip == source:
                continue
            if allowed_targets and dst_ip not in allowed_targets:
                continue
            key = (source, dst_ip, user)
            if key in seen:
                continue
            seen.add(key)
            lateral.append(
                {
                    "stage": "lateral_movement",
                    "mitre_id": str(cfg.get("mitre_id") or "T1021.004"),
                    "timestamp": ts.isoformat() if ts else ev.get("timestamp"),
                    "attempt_timestamp": ts.isoformat() if ts else ev.get("timestamp"),
                    "confirmed_timestamp": None,
                    "host": dst_ip,
                    "source_host": source,
                    "user": None if user == "?" else user,
                    "lateral_class": str(cfg.get("lateral_class") or "suspected_lateral"),
                    "description": format_template(
                        str(cfg.get("description_template") or ""),
                        source=source,
                        dst=dst_ip,
                        user=user,
                    ),
                    "evidence_refs": [ref],
                    "join_ids": [str(cfg.get("join_id") or "lateral_from_exec")],
                    "confidence": float(cfg.get("confidence") or 0.78),
                    "correlation_source": str(cfg.get("correlation_source") or "exec_inferred"),
                }
            )
            graph_edges.append(
                {
                    "from": source,
                    "to": dst_ip,
                    "protocol": "SSH",
                    "stage": "lateral_movement",
                    "class": str(cfg.get("lateral_class") or "suspected_lateral"),
                }
            )
    return lateral, graph_edges


def ssh_result(ev: dict) -> str:
    try:
        return ssh_result_from_rules(ev)
    except FileNotFoundError:
        r = str(ev.get("result") or "").lower()
        if r in ACCEPTED_SSH or "accept" in r:
            return "accepted"
        if r in FAILED_SSH or "fail" in r:
            return "failed"
        return r or "unknown"


def bfs_lateral(
    seed_hosts: list[str],
    host_ips: dict[str, str],
    index: dict[str, dict],
    anchor: datetime | None,
    t_end: datetime | None,
    max_hops: int | None = None,
    ssh_partial: bool = False,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Returns attack_chain nodes, graph nodes, graph edges."""
    bfs_policy = policy_block("bfs_lateral")
    bruteforce = dict(bfs_policy.get("ssh_bruteforce_suspected") or {})
    hop_limit = int(max_hops if max_hops is not None else bfs_policy.get("max_hops") or 10)
    mitre = str(bfs_policy.get("mitre_id") or "T1021.004")
    conf_with_fw = float(bfs_policy.get("confidence_with_fw") or 0.88)
    conf_without_fw = float(bfs_policy.get("confidence_without_fw") or 0.82)
    fw_near = int(bfs_policy.get("firewall_near_seconds") or 600)
    fail_threshold = int(bruteforce.get("failed_threshold") or 5)
    suspect_conf = float(bruteforce.get("confidence") or 0.55)

    lateral_nodes: list[dict] = []
    g_nodes: dict[str, dict] = {}
    g_edges: list[dict] = []
    visited_hosts: set[str] = set()
    queue: deque[tuple[str, int]] = deque()

    for h in seed_hosts:
        queue.append((h, 0))
        visited_hosts.add(h)
        g_nodes[h] = {"id": h, "type": "host", "label": h}

    confirmed: list[dict] = []
    suspected: list[dict] = []

    while queue:
        current, depth = queue.popleft()
        if depth >= hop_limit:
            continue
        current_ip = host_ips.get(current, current)

        accepted_targets: dict[str, list[dict]] = {}
        failed_count = 0

        for ref, ev in index.items():
            if ev["_bundle"] != "ssh_auth":
                continue
            ts = parse_ts(ev.get("timestamp"))
            if anchor and ts and ts < anchor:
                continue
            if not in_window(ts, None, t_end):
                continue
            target = victim_host_from_event(ev, host_ips) or ev.get("host") or ev.get("dst_host")
            if not target or target == current:
                continue
            src = ev.get("src_ip") or ""
            msg = str(ev.get("message") or "")
            if not src and (current_ip in msg or current in msg):
                src = current_ip
            if src and src != current_ip and src != current:
                continue
            if not src and current_ip not in msg and current not in msg:
                continue
            result = ssh_result(ev)
            if result == "accepted":
                accepted_targets.setdefault(target, []).append(ev)
            elif result == "failed":
                failed_count += 1

        for target, events in accepted_targets.items():
            events.sort(key=lambda e: parse_ts(e.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc))
            ev = events[0]
            ts = parse_ts(ev.get("timestamp"))
            refs = [ev["_ref"]]
            fw_refs = []
            for ref2, fw in index.items():
                if fw["_bundle"] != "firewall_log":
                    continue
                if fw.get("src_ip") not in (current_ip, current):
                    continue
                if fw.get("dst_ip") not in (host_ips.get(target, target), target):
                    continue
                if str(fw.get("dst_port")) in ("22", "22.0") or fw.get("dst_port") == 22:
                    fts = parse_ts(fw.get("timestamp"))
                    if near(ts, fts, fw_near):
                        fw_refs.append(fw["_ref"])
            refs.extend(fw_refs)

            lateral = {
                "stage": "lateral_movement",
                "mitre_id": mitre,
                "timestamp": ts.isoformat() if ts else ev.get("timestamp"),
                "attempt_timestamp": None,
                "confirmed_timestamp": ts.isoformat() if ts else ev.get("timestamp"),
                "host": target,
                "source_host": current,
                "user": ev.get("user"),
                "lateral_class": "confirmed_lateral",
                "description": f"SSH 登录成功: {current}({current_ip}) → {target} 用户 {ev.get('user')}",
                "evidence_refs": list(dict.fromkeys(refs)),
                "confidence": conf_with_fw if fw_refs else conf_without_fw,
            }
            confirmed.append(lateral)

            if target not in visited_hosts:
                visited_hosts.add(target)
                queue.append((target, depth + 1))
                g_nodes[target] = {"id": target, "type": "host", "label": target}
                g_edges.append(
                    {
                        "from": current,
                        "to": target,
                        "protocol": "SSH",
                        "stage": "lateral_movement",
                        "class": "confirmed_lateral",
                    }
                )

        if failed_count >= fail_threshold and not accepted_targets:
            suspected.append(
                {
                    "source_host": current,
                    "lateral_class": "suspected_lateral",
                    "description": f"{current} 存在大量 SSH 失败尝试（{failed_count} 条），无 Accepted 记录",
                    "confidence": suspect_conf,
                }
            )

    if ssh_partial and confirmed:
        for item in confirmed:
            item["coverage_note"] = "SSH 日志覆盖不全，横向清单可能遗漏"

    return confirmed, list(g_nodes.values()), g_edges, suspected

