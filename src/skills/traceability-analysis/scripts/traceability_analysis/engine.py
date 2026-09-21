"""Traceability analysis orchestration."""

from __future__ import annotations

import sys
from typing import Any

from attck_trace import build_trace_mitre_attack, format_mitre_attack_short  # noqa: E402
from correlation_trace import (  # noqa: E402
    attach_join_ids_to_stages,
    build_stages_from_join_edges,
    correlate_for_trace,
    dedupe_lateral_stages,
    matrix_supports_exec,
    matrix_supports_lateral,
    merge_attack_stages,
    merge_initial_access,
    resolve_trace_contract,
)
from heuristic_rules import policy_block, section  # noqa: E402
from host_normalize import (  # noqa: E402
    enrich_impacted_with_registry,
    inject_registered_hosts,
    investigation_host_set,
    merge_registry_host_ips,
    normalize_bundles_for_trace,
)
from risk_rules_bridge import load_trace_patterns, resolve_matched_pattern  # noqa: E402
from source_adapters.tigersec_syslog import (  # noqa: E402
    find_lateral_confirmations_from_syslog,
    upgrade_suspected_lateral_with_syslog,
)
from source_adapters.tigersec_target_impact import (  # noqa: E402
    find_post_lateral_target_exec_signals,
    impacted_note_for_likely_lateral,
    upgrade_suspected_lateral_with_target_exec,
)
from timeline_source_coverage import (  # noqa: E402
    build_source_coverage,
    resolve_timeline_source_types,
)
from trace_d1_bootstrap import build_attacker_ip_resolution  # noqa: E402

from .common import (
    build_host_ip_map,
    cmd_text,
    in_window,
    index_evidence,
    parse_ts,
    raw_behavior_text,
    web_event_url,
    web_event_victim_host,
)
from .execution import dedupe_execution_stages, find_execution_chain, find_persistence_chain
from .initial_access import (
    _exec_inferred_confidence,
    _initial_access_description,
    d1_reverse_lookup_gap,
    find_initial_access,
    find_initial_access_from_exec,
    find_initial_access_from_victim,
    resolve_execution_hosts,
)
from .lateral import bfs_lateral, find_lateral_from_exec
from .paths import DATA_ACCESS_PATH
from .result import (
    _blocked_result,
    compute_confidence,
    determine_verdict,
    gate_precheck,
    recommended_actions,
    simplify_evidence_item,
)


def _evaluated_asset_types(payload: dict[str, Any], bundles: dict[str, list[dict[str, Any]]]) -> set[str]:
    evaluated = {str(asset_type) for asset_type in bundles if asset_type}
    summary = payload.get("fetch_summary") or {}
    data_access = payload.get("data_access") or {}
    asset_ids = (
        summary.get("executed_asset_ids")
        or data_access.get("executed_asset_ids")
        or summary.get("fetch_asset_ids")
        or data_access.get("asset_ids")
        or []
    )
    if asset_ids:
        if str(DATA_ACCESS_PATH) not in sys.path:
            sys.path.insert(0, str(DATA_ACCESS_PATH))
        from registry import load_asset  # noqa: E402

        for asset_id in asset_ids:
            try:
                asset = load_asset(str(asset_id))
            except FileNotFoundError:
                continue
            asset_type = str(asset.get("asset_type") or "")
            if asset_type:
                evaluated.add(asset_type)
    return evaluated


def _not_evaluated_join_gaps(correlation: dict[str, Any], evaluated_asset_types: set[str]) -> list[str]:
    if not evaluated_asset_types:
        return []
    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    from correlation_engine import get_join, load_matrix  # noqa: E402

    matrix = load_matrix()
    gaps: list[str] = []
    seen: set[str] = set()
    for gap in correlation.get("data_gaps") or []:
        if not str(gap).startswith("no_match:"):
            continue
        join_id = str(gap).split(":", 1)[1].split(" ", 1)[0]
        join = get_join(join_id, matrix) or {}
        required = {
            str(join.get(key) or "")
            for key in ("from_asset_type", "to_asset_type")
            if join.get(key)
        }
        missing = sorted(required - evaluated_asset_types)
        if not missing:
            continue
        marker = f"not_evaluated:{join_id} (missing asset_type: {', '.join(missing)})"
        if marker not in seen:
            gaps.append(marker)
            seen.add(marker)
    return gaps


WEB_ATTACK_HINTS = (
    "webshell",
    "/cmdi/",
    "cmd=",
    "command=",
    "exec=",
    "shell=",
    ";id",
    ";whoami",
    ";cat",
    ".php?c=",
    ".php?cmd",
    "upload.php",
    "../",
    "union select",
    "<script",
    "${jndi:",
)


def _event_src_ip(ev: dict[str, Any]) -> str:
    return str(
        ev.get("src_ip")
        or ev.get("client_ip")
        or ev.get("remote_addr")
        or ev.get("real_client_ip")
        or ""
    )


def _web_event_is_attack_like(ev: dict[str, Any], initial_refs: set[str]) -> bool:
    if ev.get("_ref") in initial_refs:
        return True
    if ev.get("_bundle") == "waf_alert":
        return True
    text = " ".join(
        str(value or "")
        for value in (
            web_event_url(ev),
            ev.get("payload"),
            ev.get("request_body"),
            ev.get("args"),
            ev.get("rule_name"),
            ev.get("attack_type"),
        )
    ).lower()
    return any(hint in text for hint in WEB_ATTACK_HINTS)


def _web_timeline_description(ev: dict[str, Any]) -> str:
    method = str(ev.get("method") or ev.get("request_method") or "").upper()
    url = web_event_url(ev) or str(ev.get("url") or ev.get("request_uri") or ev.get("path") or "")
    parts = [part for part in (method, url) if part]
    desc = "WEB层攻击请求"
    if parts:
        desc += ": " + " ".join(parts)
    extras = []
    status = ev.get("status") or ev.get("status_code")
    action = ev.get("action") or ev.get("waf_action")
    rule = ev.get("rule_name") or ev.get("rule_id") or ev.get("attack_type")
    if status:
        extras.append(f"status={status}")
    if action:
        extras.append(f"action={action}")
    if rule:
        extras.append(f"rule={rule}")
    if extras:
        desc += "（" + "，".join(str(item) for item in extras) + "）"
    return desc


def _raw_behavior_from_refs(refs: list[str], index: dict[str, dict[str, Any]], *, limit: int = 3) -> str:
    values: list[str] = []
    for ref in refs:
        ev = index.get(str(ref))
        if not ev:
            continue
        raw = raw_behavior_text(ev)
        if not raw or raw in values:
            continue
        values.append(raw)
        if len(values) >= limit:
            break
    return " | ".join(values)


def _stage_raw_behavior(stage: dict[str, Any], index: dict[str, dict[str, Any]]) -> str:
    raw = str(stage.get("raw_behavior") or "").strip()
    if raw:
        return raw
    refs = [str(ref) for ref in (stage.get("evidence_refs") or []) if ref]
    preferred: dict[str, tuple[str, ...]] = {
        "initial_access": ("web_access_log", "waf_alert", "host_exec"),
        "execution": ("host_exec", "host_connect", "host_file_op", "host_persistence"),
        "persistence": ("host_persistence", "host_exec", "syslog_risk_alert"),
        "command_and_control": ("dns_log", "host_connect", "host_exec", "syslog_risk_alert"),
        "exfiltration": ("dns_log", "host_connect", "network_traffic_audit", "host_exec"),
        "lateral_movement": ("host_exec", "ssh_auth", "syslog_risk_alert"),
    }
    order = preferred.get(str(stage.get("stage") or ""), ())
    if order:
        ordered_refs = sorted(
            refs,
            key=lambda ref: order.index(index.get(ref, {}).get("_bundle"))
            if index.get(ref, {}).get("_bundle") in order
            else len(order),
        )
    else:
        ordered_refs = refs
    return _raw_behavior_from_refs(ordered_refs, index)


def _web_attack_timeline_entries(
    index: dict[str, dict[str, Any]],
    initial: dict[str, Any] | None,
    attacker_ip: str | None,
    params: dict[str, Any],
    t_start,
    t_end,
    timeline_source_types: list[str],
    simplified_index: dict[str, Any],
) -> list[dict[str, Any]]:
    initial_refs = {str(ref) for ref in ((initial or {}).get("evidence_refs") or [])}
    known_attacker = str(attacker_ip or (initial or {}).get("attacker_ip") or "")
    target_ip = str(params.get("target_ip") or "")
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for ref, ev in index.items():
        if ev.get("_bundle") not in {"waf_alert", "web_access_log"}:
            continue
        ts = parse_ts(ev.get("timestamp"))
        if not in_window(ts, t_start, t_end):
            continue
        src_ip = _event_src_ip(ev)
        if known_attacker and src_ip and src_ip != known_attacker and ref not in initial_refs:
            continue
        if not _web_event_is_attack_like(ev, initial_refs):
            continue

        url = web_event_url(ev) or str(ev.get("url") or ev.get("request_uri") or ev.get("path") or "")
        host = (
            web_event_victim_host(ev, target_ip)
            or (initial or {}).get("host")
            or ev.get("host")
            or ev.get("hostname")
            or target_ip
        )
        key = (str(ev.get("timestamp") or ""), str(ev.get("_bundle") or ""), str(host or ""), url)
        if key in seen:
            continue
        seen.add(key)

        entry = {
            "timestamp": ev.get("timestamp"),
            "stage": "web_attack",
            "host": host,
            "description": _web_timeline_description(ev),
            "raw_behavior": raw_behavior_text(ev),
            "mitre_id": "T1190",
            "evidence_refs": [ref],
            "join_ids": [],
        }
        if timeline_source_types:
            entry["source_coverage"] = build_source_coverage(
                [ref],
                simplified_index,
                timeline_source_types,
            )
        entries.append(entry)

    return sorted(entries, key=lambda item: str(item.get("timestamp") or ""))


def _host_tokens_from_params(params: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for key in ("host", "host_ip", "target_ip", "src_ip"):
        value = params.get(key)
        if value not in (None, ""):
            tokens.add(str(value))
    for key in ("hosts", "seed_hosts", "target_hosts"):
        raw = params.get(key) or []
        if isinstance(raw, str):
            raw = [raw]
        tokens.update(str(value) for value in raw if value not in (None, ""))
    return tokens


def _dns_query(ev: dict[str, Any]) -> str:
    for key in ("query", "qname", "domain", "hostname"):
        value = ev.get(key)
        if value not in (None, ""):
            return str(value).rstrip(".")
    return ""


def _dns_client(ev: dict[str, Any]) -> str:
    for key in ("client_ip", "src_ip", "host_ip", "host"):
        value = ev.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _syslog_host(ev: dict[str, Any]) -> str:
    for key in ("_victim_host", "host_ip", "host", "host_name", "__source__"):
        value = ev.get(key)
        if value not in (None, "", "null", "localhost", "localhost.localdomain"):
            return str(value)
    return ""


def _dns_timeline_description(ev: dict[str, Any]) -> str:
    query = _dns_query(ev) or "?"
    qtype = str(ev.get("query_type") or ev.get("qtype") or "")
    rcode = str(ev.get("rcode") or ev.get("response_code") or "")
    answer = ev.get("response") or ev.get("answers") or ev.get("resolved_ip") or ev.get("answer")
    parts = [f"DNS 查询 {query}"]
    if qtype:
        parts.append(f"type={qtype}")
    if rcode:
        parts.append(f"rcode={rcode}")
    if answer not in (None, ""):
        parts.append(f"answer={str(answer)[:120]}")
    return "，".join(parts)


def _dns_context_timeline_entries(
    index: dict[str, dict[str, Any]],
    params: dict[str, Any],
    scenarios: list[str],
    t_start,
    t_end,
    timeline_source_types: list[str],
    simplified_index: dict[str, Any],
    relevant_hosts: set[str],
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    host_tokens = set(relevant_hosts) | _host_tokens_from_params(params)
    # Raw DNS rows provide context only: choosing S7/S8 cannot prove intent,
    # data direction, or a C2 session. Preserve evidence without an ATT&CK label.
    stage = "network_activity"
    mitre_id = ""
    for ref, ev in index.items():
        if ev.get("_bundle") != "dns_log":
            continue
        ts = parse_ts(ev.get("timestamp"))
        if not in_window(ts, t_start, t_end):
            continue
        client = _dns_client(ev)
        if host_tokens and client and client not in host_tokens:
            continue
        query = _dns_query(ev)
        entry = {
            "timestamp": ev.get("timestamp"),
            "stage": stage,
            "host": client or "unknown",
            "description": _dns_timeline_description(ev),
            "raw_behavior": raw_behavior_text(ev),
            "mitre_id": mitre_id,
            "evidence_refs": [ref],
            "join_ids": [],
            "dns_query": query,
            "dns_rcode": ev.get("rcode") or ev.get("response_code"),
        }
        if timeline_source_types:
            entry["source_coverage"] = build_source_coverage(
                [ref],
                simplified_index,
                timeline_source_types,
            )
        entries.append(entry)
    return entries


def _syslog_context_timeline_entries(
    index: dict[str, dict[str, Any]],
    params: dict[str, Any],
    t_start,
    t_end,
    timeline_source_types: list[str],
    simplified_index: dict[str, Any],
    relevant_hosts: set[str],
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    host_tokens = set(relevant_hosts) | _host_tokens_from_params(params)
    noisy = {"ssh_login_failed", "auth_failure", "ssh_invalid_user", "ssh_auth_attempts_exceeded"}
    for ref, ev in index.items():
        if ev.get("_bundle") != "syslog_risk_alert":
            continue
        event_type = str(ev.get("event_type") or "").lower()
        if event_type in noisy:
            continue
        ts = parse_ts(ev.get("timestamp"))
        if not in_window(ts, t_start, t_end):
            continue
        host = _syslog_host(ev)
        if host_tokens and host and host not in host_tokens:
            continue
        entry = {
            "timestamp": ev.get("timestamp"),
            "stage": "syslog_context",
            "host": host or "unknown",
            "description": f"Syslog 风险事件: {event_type or ev.get('rule_name') or '?'}",
            "raw_behavior": raw_behavior_text(ev),
            "mitre_id": "T1078" if "ssh" in event_type or "auth" in event_type else "T1562",
            "evidence_refs": [ref],
            "join_ids": [],
        }
        if timeline_source_types:
            entry["source_coverage"] = build_source_coverage(
                [ref],
                simplified_index,
                timeline_source_types,
            )
        entries.append(entry)
    return entries


def _dedupe_timeline(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for entry in sorted(entries, key=lambda item: str(item.get("timestamp") or "")):
        key = (
            entry.get("timestamp"),
            entry.get("stage"),
            entry.get("host"),
            tuple(entry.get("evidence_refs") or []),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


def analyze(payload: dict, patterns: dict | None = None) -> dict:
    if patterns is None:
        patterns = load_trace_patterns()
    precheck = payload.get("completeness_precheck")
    ok, gate_reason, ceiling = gate_precheck(precheck)

    anchor_override = payload.get("correlation_anchor_pattern")
    if payload.get("correlation_anchor_patterns") and not anchor_override:
        anchor_override = payload["correlation_anchor_patterns"][0]

    contract = resolve_trace_contract(payload, anchor_pattern_id=anchor_override)
    params = contract["params"]
    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    from correlation_engine import apply_investigation_param_aliases, load_matrix

    params = apply_investigation_param_aliases(params, matrix=load_matrix())
    contract = {**contract, "params": params}
    scenarios = contract["scenarios"]
    raw_bundles = payload.get("evidence_bundles") or {}
    raw_bundles, injected_host_ids = inject_registered_hosts(raw_bundles, params)
    if injected_host_ids:
        params = merge_registry_host_ips(params, raw_bundles.get("asset_inventory") or [])
    bundles = normalize_bundles_for_trace(raw_bundles, params)

    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    from syslog_risk_normalize import inject_ssh_auth_from_syslog_risk

    bundles, _syslog_ssh_injected = inject_ssh_auth_from_syslog_risk(bundles, accepted_only=True)

    attacker_ip = params.get("attacker_ip")
    if isinstance(attacker_ip, list):
        attacker_ip = attacker_ip[0] if attacker_ip else None

    t_start = parse_ts(params.get("time_start"))
    t_end = parse_ts(params.get("time_end"))
    alert_time = parse_ts(params.get("alert_time"))

    host_ips = build_host_ip_map(bundles, params)
    index, _ = index_evidence(bundles)
    data_gaps = list((precheck or {}).get("data_gaps") or [])

    if not contract.get("anchor_pattern_ids"):
        data_gaps.append("no anchor_pattern for scenarios — 请检查 scenarios 或 anchor-patterns.json")

    if not ok:
        return _blocked_result(
            scenarios=scenarios,
            ceiling=ceiling,
            gate_reason=gate_reason,
            data_gaps=data_gaps,
            index=index,
            contract=contract,
        )

    correlation = correlate_for_trace(
        bundles,
        scenarios=scenarios,
        params=params,
        anchor_pattern_id=anchor_override,
    )
    data_gaps.extend(correlation.get("data_gaps") or [])
    data_gaps.extend(_not_evaluated_join_gaps(correlation, _evaluated_asset_types(payload, bundles)))

    matrix_initial, matrix_stages = build_stages_from_join_edges(
        correlation.get("join_edges") or [],
        index,
        patterns,
        scenarios=scenarios,
    )

    initial_heur_web = find_initial_access(
        bundles, index, attacker_ip, patterns, t_start, t_end, target_ip=params.get("target_ip")
    )
    initial_heur_exec = find_initial_access_from_exec(index, patterns, t_start, t_end, host_ips)
    initial_victim = find_initial_access_from_victim(
        index,
        params.get("target_ip"),
        patterns,
        t_start,
        t_end,
        attacker_ip=attacker_ip,
    )
    initial = merge_initial_access(matrix_initial, merge_initial_access(initial_victim, merge_initial_access(initial_heur_web, initial_heur_exec)))
    d1_gap = d1_reverse_lookup_gap(params.get("target_ip"), index)
    if d1_gap:
        data_gaps.append(d1_gap)
    if attacker_ip is None and initial and initial.get("attacker_ip"):
        attacker_ip = initial.get("attacker_ip")
    anchor = parse_ts(initial["timestamp"]) if initial else alert_time

    exec_hosts = resolve_execution_hosts(params, initial, index, host_ips)
    execution_heur: list[dict] = []
    persistence_heur: list[dict] = []
    for host in exec_hosts:
        execution_heur.extend(find_execution_chain(host, index, anchor, patterns, t_end))
        persistence_heur.extend(find_persistence_chain(host, index, anchor, patterns, t_end))
    execution_heur = dedupe_execution_stages(execution_heur)
    persistence_heur = dedupe_execution_stages(persistence_heur)

    matrix_exec = [s for s in matrix_stages if s.get("stage") == "execution"]
    matrix_persistence = [s for s in matrix_stages if s.get("stage") == "persistence"]
    matrix_lateral = [s for s in matrix_stages if s.get("stage") == "lateral_movement"]
    matrix_c2 = [s for s in matrix_stages if s.get("stage") == "command_and_control"]
    matrix_exfil = [s for s in matrix_stages if s.get("stage") == "exfiltration"]
    execution = merge_attack_stages(matrix_exec, execution_heur)
    persistence = merge_attack_stages(matrix_persistence, persistence_heur)
    # Neutral network joins remain visible, but never count as execution proof.
    matrix_network = [s for s in matrix_stages if s.get("stage") == "network_activity"]
    network_stages = merge_attack_stages(merge_attack_stages(matrix_c2, matrix_exfil), matrix_network)

    ssh_partial = any("ssh" in g.lower() or "partial" in g.lower() for g in data_gaps)
    seed_hosts = exec_hosts or list(params.get("seed_hosts") or [])
    lateral_heur, g_nodes, g_edges, suspected = bfs_lateral(
        seed_hosts, host_ips, index, anchor, t_end, ssh_partial=ssh_partial
    )
    lateral_exec, g_edges_exec = find_lateral_from_exec(index, seed_hosts, host_ips, anchor, t_end, params)
    lateral_chain = merge_attack_stages(matrix_lateral, merge_attack_stages(lateral_heur, lateral_exec))

    source_hosts = set(seed_hosts) | {str(initial["host"])} if initial else set(seed_hosts)
    target_hosts = investigation_host_set(params, host_ips) - source_hosts
    if not target_hosts:
        for lat in lateral_exec:
            if lat.get("host"):
                target_hosts.add(str(lat["host"]))
    syslog_confirmations = find_lateral_confirmations_from_syslog(
        bundles.get("syslog_risk_alert") or [],
        source_hosts={str(h) for h in source_hosts if h},
        target_hosts={str(h) for h in target_hosts if h},
        anchor=anchor,
        t_end=t_end,
    )
    if syslog_confirmations:
        lateral_login = [c for c in syslog_confirmations if c.get("stage") == "lateral_movement"]
        lateral_chain = merge_attack_stages(lateral_chain, lateral_login)
        lateral_chain = upgrade_suspected_lateral_with_syslog(lateral_chain, syslog_confirmations)
        for conf in lateral_login:
            g_edges.append(
                {
                    "from": conf.get("source_host"),
                    "to": conf.get("host"),
                    "protocol": "SSH",
                    "stage": "lateral_movement",
                    "class": "confirmed_lateral",
                }
            )

    target_exec_signals = find_post_lateral_target_exec_signals(
        bundles.get("host_exec") or [],
        lateral_chain,
    )
    if target_exec_signals:
        lateral_chain = upgrade_suspected_lateral_with_target_exec(lateral_chain, target_exec_signals)
        for lat in lateral_chain:
            if lat.get("lateral_class") != "likely_lateral":
                continue
            if "lateral_from_target_exec" not in (lat.get("join_ids") or []):
                continue
            g_edges.append(
                {
                    "from": lat.get("source_host"),
                    "to": lat.get("host"),
                    "protocol": "SSH",
                    "stage": "lateral_movement",
                    "class": "likely_lateral",
                }
            )

    lateral_chain = dedupe_lateral_stages(lateral_chain)

    g_edges = g_edges + g_edges_exec

    post_compromise = execution + persistence + matrix_c2 + matrix_exfil
    has_exec = bool(post_compromise) or matrix_supports_exec(correlation) or any(
        v["_bundle"] in {"host_exec", "host_persistence"} for v in index.values()
    )
    has_lateral_matrix = matrix_supports_lateral(correlation)
    has_lateral_exec = bool(lateral_exec)

    attack_chain: list[dict] = []
    if initial:
        ia_policy = policy_block("initial_access_stages")
        attack_chain.append(
            {
                "stage": "initial_access",
                "mitre_id": patterns.get("stage_mitre_defaults", {}).get("initial_access", "T1190"),
                "timestamp": initial["timestamp"],
                "host": initial["host"],
                "description": _initial_access_description(initial),
                "primary_evidence_refs": initial.get("primary_evidence_refs") or [],
                "supporting_evidence_refs": initial.get("supporting_evidence_refs") or [],
                "entry_point_role": initial.get("entry_point_role"),
                "first_compromise_point_status": initial.get("first_compromise_point_status"),
                "first_observed_control_url": initial.get("first_observed_control_url"),
                "first_observed_control_timestamp": initial.get("first_observed_control_timestamp"),
                "evidence_refs": initial.get("evidence_refs") or [],
                "join_ids": list(initial.get("join_ids") or []),
                "confidence": float(ia_policy.get("matrix_confidence") or 0.92)
                if initial.get("correlation_source") == "matrix"
                else _exec_inferred_confidence(initial)
                if initial.get("correlation_source") == "exec_inferred"
                else float(ia_policy.get("heuristic_confidence") or 0.9),
                "correlation_source": initial.get("correlation_source", "heuristic_fallback"),
            }
        )
    attack_chain.extend(execution)
    attack_chain.extend(persistence)
    attack_chain.extend(network_stages)
    attack_chain.extend(lateral_chain)
    attack_chain.sort(key=lambda x: x.get("timestamp") or "")
    attach_join_ids_to_stages(attack_chain, correlation.get("join_edges") or [])

    graph_nodes_by_id = {
        str(node.get("id")): dict(node)
        for node in g_nodes
        if node.get("id")
    }
    if attacker_ip:
        graph_nodes_by_id["attacker"] = {
            "id": "attacker",
            "type": "external_ip",
            "label": attacker_ip,
        }

    initial_backend = None
    if initial:
        initial_backend = str(initial.get("target_ip") or initial.get("host") or "").strip() or None
        gateway_host = str(initial.get("gateway_host") or "").strip() or None
        if initial_backend:
            graph_nodes_by_id.setdefault(
                initial_backend,
                {"id": initial_backend, "type": "host", "label": initial_backend},
            )
        if gateway_host and gateway_host != initial_backend:
            graph_nodes_by_id.setdefault(
                gateway_host,
                {"id": gateway_host, "type": "gateway", "label": gateway_host},
            )
        if attacker_ip:
            entry_target = gateway_host or initial_backend
            if entry_target:
                g_edges.insert(
                    0,
                    {
                        "from": "attacker",
                        "to": entry_target,
                        "protocol": "HTTPS",
                        "stage": "initial_access",
                    },
                )
            if gateway_host and initial_backend and gateway_host != initial_backend:
                g_edges.insert(
                    1,
                    {
                        "from": gateway_host,
                        "to": initial_backend,
                        "protocol": "HTTP upstream",
                        "stage": "initial_access",
                    },
                )

    for lateral in lateral_chain:
        source = str(lateral.get("source_host") or "").strip()
        target = str(lateral.get("host") or "").strip()
        if not source or not target or source == target:
            continue
        graph_nodes_by_id.setdefault(source, {"id": source, "type": "host", "label": source})
        graph_nodes_by_id.setdefault(target, {"id": target, "type": "host", "label": target})
        g_edges.append(
            {
                "from": source,
                "to": target,
                "protocol": "SSH",
                "stage": "lateral_movement",
                "class": lateral.get("lateral_class") or "confirmed_lateral",
            }
        )

    for network_stage in network_stages:
        source = str(network_stage.get("host") or "").strip()
        query = str(network_stage.get("dns_query") or "").strip()
        if not source or not query:
            continue
        graph_nodes_by_id.setdefault(source, {"id": source, "type": "host", "label": source})
        graph_nodes_by_id.setdefault(query, {"id": query, "type": "domain", "label": query})
        g_edges.append(
            {
                "from": source,
                "to": query,
                "protocol": "DNS",
                "stage": network_stage.get("stage") or "command_and_control",
                "class": "dns_resolution",
            }
        )

    graph_nodes = list(graph_nodes_by_id.values())
    deduped_graph_edges: list[dict[str, Any]] = []
    seen_graph_edges: set[tuple[str, str, str]] = set()
    for edge in g_edges:
        key = (
            str(edge.get("from") or ""),
            str(edge.get("to") or ""),
            str(edge.get("stage") or ""),
        )
        if not key[0] or not key[1] or key in seen_graph_edges:
            continue
        seen_graph_edges.add(key)
        deduped_graph_edges.append(edge)
    g_edges = deduped_graph_edges

    impacted: list[dict] = []
    if initial:
        impacted.append(
            {
                "host": initial_backend or initial["host"],
                "role": "initial_compromise",
                "priority": "P0",
            }
        )
    for lat in lateral_chain:
        h = lat["host"]
        if not any(a["host"] == h for a in impacted):
            note = lat.get("coverage_note")
            if lat.get("lateral_class") == "likely_lateral":
                note = note or impacted_note_for_likely_lateral(lat)
            impacted.append(
                {
                    "host": h,
                    "role": "lateral_target",
                    "priority": "P0",
                    "note": note,
                }
            )

    verdict = determine_verdict(initial, post_compromise, lateral_chain, False, has_exec)
    if verdict == "confirmed_intrusion_chain" and not has_exec:
        verdict = "likely_intrusion_chain"
    if lateral_chain and has_lateral_matrix and verdict == "initial_access_only":
        verdict = "likely_intrusion_chain"
    if lateral_exec and verdict in ("initial_access_only", "scanning_or_attempt_only") and has_exec:
        verdict = "likely_intrusion_chain"
    if lateral_chain and ssh_partial:
        for a in impacted:
            if a.get("role") != "lateral_target":
                continue
            host = a.get("host")
            if any(
                l.get("host") == host and l.get("lateral_class") in {"likely_lateral", "confirmed_lateral"}
                for l in lateral_chain
            ):
                continue
            a["note"] = "SSH 日志覆盖不全，至少已确认以下主机，可能遗漏"

    impacted = enrich_impacted_with_registry(impacted, bundles.get("asset_inventory") or [])

    confidence = compute_confidence(attack_chain, ceiling)
    join_cov = correlation.get("join_coverage") or {}
    adj = section("confidence_adjustments")
    matrix_gte = int(adj.get("matrix_join_matched_gte") or 2)
    matrix_boost = float(adj.get("matrix_join_boost") or 0.03)
    likely_boost = float(adj.get("likely_lateral_boost") or 0.03)
    if join_cov.get("matched_join_count", 0) >= matrix_gte:
        confidence = round(min(ceiling, confidence + matrix_boost), 2)
    if any(l.get("lateral_class") == "likely_lateral" for l in lateral_chain):
        confidence = round(min(ceiling, confidence + likely_boost), 2)

    simplified_index = {ref: simplify_evidence_item(ev) for ref, ev in index.items()}
    timeline_source_types = resolve_timeline_source_types(
        {
            "fetch_summary": payload.get("fetch_summary")
            or {
                "by_asset_type": {k: len(v or []) for k, v in bundles.items() if v},
                "asset_ids": payload.get("asset_ids")
                or (payload.get("data_access") or {}).get("asset_ids"),
            },
            "evidence_index": simplified_index,
        }
    )
    timeline = _web_attack_timeline_entries(
        index,
        initial,
        attacker_ip,
        params,
        t_start,
        t_end,
        timeline_source_types,
        simplified_index,
    )
    relevant_hosts = {str(h) for h in exec_hosts if h}
    if initial:
        for value in (initial.get("host"), initial.get("target_ip")):
            if value:
                relevant_hosts.add(str(value))
    for stage in network_stages + lateral_chain:
        for value in (stage.get("host"), stage.get("source_host")):
            if value:
                relevant_hosts.add(str(value))
    timeline.extend(
        _dns_context_timeline_entries(
            index,
            params,
            scenarios,
            t_start,
            t_end,
            timeline_source_types,
            simplified_index,
            relevant_hosts,
        )
    )
    timeline.extend(
        _syslog_context_timeline_entries(
            index,
            params,
            t_start,
            t_end,
            timeline_source_types,
            simplified_index,
            relevant_hosts,
        )
    )
    for s in attack_chain:
        refs = s.get("evidence_refs", [])
        entry = {
            "timestamp": s.get("timestamp"),
            "stage": s.get("stage"),
            "host": s.get("host"),
            "description": s.get("description"),
            "raw_behavior": _stage_raw_behavior(s, index),
            "mitre_id": s.get("mitre_id"),
            "evidence_refs": refs,
            "join_ids": s.get("join_ids", []),
        }
        for field in (
            "primary_evidence_refs",
            "supporting_evidence_refs",
            "attempt_timestamp",
            "confirmed_timestamp",
            "execution_target_host",
            "execution_target_hosts",
            "execution_remote_user",
            "dns_query",
            "dns_answer",
            "dst_ip",
            "dst_port",
        ):
            if field in s:
                entry[field] = s[field]
        if timeline_source_types:
            entry["source_coverage"] = build_source_coverage(
                refs,
                simplified_index,
                timeline_source_types,
            )
        timeline.append(entry)
    timeline = _dedupe_timeline(timeline)

    hyp_policy = policy_block("hypotheses")
    hypotheses = []
    if initial and not execution and not matrix_supports_exec(correlation):
        hypotheses.append(
            {
                "text": "存在 WEB 入口迹象，但未发现 matrix/heuristic 主机执行关联",
                "confidence": float(hyp_policy.get("initial_no_exec") or 0.5),
            }
        )
    if execution and not lateral_chain and not has_lateral_matrix and not has_lateral_exec:
        hypotheses.append(
            {
                "text": "已发现主机执行/下载行为，但未发现 SSH Accepted 或 matrix 横向 join",
                "confidence": float(hyp_policy.get("exec_no_lateral") or 0.6),
            }
        )
    for gap in correlation.get("data_gaps") or []:
        if gap.startswith("no_match:"):
            hypotheses.append(
                {
                    "text": f"关联缺口：{gap}",
                    "confidence": float(hyp_policy.get("data_gap") or 0.45),
                }
            )
    if suspected:
        for s in suspected:
            hypotheses.append(
                {
                    "text": s["description"],
                    "confidence": s.get("confidence", float(hyp_policy.get("suspected_default") or 0.55)),
                }
            )

    gap_impact = list(dict.fromkeys(data_gaps))
    if ssh_partial and lateral_chain:
        gap_impact.append("横向结论基于部分 SSH 覆盖，需标注「至少」")

    summary_parts = []
    if initial:
        summary_parts.append(
            f"攻击者 {initial.get('attacker_ip')} 于 {initial['timestamp'][:19]} 命中 {initial['host']}"
        )
    if execution:
        summary_parts.append(f"在 {initial['host'] if initial else '主机'} 上发现 {len(execution)} 条执行/下载行为")
    if network_stages:
        dns_count = sum(1 for s in network_stages if s.get("dns_query"))
        if dns_count:
            summary_parts.append(f"发现 {dns_count} 条 DNS/网络关联记录")
    if lateral_chain:
        targets = ", ".join(lat["host"] for lat in lateral_chain)
        prefix = "至少横向至" if ssh_partial else "横向至"
        summary_parts.append(f"{prefix} {targets}")
    cov = join_cov.get("coverage_ratio")
    if cov is not None and join_cov.get("recommended_join_count"):
        summary_parts.append(
            f"matrix 关联覆盖 {join_cov.get('matched_join_count')}/{join_cov.get('recommended_join_count')} 条 join"
        )
    summary = "；".join(summary_parts) + "。" if summary_parts else "证据不足，无法还原攻击链。"

    matched_pattern = resolve_matched_pattern(
        payload,
        attack_chain,
        patterns,
        index=index,
        cmd_text_fn=cmd_text,
    )
    mitre_full = build_trace_mitre_attack(
        attack_chain=attack_chain,
        initial=initial,
        matched_pattern=matched_pattern,
        index=index,
        cmd_text_fn=cmd_text,
    )
    mitre_attack = {
        "techniques": mitre_full.get("techniques") or [],
        "tactics": mitre_full.get("tactics") or [],
        "technique_ids": mitre_full.get("technique_ids") or [],
        "tactic_ids": mitre_full.get("tactic_ids") or [],
    }

    from host_risk_summary import build_host_high_risk_summaries  # noqa: E402

    summary_hosts = [str(a.get("host") or "") for a in impacted if a.get("host")]
    if initial and initial.get("host"):
        summary_hosts.append(str(initial["host"]))
    host_high_risk_summary = build_host_high_risk_summaries(
        index,
        hosts=list(dict.fromkeys(summary_hosts)),
        zh=True,
    )

    resolved_attacker = attacker_ip or (initial.get("attacker_ip") if initial else None)
    attacker_ip_resolution = build_attacker_ip_resolution(
        params,
        resolved_attacker,
        initial,
        payload.get("data_access"),
    )
    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    from attacker_ip_intel import build_attacker_ip_profile  # noqa: E402

    online_intel = payload.get("ip_intel_online")
    if online_intel is None:
        online_intel = params.get("ip_intel_online") is not False
    attacker_ip_profile = build_attacker_ip_profile(
        resolved_attacker,
        bundles,
        params,
        online_lookup=bool(online_intel),
    )

    return {
        "alert_type": "traceability_analysis",
        "scenario": scenarios,
        "overall_verdict": verdict,
        "confidence": confidence,
        "confidence_ceiling": ceiling,
        "blocked": False,
        "block_reason": "",
        "summary": summary,
        "initial_access": initial,
        "data_access": payload.get("data_access") or {},
        "attacker_ip_resolution": attacker_ip_resolution,
        "attacker_ip_profile": attacker_ip_profile,
        "attack_chain": attack_chain,
        "lateral_movement_graph": {"nodes": graph_nodes, "edges": g_edges},
        "impacted_assets": impacted,
        "host_high_risk_summary": host_high_risk_summary,
        "lateral_findings": {
            "confirmed": [l for l in lateral_chain if l.get("lateral_class") == "confirmed_lateral"],
            "likely": [l for l in lateral_chain if l.get("lateral_class") == "likely_lateral"],
            "suspected": [l for l in lateral_chain if l.get("lateral_class") == "suspected_lateral"] + suspected,
            "unknown": [{"reason": g} for g in data_gaps if "ssh" in g.lower()],
        },
        "timeline": timeline,
        "timeline_source_types": timeline_source_types,
        "hypotheses": hypotheses,
        "data_gaps_impact": gap_impact,
        "correlation": correlation,
        "join_edges": correlation.get("join_edges") or [],
        "join_coverage": join_cov,
        "correlation_anchor_pattern": correlation.get("anchor_pattern_id"),
        "correlation_anchor_patterns": correlation.get("anchor_pattern_ids"),
        "correlation_recommended_chain": correlation.get("recommended_chain"),
        "correlation_contract": contract.get("correlation_contract"),
        "anchor_patterns": contract.get("anchor_patterns"),
        "correlation_fetch_plan": payload.get("correlation_fetch_plan") or [],
        "host_registry": {
            "source": "dataasset/hosts",
            "injected_host_ids": injected_host_ids,
            "inventory_count": len(bundles.get("asset_inventory") or []),
        },
        "recommended_actions": recommended_actions(impacted, verdict),
        "matched_pattern": matched_pattern,
        "mitre_attack": mitre_attack,
        "mitre_attack_by_stage": mitre_full.get("by_stage") or [],
        "mitre_attack_rule_keys": mitre_full.get("rule_keys") or [],
        "top_mitre_techniques": format_mitre_attack_short(mitre_attack),
        "evidence_index": {
            ref: {
                "bundle": ev["_bundle"],
                "timestamp": ev.get("timestamp"),
                "host": ev.get("host"),
                "raw_behavior": raw_behavior_text(ev),
            }
            for ref, ev in index.items()
        },
    }
