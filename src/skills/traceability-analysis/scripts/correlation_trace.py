"""Traceability correlation contract: anchor-patterns + correlation-matrix.

Resolves investigation scenarios into anchor patterns, runs recommended join
chains, builds attack-chain stages from join_edges, and reports join coverage.
Heuristic logic in correlate.py supplements gaps only — matrix joins are primary.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Any

DATA_ACCESS_PATH = Path(__file__).resolve().parents[2] / "_shared" / "data-access"
REPO_ROOT = Path(__file__).resolve().parents[4]
if str(DATA_ACCESS_PATH) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS_PATH))

from correlation_engine import (  # noqa: E402
    anchor_pattern_for_scenarios,
    build_host_ip_map,
    get_anchor_pattern,
    get_join,
    get_join_trace_stage,
    join_ids_for_trace_stage,
    load_anchor_patterns,
    load_matrix,
    load_scenario_priority,
    parse_ts,
    resolve_anchor_params,
    run_recommended_chain,
)
from heuristic_rules import lateral_join_ids, ssh_lateral_confirmed  # noqa: E402
from dataasset_paths import DATAASSET_ROOT  # noqa: E402
from traceability_analysis.common import (  # noqa: E402
    web_event_gateway_host,
    web_event_request_outcome,
    web_event_url,
    web_event_victim_host,
)

try:
    from host_normalize import remote_execution_context, victim_host_from_event  # noqa: E402
except ImportError:
    def victim_host_from_event(ev: dict[str, Any], host_ip_map: dict[str, str] | None = None) -> str | None:  # type: ignore[misc]
        return str(ev.get("host") or ev.get("host_name") or "") or None

    def remote_execution_context(command: str, source_host: str | None = None) -> dict[str, Any]:  # type: ignore[misc]
        return {}

ANCHOR_PATTERNS_PATH = DATAASSET_ROOT / "scenarios" / "anchor-patterns.json"
CORRELATION_MATRIX_PATH = DATAASSET_ROOT / "assets" / "correlation-matrix.json"


def _report_path(path: Path | str) -> str:
    """Use checkout-independent paths for report-facing correlation metadata."""
    candidate = Path(path)
    try:
        return candidate.resolve().relative_to(REPO_ROOT).as_posix()
    except (OSError, ValueError):
        return candidate.as_posix()

def _heuristic_lateral_joins() -> frozenset[str]:
    try:
        return lateral_join_ids()
    except FileNotFoundError:
        return frozenset({"lateral_from_exec", "lateral_from_syslog", "lateral_from_target_exec"})


def _ssh_lateral_confirmed(ev: dict[str, Any]) -> bool:
    try:
        return ssh_lateral_confirmed(ev)
    except FileNotFoundError:
        result = str(ev.get("result") or "").lower()
        if result in {"failed", "failure", "denied", "invalid"} or "fail" in result:
            return False
        if result in {"accepted", "success", "successful"} or "accept" in result:
            return True
        event_type = str(ev.get("event_type") or "").lower()
        if event_type in {"ssh_login_failed", "auth_failure", "ssh_invalid_user", "ssh_auth_attempts_exceeded"}:
            return False
        return event_type == "ssh_login_success"


def anchor_patterns_for_trace(
    scenarios: list[str],
    *,
    anchor_pattern_id: str | None = None,
) -> list[str]:
    """All anchor patterns matching trace scenarios (S1+S3 → both chains)."""
    if anchor_pattern_id:
        return [anchor_pattern_id]
    patterns = load_anchor_patterns()
    scenario_set = set(scenarios or [])
    result: list[str] = []
    seen: set[str] = set()
    for sid, pid in load_scenario_priority():
        if sid in scenario_set and pid in patterns and pid not in seen:
            result.append(pid)
            seen.add(pid)
    if not result and scenarios:
        single = anchor_pattern_for_scenarios(scenarios)
        if single:
            result.append(single)
    return result


def resolve_trace_contract(
    payload: dict[str, Any],
    *,
    anchor_pattern_id: str | None = None,
) -> dict[str, Any]:
    """Resolve params, anchor patterns, and matrix metadata for traceability."""
    scenarios = list(payload.get("scenarios") or ["S1", "S3"])
    params = dict(payload.get("params") or {})
    pattern_ids = anchor_patterns_for_trace(scenarios, anchor_pattern_id=anchor_pattern_id)

    resolved_params = dict(params)
    for pid in pattern_ids:
        resolved_params = resolve_anchor_params(pid, resolved_params)

    matrix = load_matrix()
    patterns_meta = []
    for pid in pattern_ids:
        pat = get_anchor_pattern(pid) or {}
        patterns_meta.append(
            {
                "anchor_pattern_id": pid,
                "label": pat.get("label"),
                "investigation_window": pat.get("investigation_window"),
                "recommended_chain": list(pat.get("recommended_chain") or []),
                "bundle_id": pat.get("bundle_id"),
            }
        )

    primary = pattern_ids[0] if pattern_ids else None
    if not pattern_ids:
        primary = anchor_pattern_for_scenarios(scenarios)

    return {
        "scenarios": scenarios,
        "params": resolved_params,
        "anchor_pattern_ids": pattern_ids,
        "correlation_anchor_pattern": primary,
        "anchor_patterns": patterns_meta,
        "correlation_contract": {
            "anchor_patterns_path": _report_path(ANCHOR_PATTERNS_PATH),
            "correlation_matrix_path": _report_path(CORRELATION_MATRIX_PATH),
            "matrix_version": matrix.get("version"),
            "anchor_patterns_version": _file_version(ANCHOR_PATTERNS_PATH),
        },
    }


def _file_version(path: Path) -> str | None:
    if not path.is_file():
        return None
    import json

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return str(data.get("version") or "")
    except (OSError, json.JSONDecodeError):
        return None


def _edge_key(edge: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(edge.get("join_id") or ""),
        str(edge.get("left_ref") or ""),
        str(edge.get("right_ref") or ""),
    )


def correlate_for_trace(
    bundles: dict[str, list[dict[str, Any]]],
    *,
    scenarios: list[str],
    params: dict[str, Any],
    anchor_pattern_id: str | None = None,
) -> dict[str, Any]:
    """Run recommended_chain for each trace anchor pattern; merge join_edges."""
    pattern_ids = anchor_patterns_for_trace(scenarios, anchor_pattern_id=anchor_pattern_id)
    if not pattern_ids:
        return {
            "anchor_pattern_id": None,
            "anchor_pattern_ids": [],
            "recommended_chain": [],
            "recommended_chains": {},
            "join_edges": [],
            "data_gaps": ["no anchor_pattern for scenarios"],
            "join_coverage": {},
        }

    merged_edges: list[dict[str, Any]] = []
    merged_gaps: list[str] = []
    chains_by_pattern: dict[str, list[str]] = {}
    seen_edges: set[tuple[str, str, str]] = set()
    seen_gaps: set[str] = set()

    for pid in pattern_ids:
        result = run_recommended_chain(pid, bundles, params=params)
        chains_by_pattern[pid] = list(result.get("recommended_chain") or [])
        for edge in result.get("join_edges") or []:
            key = _edge_key(edge)
            if key not in seen_edges:
                seen_edges.add(key)
                merged_edges.append(edge)
        for gap in result.get("data_gaps") or []:
            if gap not in seen_gaps:
                seen_gaps.add(gap)
                merged_gaps.append(gap)

    all_chain: list[str] = []
    seen_joins: set[str] = set()
    for pid in pattern_ids:
        for join_id in chains_by_pattern.get(pid) or []:
            if join_id not in seen_joins:
                seen_joins.add(join_id)
                all_chain.append(join_id)

    coverage = compute_join_coverage(all_chain, merged_edges, merged_gaps)

    return {
        "anchor_pattern_id": pattern_ids[0],
        "anchor_pattern_ids": pattern_ids,
        "recommended_chain": all_chain,
        "recommended_chains": chains_by_pattern,
        "join_edges": merged_edges,
        "data_gaps": merged_gaps,
        "join_coverage": coverage,
    }


def compute_join_coverage(
    recommended_chain: list[str],
    join_edges: list[dict[str, Any]],
    data_gaps: list[str],
) -> dict[str, Any]:
    """Per join_id: matched | no_match | not_evaluated."""
    matched_ids = {str(e.get("join_id")) for e in join_edges}
    gap_ids = set()
    for gap in data_gaps:
        if gap.startswith("no_match:"):
            gap_ids.add(gap.split(":", 1)[1].split(" ", 1)[0])

    per_join: dict[str, str] = {}
    for join_id in recommended_chain:
        if join_id in matched_ids:
            per_join[join_id] = "matched"
        elif join_id in gap_ids:
            per_join[join_id] = "no_match"
        else:
            per_join[join_id] = "not_evaluated"

    total = len(recommended_chain)
    matched = sum(1 for v in per_join.values() if v == "matched")
    return {
        "recommended_join_count": total,
        "matched_join_count": matched,
        "coverage_ratio": round(matched / total, 2) if total else 0.0,
        "per_join": per_join,
    }


def _event_host(ev: dict[str, Any], host_ip_map: dict[str, str] | None = None) -> str:
    return str(victim_host_from_event(ev, host_ip_map) or ev.get("host") or ev.get("host_name") or ev.get("hostname") or "unknown")


def dedupe_lateral_stages(stages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse repeated lateral rows; likely/confirmed dedupe by src→dst pair only."""
    seen: set[tuple[str, ...]] = set()
    out: list[dict[str, Any]] = []
    for stage in sorted(stages, key=lambda x: x.get("timestamp") or ""):
        if stage.get("stage") != "lateral_movement":
            out.append(stage)
            continue
        lat_class = str(stage.get("lateral_class") or "")
        if lat_class in {"likely_lateral", "confirmed_lateral"}:
            key = (
                str(stage.get("source_host") or ""),
                str(stage.get("host") or ""),
                lat_class,
            )
        else:
            key = (
                str(stage.get("source_host") or ""),
                str(stage.get("host") or ""),
                str(stage.get("user") or ""),
                lat_class,
            )
        if key in seen:
            continue
        seen.add(key)
        out.append(stage)
    return out


def _event_ts_iso(ev: dict[str, Any]) -> str:
    ts = parse_ts(ev.get("timestamp"))
    return ts.isoformat() if ts else str(ev.get("timestamp") or "")


def _stage_confidence(edge: dict[str, Any], base: float = 0.85) -> float:
    return round(max(base, float(edge.get("confidence") or base)), 2)


def _dns_query(ev: dict[str, Any]) -> str:
    for key in ("query", "qname", "domain", "hostname"):
        value = ev.get(key)
        if value not in (None, ""):
            return str(value).rstrip(".")
    return ""


def _dns_answer(ev: dict[str, Any]) -> str:
    for key in ("response", "answers", "resolved_ip", "answer"):
        value = ev.get(key)
        if value not in (None, ""):
            if isinstance(value, list):
                return ", ".join(str(item) for item in value)
            return str(value)
    return ""


def _dns_client(ev: dict[str, Any]) -> str:
    for key in ("client_ip", "src_ip", "host_ip", "host"):
        value = ev.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _connect_target(ev: dict[str, Any]) -> str:
    dst = str(ev.get("dst_ip") or ev.get("remote_ip") or ev.get("target_ip") or "")
    port = str(ev.get("dst_port") or ev.get("remote_port") or ev.get("target_port") or "")
    if dst and port:
        return f"{dst}:{port}"
    return dst or port


def _dns_stage_for_scenarios(trace_stage: str, scenarios: list[str] | None) -> str:
    """DNS proximity supplies network context, regardless of investigation intent.

    A scenario or a legacy matrix stage is not evidence of C2 or exfiltration.
    """
    return "network_activity"


def build_stages_from_join_edges(
    join_edges: list[dict[str, Any]],
    index: dict[str, dict],
    patterns: dict[str, Any],
    *,
    matrix: dict[str, Any] | None = None,
    scenarios: list[str] | None = None,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Build initial_access + attack_chain stages from matrix join_edges."""
    matrix = matrix or load_matrix()
    mitre = patterns.get("stage_mitre_defaults", {})
    initial: dict[str, Any] | None = None
    stages: list[dict[str, Any]] = []
    seen_stage_keys: set[tuple[str, str, str]] = set()

    def explicit_web_target(ev: dict[str, Any]) -> str | None:
        if not any(ev.get(key) for key in ("target_ip", "upstream_addr", "upstream_host", "dst_ip")):
            return None
        return web_event_victim_host(ev)

    def add_stage(
        stage: str,
        ev: dict[str, Any],
        *,
        description: str,
        refs: list[str],
        join_ids: list[str],
        confidence: float,
        extra: dict[str, Any] | None = None,
    ) -> None:
        host = _event_host(ev)
        ts = _event_ts_iso(ev)
        key = (stage, host, ts[:19])
        if key in seen_stage_keys:
            for existing in stages:
                if (existing["stage"], existing["host"], (existing.get("timestamp") or "")[:19]) == key:
                    for ref in refs:
                        if ref not in existing["evidence_refs"]:
                            existing["evidence_refs"].append(ref)
                    for jid in join_ids:
                        if jid not in existing.get("join_ids", []):
                            existing.setdefault("join_ids", []).append(jid)
                    existing["confidence"] = round(max(existing["confidence"], confidence), 2)
                    return
            return
        seen_stage_keys.add(key)
        row: dict[str, Any] = {
            "stage": stage,
            "mitre_id": "" if stage == "network_activity" else mitre.get(stage, "T1059"),
            "timestamp": ts,
            "host": host,
            "description": description,
            "evidence_refs": list(dict.fromkeys(refs)),
            "join_ids": list(dict.fromkeys(join_ids)),
            "confidence": confidence,
            "correlation_source": "matrix",
        }
        if extra:
            row.update(extra)
        stages.append(row)

    def refine_initial_from_web_event(web_ev: dict[str, Any], refs: list[str], join_ids: list[str]) -> None:
        if not initial or not web_ev:
            return
        victim_host = web_event_victim_host(web_ev)
        url = web_event_url(web_ev) or web_ev.get("url") or web_ev.get("path")
        if victim_host:
            previous_host = str(initial.get("host") or "")
            raw_web_host = str(web_ev.get("host") or web_ev.get("hostname") or web_ev.get("dst_host") or "")
            if not initial.get("target_ip") or not previous_host or previous_host == "unknown" or previous_host == raw_web_host:
                initial["host"] = victim_host
            initial["target_ip"] = victim_host
        if url and (not initial.get("url") or "://" not in str(initial.get("url"))):
            initial["url"] = url
        if web_ev.get("src_ip") or web_ev.get("client_ip"):
            initial.setdefault("attacker_ip", web_ev.get("src_ip") or web_ev.get("client_ip"))
        for ref in refs:
            if ref and ref not in initial.setdefault("evidence_refs", []):
                initial["evidence_refs"].append(ref)
            if ref and ref not in initial.setdefault("primary_evidence_refs", []):
                supporting = initial.setdefault("supporting_evidence_refs", [])
                if ref not in supporting:
                    supporting.append(ref)
        for jid_item in join_ids:
            if jid_item and jid_item not in initial.setdefault("join_ids", []):
                initial["join_ids"].append(jid_item)

    for edge in join_edges:
        jid = str(edge.get("join_id") or "")
        trace_stage = get_join_trace_stage(jid, matrix)
        if not trace_stage or trace_stage in ("enrichment",):
            continue

        left_ref = str(edge.get("left_ref") or "")
        right_ref = str(edge.get("right_ref") or "")
        left_ev = index.get(left_ref) or {}
        right_ev = index.get(right_ref) or {}
        conf = _stage_confidence(edge)

        if trace_stage == "initial_access":
            web_ev = left_ev if left_ev.get("_bundle") in ("waf_alert", "web_access_log") else right_ev
            attacker = web_ev.get("src_ip") or web_ev.get("client_ip")
            url = web_event_url(web_ev) or web_ev.get("url") or web_ev.get("path")
            if not initial:
                primary_ref = str(web_ev.get("_ref") or left_ref or right_ref)
                all_refs = list(dict.fromkeys(ref for ref in (left_ref, right_ref) if ref))
                initial = {
                    "host": web_event_victim_host(web_ev) or _event_host(web_ev),
                    "timestamp": _event_ts_iso(web_ev),
                    "vector": "web_exploit",
                    "url": url,
                    "attacker_ip": attacker,
                    "target_ip": explicit_web_target(web_ev),
                    "gateway_host": web_event_gateway_host(web_ev),
                    "request_outcome": web_event_request_outcome(web_ev),
                    "primary_evidence_refs": [primary_ref] if primary_ref else [],
                    "supporting_evidence_refs": [ref for ref in all_refs if ref != primary_ref],
                    "evidence_refs": all_refs,
                    "join_ids": [jid],
                    "correlation_source": "matrix",
                }
            else:
                for ref in (left_ref, right_ref):
                    if ref not in initial["evidence_refs"]:
                        initial["evidence_refs"].append(ref)
                initial.setdefault("join_ids", [])
                if jid not in initial["join_ids"]:
                    initial["join_ids"].append(jid)
                refine_initial_from_web_event(web_ev, [left_ref, right_ref], [jid])

        if jid == "web_access_to_host_exec":
            web_ev = left_ev if left_ev.get("_bundle") == "web_access_log" else right_ev
            exec_ev = right_ev if right_ev.get("_bundle") == "host_exec" else left_ev
            if not initial and web_ev:
                primary_ref = str(web_ev.get("_ref") or left_ref)
                initial = {
                    "host": web_event_victim_host(web_ev) or _event_host(web_ev),
                    "timestamp": _event_ts_iso(web_ev),
                    "vector": "web_exploit",
                    "url": web_event_url(web_ev) or web_ev.get("url") or web_ev.get("path"),
                    "attacker_ip": web_ev.get("src_ip") or web_ev.get("client_ip"),
                    "target_ip": explicit_web_target(web_ev),
                    "gateway_host": web_event_gateway_host(web_ev),
                    "request_outcome": web_event_request_outcome(web_ev),
                    "primary_evidence_refs": [primary_ref] if primary_ref else [],
                    "supporting_evidence_refs": [],
                    "evidence_refs": [left_ref],
                    "join_ids": [jid],
                    "correlation_source": "matrix",
                }
            else:
                refine_initial_from_web_event(web_ev, [left_ref], [jid])
            if exec_ev:
                cmd = exec_ev.get("command")
                cmd_text = " ".join(str(c) for c in cmd) if isinstance(cmd, list) else str(cmd or "")
                remote_context = remote_execution_context(cmd_text, source_host=_event_host(exec_ev))
                add_stage(
                    "execution",
                    exec_ev,
                    description=f"matrix join {jid}: 主机 {_event_host(exec_ev)} 执行 {cmd_text[:120]}",
                    refs=[left_ref, right_ref],
                    join_ids=[jid],
                    confidence=conf,
                    extra=remote_context,
                )
            continue

        if trace_stage == "execution":
            focus = right_ev if right_ev.get("_bundle") in ("host_exec", "host_connect", "host_file_op", "host_persistence") else left_ev
            bundle = focus.get("_bundle", "")
            remote_context = (
                remote_execution_context(
                    " ".join(str(c) for c in focus.get("command"))
                    if isinstance(focus.get("command"), list)
                    else str(focus.get("command") or focus.get("command_line") or ""),
                    source_host=_event_host(focus),
                )
                if bundle == "host_exec"
                else {}
            )
            add_stage(
                "execution",
                focus,
                description=f"matrix join {jid}: {bundle} @ {_event_host(focus)}",
                refs=[left_ref, right_ref],
                join_ids=[jid],
                confidence=conf,
                extra=remote_context,
            )

        elif trace_stage == "persistence":
            focus = right_ev if right_ev.get("_bundle") == "host_persistence" else left_ev
            path = focus.get("path") or "?"
            ptype = focus.get("persistence_type") or focus.get("category") or "persistence"
            add_stage(
                "persistence",
                focus,
                description=f"matrix join {jid}: 主机 {_event_host(focus)} 持久化变更 {ptype} {path}",
                refs=[left_ref, right_ref],
                join_ids=[jid],
                confidence=conf,
            )

        elif trace_stage == "lateral_movement":
            ssh_ev = right_ev if right_ev.get("_bundle") == "ssh_auth" else left_ev
            if ssh_ev.get("_bundle") == "ssh_auth" and _ssh_lateral_confirmed(ssh_ev):
                src = ssh_ev.get("src_ip") or ""
                user = ssh_ev.get("user") or "?"
                target = _event_host(ssh_ev)
                add_stage(
                    "lateral_movement",
                    ssh_ev,
                    description=f"matrix join {jid}: SSH {src} → {target} 用户 {user}",
                    refs=[left_ref, right_ref],
                    join_ids=[jid],
                    confidence=conf,
                    extra={
                        "source_host": src,
                        "user": user,
                        "lateral_class": "confirmed_lateral",
                        "attempt_timestamp": None,
                        "confirmed_timestamp": _event_ts_iso(ssh_ev),
                    },
                )

        elif jid in {"host_connect_to_dns", "nta_session_correlation"} or trace_stage in {"network_activity", "command_and_control", "exfiltration"}:
            connect_ev = left_ev if left_ev.get("_bundle") == "host_connect" else right_ev
            dns_ev = right_ev if right_ev.get("_bundle") == "dns_log" else left_ev
            focus = dns_ev if dns_ev.get("_bundle") == "dns_log" else connect_ev
            query = _dns_query(dns_ev)
            answer = _dns_answer(dns_ev)
            client = _dns_client(dns_ev) or str(connect_ev.get("host_ip") or connect_ev.get("host") or "")
            target = _connect_target(connect_ev)
            desc_parts = [f"matrix join {jid}:"]
            if client:
                desc_parts.append(client)
            if query:
                desc_parts.append(f"resolved {query}")
            if target:
                desc_parts.append(f"near egress {target}")
            if answer:
                desc_parts.append(f"answer={answer[:120]}")
            stage_name = (
                _dns_stage_for_scenarios(trace_stage, scenarios)
                if jid in {"host_connect_to_dns", "nta_session_correlation"}
                else trace_stage
            )
            add_stage(
                stage_name,
                focus,
                description=" ".join(desc_parts),
                refs=[left_ref, right_ref],
                join_ids=[jid],
                confidence=conf,
                extra={
                    "host": client or _event_host(connect_ev),
                    "dns_query": query,
                    "dns_answer": answer,
                    "dst_ip": connect_ev.get("dst_ip"),
                    "dst_port": connect_ev.get("dst_port"),
                },
            )

    stages.sort(key=lambda x: x.get("timestamp") or "")
    return initial, dedupe_lateral_stages(stages)


def merge_initial_access(
    matrix_initial: dict[str, Any] | None,
    heuristic_initial: dict[str, Any] | None,
) -> dict[str, Any] | None:
    def normalize_evidence_groups(item: dict[str, Any]) -> dict[str, Any]:
        row = dict(item)
        all_refs = list(dict.fromkeys(str(ref) for ref in row.get("evidence_refs") or [] if ref))
        primary_refs = list(
            dict.fromkeys(str(ref) for ref in row.get("primary_evidence_refs") or [] if ref)
        )
        if not primary_refs and all_refs:
            primary_refs = [all_refs[0]]
        supporting_refs = list(
            dict.fromkeys(str(ref) for ref in row.get("supporting_evidence_refs") or [] if ref)
        )
        for ref in all_refs:
            if ref not in primary_refs and ref not in supporting_refs:
                supporting_refs.append(ref)
        row["primary_evidence_refs"] = primary_refs
        row["supporting_evidence_refs"] = supporting_refs
        row["evidence_refs"] = list(dict.fromkeys(primary_refs + supporting_refs))
        return row

    if matrix_initial and heuristic_initial:
        matrix_initial = normalize_evidence_groups(matrix_initial)
        heuristic_initial = normalize_evidence_groups(heuristic_initial)
        outcome_rank = {"success": 0, "unknown": 1, "failed": 2, "blocked": 3}
        vector_rank = {"web_exploit:rce": 0, "web_exploit:sqli": 1, "webshell": 2, "web_exploit": 3}

        def candidate_rank(item: dict[str, Any]) -> tuple[int, int, int, str]:
            source = str(item.get("correlation_source") or "")
            return (
                outcome_rank.get(str(item.get("request_outcome") or "unknown"), 1),
                vector_rank.get(str(item.get("vector") or ""), 4),
                0 if "matrix" in source else 1,
                str(item.get("timestamp") or ""),
            )

        primary, secondary = sorted(
            (matrix_initial, heuristic_initial),
            key=candidate_rank,
        )
        merged = dict(primary)
        merged["primary_evidence_refs"] = list(primary.get("primary_evidence_refs") or [])
        merged["supporting_evidence_refs"] = list(primary.get("supporting_evidence_refs") or [])
        for ref in secondary.get("evidence_refs") or []:
            if ref not in merged["primary_evidence_refs"] and ref not in merged["supporting_evidence_refs"]:
                merged["supporting_evidence_refs"].append(ref)
        merged["evidence_refs"] = list(
            dict.fromkeys(merged["primary_evidence_refs"] + merged["supporting_evidence_refs"])
        )
        merged["join_ids"] = list(primary.get("join_ids") or [])
        for join_id in secondary.get("join_ids") or []:
            if join_id not in merged["join_ids"]:
                merged["join_ids"].append(join_id)
        for key in (
            "attacker_ip",
            "target_ip",
            "gateway_host",
            "entry_point_role",
            "first_compromise_point_status",
            "selection_reason",
            "first_observed_control_url",
            "first_observed_control_timestamp",
            "first_observed_control_evidence_refs",
        ):
            if not merged.get(key) and secondary.get(key):
                merged[key] = secondary[key]

        # An inference note describes the selected candidate. Borrowing a
        # fallback candidate's note can falsely claim that WEB/WAF is absent.
        sources = {
            str(matrix_initial.get("correlation_source") or ""),
            str(heuristic_initial.get("correlation_source") or ""),
        }
        if any("matrix" in source for source in sources):
            if "victim_target_ip" in sources:
                merged["correlation_source"] = "matrix+victim_target_ip"
            elif "exec_inferred" in sources:
                merged["correlation_source"] = "matrix+exec_inferred"
            else:
                merged["correlation_source"] = "matrix+heuristic"
        return merged
    if matrix_initial:
        return normalize_evidence_groups(matrix_initial)
    if heuristic_initial:
        heuristic_initial = normalize_evidence_groups(heuristic_initial)
        src = heuristic_initial.get("correlation_source")
        if src not in ("exec_inferred", "victim_target_ip"):
            heuristic_initial["correlation_source"] = "heuristic_fallback"
        return heuristic_initial
    return None


def merge_attack_stages(
    matrix_stages: list[dict[str, Any]],
    heuristic_stages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Prefer matrix stages; add heuristic stages only when no matrix stage shares refs."""
    matrix_refs: set[str] = set()
    for stage in matrix_stages:
        matrix_refs.update(stage.get("evidence_refs") or [])

    merged = list(matrix_stages)
    for stage in heuristic_stages:
        refs = set(stage.get("evidence_refs") or [])
        if refs & matrix_refs:
            for existing in merged:
                if refs & set(existing.get("evidence_refs") or []):
                    existing["confidence"] = round(max(existing.get("confidence", 0.7), stage.get("confidence", 0.7)), 2)
                    if not existing.get("join_ids") and stage.get("join_ids"):
                        existing["join_ids"] = stage["join_ids"]
            continue
        row = dict(stage)
        row["correlation_source"] = "heuristic_fallback"
        merged.append(row)

    merged.sort(key=lambda x: x.get("timestamp") or "")
    return merged


def attach_join_ids_to_stages(
    attack_chain: list[dict[str, Any]],
    join_edges: list[dict[str, Any]],
) -> None:
    for stage in attack_chain:
        refs = set(stage.get("evidence_refs") or [])
        for edge in join_edges:
            if edge.get("left_ref") in refs or edge.get("right_ref") in refs:
                stage.setdefault("join_ids", [])
                jid = edge["join_id"]
                if jid not in stage["join_ids"]:
                    stage["join_ids"].append(jid)


def matrix_supports_exec(correlation: dict[str, Any]) -> bool:
    per_join = (correlation.get("join_coverage") or {}).get("per_join") or {}
    exec_joins = join_ids_for_trace_stage("execution")
    return any(per_join.get(jid) == "matched" for jid in exec_joins)


def matrix_supports_lateral(correlation: dict[str, Any]) -> bool:
    per_join = (correlation.get("join_coverage") or {}).get("per_join") or {}
    lateral_joins = join_ids_for_trace_stage("lateral_movement") | _heuristic_lateral_joins()
    return any(per_join.get(jid) == "matched" for jid in lateral_joins)


def plan_fetch_for_trace(
    scenarios: list[str],
    params: dict[str, Any],
    *,
    asset_ids: list[str],
    anchor_pattern_id: str | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Merge correlation fetch tasks from all trace anchor patterns."""
    from correlation_engine import plan_fetch

    pattern_ids = anchor_patterns_for_trace(scenarios, anchor_pattern_id=anchor_pattern_id)
    tasks: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for pid in pattern_ids:
        resolved = resolve_anchor_params(pid, dict(params))
        for task in plan_fetch(pid, resolved, asset_ids=asset_ids):
            key = (
                task.get("join_id"),
                task.get("template_id"),
                task.get("asset_id"),
                tuple(sorted((task.get("params") or {}).items())),
            )
            if key in seen:
                continue
            seen.add(key)
            tasks.append(task)
    return tasks, pattern_ids
