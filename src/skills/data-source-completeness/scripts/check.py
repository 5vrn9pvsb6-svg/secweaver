#!/usr/bin/env python3
"""SecWeaver 数据源完整性分析 — 确定性评估脚本。

读取 JSON 输入（调查意图、场景、已注册资产），输出完整性评估 JSON。
Agent Skill 可调用此脚本，也可由 AI 按 SKILL.md 自行研判。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SCENARIOS_PATH = Path(__file__).resolve().parent.parent / "scenarios.json"
DATA_ACCESS_PATH = Path(__file__).resolve().parents[2] / "_shared" / "data-access"
if str(DATA_ACCESS_PATH) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS_PATH))

from field_inventory import check_required_fields, effective_fields, canonical_fields  # noqa: E402
from correlation_engine import anchor_pattern_for_scenarios, resolve_anchor_params  # noqa: E402

PARTIAL_COVERAGE = {"partial", "partial_internal", "partial_web", "jump_hosts", "target_hosts"}
FULL_COVERAGE = {"full", "web_zone", "web_hosts", "internal_ssh", "dmz_to_internal", "internal", "any"}

# Scenario coverage hints → asset zone tokens that satisfy fully / partially
HINT_ZONE_FULL = {
    "any": set(),  # special-cased
    "full": {"full"},
    "web_zone": {"web_zone", "web_hosts", "dmz"},
    "web_hosts": {"web_hosts", "web_zone"},
    "internal_ssh": {"internal_ssh", "internal"},
    "internal": {"internal", "internal_ssh"},
    "dmz_to_internal": {"dmz_to_internal"},
    "jump_hosts": {"jump_hosts", "internal", "internal_ssh"},
    "target_hosts": {"target_hosts", "internal", "internal_ssh"},
}

HINT_ZONE_PARTIAL = {
    "web_zone": {"dmz_to_internal"},
    "web_hosts": {"web_zone", "partial_web"},
    "internal_ssh": {"partial_internal", "partial"},
    "internal": {"partial_internal", "partial"},
    "dmz_to_internal": {"dmz"},
    "jump_hosts": {"partial_internal", "partial", "web_zone"},
    "target_hosts": {"partial_internal", "partial"},
}


def _investigation_hosts(params: dict) -> set[str]:
    hosts = params.get("hosts") or []
    if isinstance(hosts, str):
        hosts = [hosts]
    single = params.get("host")
    if single:
        hosts = list(hosts) + [single]
    return {str(h).strip() for h in hosts if h not in (None, "")}


def normalize_asset_coverage(asset: dict) -> dict[str, set[str]]:
    """Parse asset coverage into zones / apps / hosts."""
    detail = asset.get("coverage_detail")
    if isinstance(detail, dict):
        return {
            "zones": {str(x) for x in detail.get("zones") or []},
            "apps": {str(x) for x in detail.get("apps") or []},
            "hosts": {str(x) for x in detail.get("hosts") or []},
        }

    raw = asset.get("coverage")
    zones: set[str] = set()
    apps: set[str] = set()
    hosts: set[str] = set()

    if isinstance(raw, dict):
        zones = {str(x) for x in raw.get("zones") or []}
        apps = {str(x) for x in raw.get("apps") or []}
        hosts = {str(x) for x in raw.get("hosts") or []}
    elif isinstance(raw, list):
        for item in raw:
            token = str(item).strip()
            if not token or token in ("none", ""):
                continue
            if token in FULL_COVERAGE or token in PARTIAL_COVERAGE or token.startswith("partial"):
                zones.add(token)
            elif token in ("portal", "api-gateway") or token.endswith("_gateway"):
                apps.add(token)
            else:
                # Flat list convention: unknown tokens are hostnames (web-01, db-01)
                hosts.add(token)
    elif raw not in (None, ""):
        zones.add(str(raw))

    return {"zones": zones, "apps": apps, "hosts": hosts}


def _hosts_cover_investigation(asset_hosts: set[str], inv_hosts: set[str]) -> bool:
    if not inv_hosts:
        return bool(asset_hosts)
    if not asset_hosts:
        return False
    return inv_hosts.issubset(asset_hosts)


def _hosts_overlap(asset_hosts: set[str], inv_hosts: set[str]) -> bool:
    if not inv_hosts:
        return bool(asset_hosts)
    return bool(asset_hosts & inv_hosts)


def match_coverage_hint(hint: str, asset: dict, params: dict | None = None) -> str:
    """Return full | partial | none | unknown for scenario coverage hint vs asset."""
    params = params or {}
    hint = (hint or "any").strip()
    cov = normalize_asset_coverage(asset)
    zones, hosts = cov["zones"], cov["hosts"]
    inv_hosts = _investigation_hosts(params)

    if not zones and not hosts and not cov["apps"]:
        return "none"

    if hint == "any":
        return "full"

    if hint == "full":
        return "full" if "full" in zones else "none"

    if hint == "web_hosts":
        if "web_hosts" in zones:
            return "full"
        if "web_zone" in zones and _hosts_cover_investigation(hosts, inv_hosts):
            return "full"
        if hosts and not zones and _hosts_cover_investigation(hosts, inv_hosts):
            return "full"
        if "web_zone" in zones or hosts:
            return "partial"
        if zones & HINT_ZONE_FULL.get("web_zone", set()):
            return "partial"
        return "none"

    if hint == "web_zone" and hosts and not (zones & HINT_ZONE_FULL["web_zone"]):
        # A legacy host list proves some web coverage, but not the whole zone.
        return "partial"

    if hint in ("jump_hosts", "target_hosts"):
        # An explicit target set is the assessment boundary, not a zone-wide
        # claim. When hosts are enumerated, broad zone labels must not inflate
        # a partial or disjoint host list to full coverage.
        if hosts and inv_hosts:
            if inv_hosts.issubset(hosts):
                return "full"
            return "partial" if hosts & inv_hosts else "none"
        if hint in zones:
            return "full"
        if zones & {"internal", "internal_ssh"} and _hosts_overlap(hosts, inv_hosts):
            return "full"
        if zones & HINT_ZONE_PARTIAL.get(hint, set()) or zones & {"internal", "internal_ssh"}:
            return "partial"
        return "none"

    if hint in ("internal_ssh", "internal") and hosts:
        if _hosts_cover_investigation(hosts, inv_hosts):
            return "full"
        return "partial"

    full_tokens = HINT_ZONE_FULL.get(hint, set())
    partial_tokens = HINT_ZONE_PARTIAL.get(hint, set())

    if zones & full_tokens:
        if hint in ("internal_ssh", "internal") and "partial_internal" in zones and not (
            zones & {"internal", "internal_ssh"}
        ):
            return "partial"
        return "full"

    if zones & partial_tokens:
        return "partial"

    return "none"


def coverage_ok(asset: dict, hint: str, params: dict | None = None) -> str:
    """Match scenario coverage hint against asset zones/hosts (and optional investigation hosts)."""
    return match_coverage_hint(hint, asset, params)


def load_scenarios(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def infer_scenarios(intent: str, catalog: dict) -> list[str]:
    if not intent:
        return []
    found: list[str] = []
    for sid, meta in catalog["scenarios"].items():
        for kw in meta.get("keywords", []):
            if kw.lower() in intent.lower() or kw in intent:
                found.append(sid)
                break
    return list(dict.fromkeys(found))


def merge_requirements(scenario_ids: list[str], catalog: dict) -> list[dict]:
    merged: dict[str, dict] = {}
    for sid in scenario_ids:
        for req in catalog["scenarios"][sid]["requirements"]:
            rid = req["id"]
            if rid not in merged:
                merged[rid] = deepcopy(req)
                merged[rid]["scenarios"] = [sid]
            else:
                merged[rid]["scenarios"].append(sid)
    return list(merged.values())


def asset_type_aliases(asset: dict) -> list[str]:
    aliases: list[str] = []
    for value in [asset.get("type"), *(asset.get("covers_asset_types") or [])]:
        if value and str(value) not in aliases:
            aliases.append(str(value))
    return aliases


def assets_by_type(registered: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for asset in registered:
        if asset.get("status") == "not_registered":
            continue
        for t in asset_type_aliases(asset):
            out.setdefault(t, []).append(asset)
    return out


def fields_ok(asset: dict, required: list[str]) -> tuple[bool, list[str]]:
    return check_required_fields(asset, required)


def retention_ok(asset: dict, params: dict) -> bool:
    days = asset.get("retention_days")
    if days is None:
        return True
    start = params.get("time_start")
    end = params.get("time_end")
    if not start:
        return True
    try:
        t0 = datetime.fromisoformat(start.replace("Z", "+00:00"))
        if end:
            t1 = datetime.fromisoformat(end.replace("Z", "+00:00"))
        else:
            t1 = datetime.now(t0.tzinfo)
        span = (t1 - t0).days + 1
        return days >= span
    except ValueError:
        return True


def evaluate_requirement(req: dict, by_type: dict[str, list[dict]], params: dict) -> dict:
    types = req["asset_types"]
    match_mode = req.get("match", "all")
    candidates: list[tuple[str, dict, str, list[str]]] = []

    for atype in types:
        for asset in by_type.get(atype, []):
            req_fields = req["required_fields"].get(atype, [])
            ok, missing = fields_ok(asset, req_fields)
            cov = coverage_ok(asset, req.get("coverage", "any"), params)
            ret_ok = retention_ok(asset, params)
            if ok and cov != "none" and ret_ok:
                status = "ready" if cov == "full" else "partial"
            elif by_type.get(atype):
                gaps = []
                if not ok:
                    gaps.extend(missing)
                if cov == "none":
                    gaps.append("coverage_none")
                elif cov == "partial":
                    gaps.append("coverage_partial")
                if not ret_ok:
                    gaps.append("retention_insufficient")
                status = "partial"
            else:
                continue
            candidates.append((status, asset, cov, missing if not ok else []))

    if match_mode == "any":
        if not candidates:
            return {
                "requirement_id": req["id"],
                "label": req["label"],
                "priority": req["priority"],
                "status": "missing",
                "asset_types": types,
                "gaps": ["not_registered"],
            }
        order = {"ready": 0, "partial": 1, "missing": 2}
        best = min(candidates, key=lambda x: order.get(x[0], 9))
        status, asset, cov, field_gaps = best
        gaps = list(field_gaps)
        if cov == "partial":
            gaps.append("coverage_partial")
        elif cov == "none":
            gaps.append("coverage_none")
        return {
            "requirement_id": req["id"],
            "label": req["label"],
            "priority": req["priority"],
            "status": status,
            "asset_id": asset.get("asset_id"),
            "asset_type": asset.get("type"),
            "coverage": cov,
            "gaps": gaps,
        }

    # match all — need every type (rare); treat as single type requirement
    atype = types[0]
    assets = by_type.get(atype, [])
    if not assets:
        return {
            "requirement_id": req["id"],
            "label": req["label"],
            "priority": req["priority"],
            "status": "missing",
            "asset_types": types,
            "gaps": ["not_registered"],
        }
    asset = assets[0]
    req_fields = req["required_fields"].get(atype, [])
    ok, missing = fields_ok(asset, req_fields)
    cov = coverage_ok(asset, req.get("coverage", "any"), params)
    ret_ok = retention_ok(asset, params)
    gaps: list[str] = []
    if not ok:
        gaps.extend(missing)
    if cov == "none":
        gaps.append("coverage_none")
    elif cov == "partial":
        gaps.append("coverage_partial")
    if not ret_ok:
        gaps.append("retention_insufficient")

    if ok and cov == "full" and ret_ok:
        status = "ready"
    elif assets:
        status = "partial"
    else:
        status = "missing"

    return {
        "requirement_id": req["id"],
        "label": req["label"],
        "priority": req["priority"],
        "status": status,
        "asset_id": asset.get("asset_id"),
        "asset_type": atype,
        "coverage": cov,
        "gaps": gaps,
    }


def count_by_priority(evaluated: list[dict], priority: str, status: str) -> int:
    return sum(1 for e in evaluated if e["priority"] == priority and e["status"] == status)


def total_by_priority(evaluated: list[dict], priority: str) -> int:
    return sum(1 for e in evaluated if e["priority"] == priority)


def compute_confidence(evaluated: list[dict], key_score: float, time_score: float) -> float:
    p0_t = total_by_priority(evaluated, "P0") or 1
    p1_t = total_by_priority(evaluated, "P1") or 1
    p0_r = count_by_priority(evaluated, "P0", "ready") / p0_t
    p1_r = (count_by_priority(evaluated, "P1", "ready") + 0.5 * count_by_priority(evaluated, "P1", "partial")) / p1_t
    c = 0.40 * p0_r + 0.35 * p1_r + 0.15 * key_score + 0.10 * time_score
    return round(min(max(c, 0.0), 1.0), 2)


def correlation_key_score(by_type: dict[str, list[dict]], catalog: dict) -> float:
    keys_present: set[str] = set()
    key_map = {
        "src_ip": [
            "waf_alert",
            "web_access_log",
            "syslog_risk_alert",
            "ssh_auth",
            "firewall_log",
            "network_traffic_audit",
            "vpn_auth",
            "dns_log",
        ],
        "host": [
            "host_exec",
            "host_connect",
            "host_file_op",
            "host_persistence",
            "host_process",
			"host_socket",
			"host_identity",
			"host_service",
			"host_kernel_context",
            "syslog_risk_alert",
            "ssh_auth",
            "edr_event",
            "windows_event_log",
            "linux_syslog",
            "dns_log",
        ],
        "timestamp": [
            "waf_alert",
            "web_access_log",
            "host_exec",
            "host_persistence",
            "host_process",
			"host_socket",
			"host_identity",
			"host_service",
			"host_kernel_context",
            "syslog_risk_alert",
            "ssh_auth",
            "firewall_log",
            "network_traffic_audit",
            "dns_log",
        ],
        "user": ["syslog_risk_alert", "ssh_auth", "vpn_auth", "host_identity", "host_socket"],
        "pid": ["host_exec", "host_connect", "host_persistence", "host_process", "host_socket"],
    }
    for key, types in key_map.items():
        for t in types:
            for asset in by_type.get(t, []):
                corr = set(asset.get("correlation_keys") or [])
                if key in corr:
                    keys_present.add(key)
                    break
    n = len(keys_present)
    if n >= 4:
        return 1.0
    if n >= 3:
        return 0.7
    return 0.4


def build_recommendations(missing: list[dict], catalog: dict) -> list[dict]:
    recs: list[dict] = []
    rank = 1
    seen: set[str] = set()
    priority_order = {"P0": 0, "P1": 1, "P2": 2}

    items = sorted(missing, key=lambda x: priority_order.get(x["priority"], 9))
    for item in items:
        label = item["label"]
        if label in seen:
            continue
        seen.add(label)
        atype = (item.get("asset_types") or [item.get("asset_type")])[0]
        if isinstance(atype, list):
            atype = atype[0]
        hint = catalog["collection_hints"].get(atype, "按平台资产注册向导接入")
        impact = catalog["impact_templates"].get(atype, f"缺少 {label}，相关调查结论置信度下降")
        recs.append(
            {
                "rank": rank,
                "source_name": label,
                "priority": item["priority"],
                "asset_type": atype,
                "reason": f"场景需要 {label} 支撑关联分析与溯源",
                "impact_if_missing": impact,
                "collection_hint": hint,
                "expected_gain": f"补齐后可支撑 {label} 相关调查环节",
            }
        )
        rank += 1
    return recs


def overall_verdict(
    evaluated: list[dict], scenarios: list[str], by_type: dict[str, list[dict]]
) -> tuple[str, bool, bool, bool]:
    p0_missing = [e for e in evaluated if e["priority"] == "P0" and e["status"] == "missing"]
    p0_ready = all(e["status"] in ("ready", "partial") for e in evaluated if e["priority"] == "P0")
    p1_total = total_by_priority(evaluated, "P1")
    p1_ready = count_by_priority(evaluated, "P1", "ready")
    p1_partial = count_by_priority(evaluated, "P1", "partial")

    has_d2 = any(by_type.get(t) for t in ("host_exec", "host_connect", "host_file_op", "host_persistence", "edr_event"))
    has_d1 = any(by_type.get(t) for t in ("waf_alert", "web_access_log"))

    if p0_missing:
        return "not_traceable", False, False, True

    if "S4" in scenarios and not has_d2:
        if has_d1 and not has_d2:
            return "alert_triage_only", False, False, "S4" in scenarios and not p0_missing

    if p0_ready and p1_total > 0 and (p1_ready + p1_partial * 0.5) / p1_total >= 0.8:
        return "full_traceable", True, has_d2, False

    if p0_ready:
        return "partial_traceable", True, has_d2, False

    return "not_traceable", False, False, True


def can_confirm_breach(
    scenarios: list[str], by_type: dict[str, list[dict]], verdict: str
) -> bool:
    breach_scenarios = {"S1", "S2", "S4"}
    has_d1 = any(by_type.get(t) for t in ("waf_alert", "web_access_log"))
    has_d2 = any(
        by_type.get(t)
        for t in ("host_exec", "host_connect", "host_file_op", "host_persistence", "edr_event")
    )
    return bool(breach_scenarios.intersection(scenarios)) and has_d1 and has_d2 and verdict in (
        "full_traceable",
        "partial_traceable",
    )


def dns_capability_notes(
    evaluated: list[dict], scenarios: list[str], by_type: dict[str, list[dict]]
) -> list[dict[str, str]]:
    """Explain DNS coverage boundaries for trace/C2/exfil scenarios."""
    scoped = {"S1", "S3", "S7", "S8"}.intersection(scenarios)
    if not scoped:
        return []
    has_dns = bool(by_type.get("dns_log"))
    network_asset_types = {"firewall_log", "network_traffic_audit", "proxy_log"}
    missing_or_partial_network = [
        e
        for e in evaluated
        if e.get("priority") in {"P0", "P1"}
        and e.get("status") != "ready"
        and network_asset_types.intersection(set(e.get("asset_types") or [e.get("asset_type") or ""]))
    ]
    if not has_dns and not missing_or_partial_network:
        return []
    notes: list[dict[str, str]] = []
    if has_dns:
        notes.append(
            {
                "type": "dns_boundary",
                "severity": "info",
                "message": "DNS 查询日志已参与域名/C2/DGA 解释，但不能替代 firewall/NTA/proxy 的会话路径、方向、字节数和代理动作证据。",
            }
        )
    if missing_or_partial_network:
        labels = ", ".join(dict.fromkeys(str(e.get("label")) for e in missing_or_partial_network))
        notes.append(
            {
                "type": "partial_traceability_boundary",
                "severity": "warning",
                "message": f"S1/S3/S7/S8 仍受网络侧证据缺口限制：{labels}；DNS 只能补充域名解析，不能单独证明完整链路或外传体量。",
            }
        )
    return notes


def pick_next_skill(scenarios: list[str], catalog: dict, blocked: bool) -> str:
    if blocked:
        return catalog["next_skill_map"].get(scenarios[0], "traceability_analysis")
    for sid in scenarios:
        if sid in catalog["next_skill_map"]:
            return catalog["next_skill_map"][sid]
    return "traceability_analysis"


def enrich_registered_assets(registered: list[dict]) -> list[dict]:
    from correlation_keys import derive_correlation_keys

    out: list[dict] = []
    for asset in registered:
        item = dict(asset)
        if not item.get("correlation_keys"):
            pseudo = {
                "asset_id": item.get("asset_id"),
                "asset_type": item.get("type"),
                "schema": {
                    "fields": item.get("fields") or [],
                    "time_field": item.get("time_field") or "timestamp",
                },
            }
            item["correlation_keys"] = derive_correlation_keys(pseudo)
        out.append(item)
    return out


def assess(payload: dict, catalog: dict) -> dict:
    intent = payload.get("investigation_intent", "")
    scenarios = payload.get("scenarios") or infer_scenarios(intent, catalog)
    if not scenarios:
        scenarios = ["S1"]

    params = payload.get("params") or {}
    pid = anchor_pattern_for_scenarios(scenarios)
    if pid:
        params = resolve_anchor_params(pid, params)
    registered = enrich_registered_assets(payload.get("registered_assets") or [])
    by_type = assets_by_type(registered)

    requirements = merge_requirements(scenarios, catalog)
    evaluated = [evaluate_requirement(r, by_type, params) for r in requirements]

    key_score = correlation_key_score(by_type, catalog)
    time_score = 1.0
    if any("retention_insufficient" in e.get("gaps", []) for e in evaluated):
        time_score = 0.6

    verdict, can_trace, _has_d2, blocked = overall_verdict(evaluated, scenarios, by_type)
    confidence = compute_confidence(evaluated, key_score, time_score)
    if key_score < 0.7:
        confidence = min(confidence, 0.75)

    missing_critical = [
        {
            "source_name": e["label"],
            "priority": e["priority"],
            "requirement_id": e["requirement_id"],
            "impact_if_missing": catalog["impact_templates"].get(
                (e.get("asset_types") or [e.get("asset_type") or "host_exec"])[0],
                f"缺少 {e['label']}",
            ),
        }
        for e in evaluated
        if e["status"] == "missing" and e["priority"] in ("P0", "P1")
    ]

    missing_for_rec = [e for e in evaluated if e["status"] in ("missing", "partial") and e["priority"] != "P2"]
    recommendations = build_recommendations(missing_for_rec, catalog)

    scenario_names = [catalog["scenarios"][s]["name"] for s in scenarios if s in catalog["scenarios"]]
    p0_missing_labels = [e["label"] for e in evaluated if e["priority"] == "P0" and e["status"] == "missing"]

    if verdict == "not_traceable":
        summary = f"缺少关键数据源（{', '.join(p0_missing_labels) or 'P0 未满足'}），当前无法完整溯源。"
    elif verdict == "alert_triage_only":
        summary = "仅有 WEB/WAF 类数据，可做告警分类，无法确认攻击是否成功或打穿。"
    elif verdict == "partial_traceable":
        summary = "P0 数据源基本齐全，但部分 P1 缺失，溯源结论置信度受限。"
    else:
        summary = "数据源满足当前调查场景，可启动下游溯源或确认 Skill。"

    next_skill = pick_next_skill(scenarios, catalog, blocked)
    block_reason = ""
    if blocked and p0_missing_labels:
        block_reason = f"缺少 P0 数据源: {', '.join(p0_missing_labels)}"

    capability_notes = dns_capability_notes(evaluated, scenarios, by_type)

    registered_sources = []
    for asset in registered:
        if asset.get("status") == "not_registered":
            continue
        registered_sources.append(
            {
                "asset_id": asset.get("asset_id"),
                "name": asset.get("name", asset.get("asset_id")),
                "type": asset.get("type"),
                "domain": asset.get("domain"),
                "coverage": asset.get("coverage"),
                "fields": asset.get("fields", []),
                "canonical_fields": sorted(canonical_fields(asset) - set(asset.get("fields", []))),
                "effective_fields": sorted(effective_fields(asset)),
                "correlation_keys": asset.get("correlation_keys", []),
            }
        )

    return {
        "alert_type": "data_source_completeness",
        "scenario": scenarios,
        "scenario_summary": " + ".join(scenario_names),
        "investigation_params": params,
        "overall_verdict": verdict,
        "confidence": confidence,
        "can_trace": can_trace,
        "can_confirm_breach": can_confirm_breach(scenarios, by_type, verdict),
        "summary": summary,
        "requirements_evaluated": evaluated,
        "registered_sources": registered_sources,
        "missing_critical": missing_critical,
        "recommendations": recommendations,
        "capability_notes": capability_notes,
        "correlation_key_score": key_score,
        "next_skill": next_skill,
        "next_skill_blocked": blocked,
        "block_reason": block_reason,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="SecWeaver 数据源完整性分析")
    parser.add_argument("-i", "--input", help="输入 JSON 文件路径；省略则从 stdin 读取")
    parser.add_argument("-o", "--output", help="输出 JSON 文件路径；省略则打印到 stdout")
    parser.add_argument(
        "--scenarios",
        default=str(SCENARIOS_PATH),
        help="scenarios.json 路径",
    )

    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    # Payload adaptation belongs to the upper runtime, not the fetch layer.
    sys.path.insert(0, str(DATA_ACCESS_PATH.parent))
    from skill_runtime.contracts import ensure_skill_envelope
    from skill_runtime.inputs import add_bundle_arguments, build_completeness_payload, load_input_payload

    add_bundle_arguments(parser, "completeness")
    args = parser.parse_args()

    scenarios_path = Path(args.scenarios)
    if not scenarios_path.exists():
        print(f"scenarios.json not found: {scenarios_path}", file=sys.stderr)
        return 1

    catalog = load_scenarios(scenarios_path)

    try:
        payload = load_input_payload(args, "completeness", build_completeness_payload)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 1

    result = assess(payload, catalog)
    ensure_skill_envelope(result, "data-source-completeness")
    out = json.dumps(result, ensure_ascii=False, indent=2)

    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
