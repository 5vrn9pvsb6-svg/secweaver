"""Shared fetch statistics for SecWeaver Skills — JSON + Markdown reporting."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from normalizer import normalize_ip

ATTACKER_IP_FIELDS = (
    "src_ip",
    "ip",
    "remote_addr",
    "client_ip",
    "source_ip",
    "sourceIPAddress",
)
EVENT_TIME_FIELDS = (
    "timestamp",
    "@timestamp",
    "time",
    "event_time",
    "time_local",
    "__time__",
    "ts",
    "created_at",
)


def _bundle_event_counts(payload: dict[str, Any]) -> dict[str, int]:
    """Count events by asset_type from evidence_bundles / correlated_evidence."""
    by_type: dict[str, int] = {}
    bundles = dict(payload.get("evidence_bundles") or {})
    correlated = payload.get("correlated_evidence") or {}
    for key, events in {**bundles, **correlated}.items():
        if key in by_type:
            continue
        by_type[str(key)] = len(events or [])

    primary = payload.get("primary_alerts") or []
    if primary and "waf_alert" not in by_type:
        by_type["waf_alert"] = len(primary)
    elif primary and by_type.get("waf_alert", 0) < len(primary):
        by_type["waf_alert"] = len(primary)

    return by_type


def _iter_bundle_events(payload: dict[str, Any]) -> list[tuple[str, list[dict[str, Any]]]]:
    bundles = dict(payload.get("evidence_bundles") or {})
    correlated = payload.get("correlated_evidence") or {}
    groups: dict[str, list[dict[str, Any]]] = {**bundles, **correlated}
    if payload.get("primary_alerts") and "waf_alert" not in groups:
        groups["waf_alert"] = list(payload.get("primary_alerts") or [])
    return [(str(key), list(events or [])) for key, events in groups.items()]


def _normalize_ip(value: Any) -> str | None:
    """Compatibility wrapper for the shared source-IP normalizer."""
    return normalize_ip(value)


def _event_matches_attacker_ip(event: dict[str, Any], attacker_ip: str) -> bool:
    for field in ATTACKER_IP_FIELDS:
        if _normalize_ip(event.get(field)) == attacker_ip:
            return True
    return False


def _parse_event_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 10_000_000_000:
            ts = ts / 1000.0
        try:
            return datetime.fromtimestamp(ts).astimezone()
        except (OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return _parse_event_time(int(text))
    normalized = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _event_time(event: dict[str, Any]) -> datetime | None:
    for field in EVENT_TIME_FIELDS:
        parsed = _parse_event_time(event.get(field))
        if parsed:
            return parsed
    return None


def _time_sort_key(value: datetime) -> float:
    if value.tzinfo is None:
        return value.timestamp()
    return value.astimezone().timestamp()


def summarize_attacker_ip_log_time_range(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return first/last event timestamp for the requested attacker IP."""
    params = payload.get("params") or {}
    raw_ip = params.get("attacker_ip") or params.get("src_ip") or params.get("ip")
    attacker_ip = _normalize_ip(raw_ip)
    if not attacker_ip:
        return None

    event_count = 0
    timestamped: list[tuple[datetime, str]] = []
    source_bundles: list[str] = []
    for bundle_type, events in _iter_bundle_events(payload):
        matched_in_bundle = False
        for event in events:
            if not isinstance(event, dict):
                continue
            if not _event_matches_attacker_ip(event, attacker_ip):
                continue
            event_count += 1
            matched_in_bundle = True
            ts = _event_time(event)
            if ts:
                timestamped.append((ts, bundle_type))
        if matched_in_bundle and bundle_type not in source_bundles:
            source_bundles.append(bundle_type)

    if not event_count:
        return {
            "attacker_ip": attacker_ip,
            "event_count": 0,
            "timestamped_event_count": 0,
            "source_bundles": [],
        }

    result: dict[str, Any] = {
        "attacker_ip": attacker_ip,
        "event_count": event_count,
        "timestamped_event_count": len(timestamped),
        "source_bundles": source_bundles,
    }
    if timestamped:
        timestamped.sort(key=lambda item: _time_sort_key(item[0]))
        first_seen, first_bundle = timestamped[0]
        last_seen, last_bundle = timestamped[-1]
        result.update(
            {
                "first_seen": first_seen.isoformat(),
                "last_seen": last_seen.isoformat(),
                "first_seen_asset_type": first_bundle,
                "last_seen_asset_type": last_bundle,
            }
        )
    return result


def _distinct_asset_ids(payload: dict[str, Any]) -> list[str]:
    assets: set[str] = set()
    for aid in payload.get("asset_ids") or []:
        assets.add(str(aid))
    data_access = payload.get("data_access") or {}
    for aid in data_access.get("fetch_asset_ids") or data_access.get("asset_ids") or []:
        assets.add(str(aid))
    plan = payload.get("correlation_fetch_plan") or data_access.get("correlation_fetch_plan") or []
    for task in plan:
        aid = task.get("asset_id")
        if aid:
            assets.add(str(aid))
    return sorted(assets)


def _truncated_asset_types(by_type: dict[str, int], params: dict[str, Any], attempts: list[dict]) -> list[str]:
    """Use per-query truncation metadata; merged totals are not page lengths.

    Legacy offline payloads without explicit flags retain the limit heuristic.
    A partial/failed query remains a query-integrity gap, not proof of truncation.
    """
    observed = {str(a["asset_type"]) for a in attempts if a.get("asset_type") and "truncated" in a}
    truncated = {str(a["asset_type"]) for a in attempts if a.get("asset_type") and a.get("truncated")}
    limit = params.get("limit")
    if limit is None:
        return sorted(truncated)
    try:
        cap = int(limit)
    except (TypeError, ValueError):
        return sorted(truncated)
    return sorted(truncated | {asset_type for asset_type, count in by_type.items()
                              if asset_type not in observed and cap > 0 and count >= cap})


def _retained_event_counts_by_asset(payload: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for _asset_type, events in _iter_bundle_events(payload):
        for event in events:
            if not isinstance(event, dict):
                continue
            asset_id = str(event.get("_source_asset_id") or "").strip()
            if asset_id:
                counts[asset_id] = counts.get(asset_id, 0) + 1
    return counts


def _asset_fetch_stats(
    payload: dict[str, Any],
    by_type: dict[str, int],
) -> list[dict[str, Any]]:
    attempts = list((payload.get("data_access") or {}).get("fetch_attempts") or [])
    if not attempts:
        return []

    retained_by_asset = _retained_event_counts_by_asset(payload)
    grouped: dict[str, dict[str, Any]] = {}
    for attempt in attempts:
        asset_id = str(attempt.get("asset_id") or "").strip()
        if not asset_id:
            continue
        row = grouped.setdefault(
            asset_id,
            {
                "asset_id": asset_id,
                "asset_type": str(attempt.get("asset_type") or ""),
                "request_count": 0,
                "query_count": 0,
                "successful_query_count": 0,
                "failed_query_count": 0,
                "dry_run_query_count": 0,
                "cache_hit_count": 0,
                "truncated_query_count": 0,
                "cumulative_fetched_events": 0,
                "templates": [],
            },
        )
        row["request_count"] += 1
        status = str(attempt.get("status") or "unknown")
        if status == "success":
            row["query_count"] += 1
            row["successful_query_count"] += 1
        elif status == "failed":
            row["query_count"] += 1
            row["failed_query_count"] += 1
        elif status == "dry_run":
            row["dry_run_query_count"] += 1
        elif status == "cache_hit":
            row["cache_hit_count"] += 1
        if attempt.get("truncated"):
            row["truncated_query_count"] += 1
        if status == "success":
            try:
                row["cumulative_fetched_events"] += int(attempt.get("returned_event_count") or 0)
            except (TypeError, ValueError):
                pass
        template_id = str(attempt.get("template_id") or "").strip()
        if template_id and template_id not in row["templates"]:
            row["templates"].append(template_id)

    assets_by_type: dict[str, list[str]] = {}
    for asset_id, row in grouped.items():
        assets_by_type.setdefault(str(row.get("asset_type") or ""), []).append(asset_id)

    evidence_filter = (
        ((payload.get("data_access") or {}).get("attacker_ip_window_narrowing") or {}).get(
            "evidence_filter"
        )
        or {}
    )
    filtered_by_asset = evidence_filter.get("dropped_by_asset_id") or {}
    filtered_by_type = evidence_filter.get("dropped_by_asset_type") or {}

    for asset_id, row in grouped.items():
        asset_type = str(row.get("asset_type") or "")
        retained = retained_by_asset.get(asset_id)
        if retained is None and len(assets_by_type.get(asset_type) or []) == 1:
            retained = int(by_type.get(asset_type, 0))
        row["final_event_count"] = retained
        if retained is None:
            row["duplicate_or_filtered_count"] = None
            row["deduplicated_count"] = None
            row["window_filtered_count"] = None
        else:
            removed = max(
                0,
                int(row["cumulative_fetched_events"]) - retained,
            )
            window_filtered = filtered_by_asset.get(asset_id)
            if window_filtered is None and len(assets_by_type.get(asset_type) or []) == 1:
                window_filtered = filtered_by_type.get(asset_type, 0)
            try:
                window_filtered = min(removed, max(0, int(window_filtered or 0)))
            except (TypeError, ValueError):
                window_filtered = 0
            row["window_filtered_count"] = window_filtered
            row["deduplicated_count"] = max(0, removed - window_filtered)
            row["duplicate_or_filtered_count"] = removed
        row["fetch_request_count"] = row["request_count"]
        row["fetch_count"] = row["query_count"]
        row["successful_fetch_count"] = row["successful_query_count"]
        row["failed_fetch_count"] = row["failed_query_count"]
        row["fetched_event_count"] = row["cumulative_fetched_events"]
        row["retained_event_count"] = row["final_event_count"]
    return sorted(grouped.values(), key=lambda row: row["asset_id"])


def _query_integrity(payload: dict[str, Any]) -> dict[str, Any]:
    """Describe observed query gaps without claiming unqueried data is complete.

    Cached partial responses remain incomplete. Preserve evidence for positive
    findings, while preventing a clean transport status from implying coverage.
    """
    attempts = (payload.get("data_access") or {}).get("fetch_attempts") or []
    gaps = []
    for attempt in attempts:
        reasons = list(attempt.get("incomplete_reasons") or [])
        if attempt.get("status") == "failed":
            reasons.append("query_failed")
        if attempt.get("truncated"):
            reasons.append("truncated")
        if attempt.get("partial"):
            reasons.append("partial_response")
        if reasons:
            gaps.append({"asset_id": attempt.get("asset_id"), "connector_id": attempt.get("connector_id"),
                         "reasons": sorted(set(reasons))})
    observed = any(item.get("status") in {"success", "cache_hit", "failed"} for item in attempts)
    access = payload.get("data_access") or {}
    if access.get("fetch_mode") == "live":
        # Planned/executed metadata can include skipped assets. Actual attempts
        # are authoritative; absence of a request is not a clean empty response.
        attempted = {item.get("asset_id") for item in attempts}
        for asset_id in sorted(set(access.get("declared_asset_ids") or []) - attempted):
            gaps.append({"asset_id": asset_id, "connector_id": None,
                         "reasons": ["not_queried"]})
    return {"status": "incomplete" if gaps else "no_known_gaps" if observed else "unknown",
            "incomplete_queries": gaps,
            "absence_is_not_evidence": bool(gaps)}


def _evidence_readiness(payload: dict[str, Any], counts: dict[str, int], integrity: dict) -> dict:
    """Describe observed evidence separately from static registry readiness.

    Presence is not a detection result or proof of full collection. Requirements
    come from the existing precheck; never invent evidence or alter its legacy
    registry score, which downstream callers may use as a confidence ceiling.
    """
    missing = []
    for requirement in (payload.get("completeness_precheck") or {}).get("requirements_evaluated") or []:
        if requirement.get("priority") != "P0":
            continue
        types = requirement.get("asset_types") or [requirement.get("asset_type")]
        types = [value for value in types if value]
        if types and not any(counts.get(value, 0) for value in types):
            missing.append({"requirement_id": requirement.get("requirement_id"), "asset_types": types})
    total = sum(counts.values())
    mode = (payload.get("data_access") or {}).get("fetch_mode")
    live = mode == "live"
    if total:
        status = "partial" if missing or integrity["status"] == "incomplete" else "evidence_observed"
    else:
        evidence_supplied = mode not in {"dry_run", "plan_only"} and payload.get("evidence_bundles") is not None
        status = "no_evidence" if live or evidence_supplied else "not_evaluated"
    return {"status": status, "event_count": total,
            "missing_required_evidence": missing, "query_status": integrity["status"],
            "assessment_basis": "returned_events_and_query_attempts",
            "does_not_establish_skill_coverage": True}


def _analysis_constraints(
    fetch_mode: str | None,
    readiness: dict[str, Any],
    integrity: dict[str, Any],
) -> dict[str, Any]:
    """Translate transport/readiness state into a common conclusion boundary.

    Positive evidence remains usable even when another query fails. Negative
    conclusions require observed evidence and no known query gaps; plan/dry-run
    output is never evidence. The ceiling is advisory because each Skill owns
    the meaning of its domain-specific confidence value.
    """
    readiness_status = str(readiness.get("status") or "not_evaluated")
    integrity_status = str(integrity.get("status") or "unknown")
    event_count = int(readiness.get("event_count") or 0)
    if fetch_mode in {"plan_only", "dry_run"}:
        scope = "planning_only"
        ceiling = 0.0
    elif fetch_mode == "live" and integrity_status == "incomplete":
        scope = "partial_live_evidence"
        ceiling = 0.65
    elif fetch_mode == "live" and readiness_status == "no_evidence":
        scope = "queried_window_no_events"
        ceiling = 0.35
    elif fetch_mode == "live":
        scope = "observed_live_evidence"
        ceiling = 1.0
    else:
        scope = "supplied_evidence_only"
        ceiling = 0.85 if event_count else 0.0
    negative_allowed = bool(
        fetch_mode == "live"
        and integrity_status == "no_known_gaps"
        and readiness_status == "evidence_observed"
    )
    return {
        "scope": scope,
        "positive_findings_allowed": event_count > 0,
        "negative_conclusion_allowed": negative_allowed,
        "absence_is_not_evidence": not negative_allowed,
        "recommended_confidence_ceiling": ceiling,
    }


def summarize_fetch(payload: dict[str, Any]) -> dict[str, Any]:
    """Build fetch_summary from a skill payload (post-fetch or pass-through input)."""
    by_type = _bundle_event_counts(payload)
    total = sum(by_type.values())
    params = payload.get("params") or {}
    data_access = payload.get("data_access") or {}
    fetch_mode = data_access.get("fetch_mode")
    plan = payload.get("correlation_fetch_plan") or data_access.get("correlation_fetch_plan") or []
    asset_ids = _distinct_asset_ids(payload)
    declared_asset_ids = data_access.get("declared_asset_ids") or payload.get("asset_ids") or []
    fetch_asset_ids = data_access.get("fetch_asset_ids") or data_access.get("asset_ids") or asset_ids
    planned_asset_ids = data_access.get("planned_asset_ids") or (
        [
            str(task.get("asset_id"))
            for task in plan
            if task.get("asset_id")
        ]
        if fetch_mode == "plan_only"
        else []
    )
    if fetch_mode == "plan_only":
        executed_asset_ids = []
    else:
        executed_asset_ids = data_access.get("executed_asset_ids") or [
            str(task.get("asset_id"))
            for task in plan
            if task.get("asset_id")
        ] or fetch_asset_ids
    skipped_assets = data_access.get("skipped_assets") or []
    asset_fetch_stats = _asset_fetch_stats(payload, by_type)
    queried_asset_types = {
        str(row.get("asset_type") or "")
        for row in asset_fetch_stats
        if row.get("asset_type")
    }
    non_connector_by_asset_type = {
        asset_type: count
        for asset_type, count in by_type.items()
        if asset_type not in queried_asset_types and count
    }

    integrity = _query_integrity(payload)
    readiness = _evidence_readiness(payload, by_type, integrity)
    return {
        "fetched_at": datetime.now().astimezone().isoformat(),
        "query_integrity": integrity,
        "evidence_readiness": readiness,
        "analysis_constraints": _analysis_constraints(fetch_mode, readiness, integrity),
        "total_events": total,
        "total_fetched_events": sum(
            int(row.get("cumulative_fetched_events") or 0)
            for row in asset_fetch_stats
        ),
        "total_fetch_queries": sum(int(row.get("query_count") or 0) for row in asset_fetch_stats),
        "total_fetch_requests": sum(int(row.get("request_count") or 0) for row in asset_fetch_stats),
        "total_fetch_cache_hits": sum(int(row.get("cache_hit_count") or 0) for row in asset_fetch_stats),
        "total_deduplicated_events": sum(
            int(row.get("deduplicated_count") or 0) for row in asset_fetch_stats
        ),
        "total_window_filtered_events": sum(
            int(row.get("window_filtered_count") or 0) for row in asset_fetch_stats
        ),
        "failed_fetch_queries": sum(int(row.get("failed_query_count") or 0) for row in asset_fetch_stats),
        "non_connector_event_count": sum(non_connector_by_asset_type.values()),
        "non_connector_by_asset_type": non_connector_by_asset_type,
        "by_asset_type": by_type,
        "asset_fetch_stats": asset_fetch_stats,
        "asset_count": len(asset_ids),
        "asset_ids": asset_ids or None,
        "declared_asset_ids": declared_asset_ids or None,
        "fetch_asset_ids": fetch_asset_ids or None,
        "planned_asset_ids": planned_asset_ids or None,
        "executed_asset_ids": executed_asset_ids or None,
        "skipped_assets": skipped_assets,
        "skipped_asset_count": len(skipped_assets),
        "primary_alert_count": len(payload.get("primary_alerts") or []),
        "fetch_mode": fetch_mode,
        "fetch_strategy": data_access.get("fetch_strategy"),
        "bundle_id": payload.get("bundle_id") or data_access.get("bundle_id"),
        "plan_task_count": len(plan) if plan else data_access.get("plan_task_count", 0),
        "time_window": {
            "time_start": params.get("time_start"),
            "time_end": params.get("time_end"),
            "alert_time": params.get("alert_time"),
            "attacker_ip": params.get("attacker_ip") or params.get("src_ip"),
            "target_ip": params.get("target_ip"),
        },
        "attacker_ip_log_time_range": summarize_attacker_ip_log_time_range(payload),
        "truncated_asset_types": _truncated_asset_types(by_type, params, data_access.get("fetch_attempts") or []),
    }


def attach_fetch_summary(payload: dict[str, Any]) -> dict[str, Any]:
    """Attach observed query quality alongside the registry completeness precheck.

    Do not discard positive evidence or invent a confidence penalty. An incomplete
    query is an explicit data gap, even when registered source coverage is ready.
    """
    has_fetch = bool(
        payload.get("evidence_bundles")
        or payload.get("correlated_evidence")
        or payload.get("data_access")
        or payload.get("primary_alerts")
    )
    if has_fetch:
        payload["fetch_summary"] = summarize_fetch(payload)
        integrity = payload["fetch_summary"]["query_integrity"]
        if payload.get("completeness_precheck"):
            precheck = dict(payload["completeness_precheck"])
            precheck["assessment_basis"] = "registry_metadata"
            precheck["metadata_readiness"] = {
                key: precheck.get(key) for key in ("overall_verdict", "confidence", "next_skill_blocked")
            }
            precheck["evidence_readiness"] = payload["fetch_summary"]["evidence_readiness"]
            precheck["query_integrity"] = integrity
            precheck["analysis_constraints"] = payload["fetch_summary"]["analysis_constraints"]
            gaps = list(precheck.get("data_gaps") or [])
            # Reconcile our derived flag after a pre-fetch summary. Preserve
            # unrelated gaps and unknown states; only observed success clears it.
            if integrity["status"] == "no_known_gaps":
                gaps = [gap for gap in gaps if gap != "query_results_incomplete"]
            if integrity["status"] == "incomplete" and "query_results_incomplete" not in gaps:
                gaps.append("query_results_incomplete")
            precheck["data_gaps"] = gaps
            payload["completeness_precheck"] = precheck
    return payload


def format_fetch_summary_markdown(
    summary: dict[str, Any] | None,
    *,
    heading: str = "## 数据取数统计",
) -> str:
    """Render fetch_summary as a Markdown section for skill reports."""
    if not summary:
        return f"{heading}\n\n_未执行 live 取数或未传入 evidence_bundles_\n"

    lines = [heading, ""]
    readiness = summary.get("evidence_readiness") or {}
    if readiness:
        lines.append(f"- **实际证据 / Evidence readiness**: `{readiness.get('status')}`；资产注册评分不代表本次证据完整或技能可运行。Registry readiness does not establish runtime coverage.")
        for requirement in readiness.get("missing_required_evidence") or []:
            lines.append(f"  - P0 evidence absent: `{requirement.get('requirement_id')}` ({', '.join(requirement.get('asset_types') or [])})")
    integrity = summary.get("query_integrity") or {}
    if integrity.get("status") == "incomplete":
        lines.append("- **取数不完整 / Incomplete query results**：存在未查询、超时、失败或截断；不得以未检出事件排除威胁。Absence of returned events cannot rule out a threat.")
        for gap in integrity.get("incomplete_queries") or []:
            lines.append(f"  - `{gap.get('asset_id')}` / `{gap.get('connector_id')}`: {', '.join(gap.get('reasons') or [])}")
    constraints = summary.get("analysis_constraints") or {}
    if constraints and not constraints.get("negative_conclusion_allowed", False):
        lines.append(
            "- **结论边界 / Conclusion boundary**：当前证据可支持已观察到的正向发现，"
            "但不得用未返回事件排除风险。"
        )
    mode = summary.get("fetch_mode") or "—"
    strategy = summary.get("fetch_strategy") or "—"
    lines.append(f"- **取数模式**: {mode} / {strategy}")

    bundle_id = summary.get("bundle_id")
    if bundle_id:
        lines.append(f"- **资产包**: `{bundle_id}`")

    asset_ids = summary.get("asset_ids") or []
    declared_asset_ids = summary.get("declared_asset_ids") or []
    fetch_asset_ids = summary.get("fetch_asset_ids") or asset_ids
    planned_asset_ids = summary.get("planned_asset_ids") or []
    executed_asset_ids = summary.get("executed_asset_ids") or []
    asset_count = summary.get("asset_count", len(asset_ids))
    if declared_asset_ids:
        shown = ", ".join(f"`{a}`" for a in declared_asset_ids[:8])
        if len(declared_asset_ids) > 8:
            shown += f" … 共 {len(declared_asset_ids)} 个声明资产"
        lines.append(f"- **声明资产**: {shown}")
    if fetch_asset_ids:
        shown = ", ".join(f"`{a}`" for a in fetch_asset_ids[:8])
        if len(fetch_asset_ids) > 8:
            shown += f" … 共 {len(fetch_asset_ids)} 个取数资产"
        lines.append(f"- **涉及资产**: {shown}")
    elif asset_count:
        lines.append(f"- **涉及资产数**: {asset_count}")
    if executed_asset_ids:
        shown = ", ".join(f"`{a}`" for a in executed_asset_ids[:8])
        if len(executed_asset_ids) > 8:
            shown += f" … 共 {len(executed_asset_ids)} 个执行资产"
        lines.append(f"- **实际执行查询资产**: {shown}")
    elif planned_asset_ids:
        shown = ", ".join(f"`{a}`" for a in planned_asset_ids[:8])
        if len(planned_asset_ids) > 8:
            shown += f" … 共 {len(planned_asset_ids)} 个计划资产"
        lines.append(f"- **计划查询资产**: {shown}")

    tw = summary.get("time_window") or {}
    if tw.get("time_start") or tw.get("time_end"):
        lines.append(f"- **时间窗**: {tw.get('time_start', '—')} ~ {tw.get('time_end', '—')}")
    if tw.get("attacker_ip"):
        lines.append(f"- **攻击源 IP**: {tw.get('attacker_ip')}")
    if tw.get("target_ip"):
        lines.append(f"- **受害 target_ip**: {tw.get('target_ip')}")
    if tw.get("alert_time"):
        lines.append(f"- **锚定告警时间**: {tw.get('alert_time')}")
    ip_range = summary.get("attacker_ip_log_time_range") or {}
    if ip_range:
        if ip_range.get("first_seen") or ip_range.get("last_seen"):
            lines.append(
                "- **该 IP 日志时间范围**: "
                f"{ip_range.get('first_seen', '—')} ~ {ip_range.get('last_seen', '—')} "
                f"（匹配 {ip_range.get('event_count', 0)} 条，"
                f"带时间戳 {ip_range.get('timestamped_event_count', 0)} 条，"
                f"来源 {', '.join(f'`{v}`' for v in ip_range.get('source_bundles') or []) or '—'}）"
            )
        else:
            lines.append(
                "- **该 IP 日志时间范围**: "
                f"未在已取日志中找到匹配 `{ip_range.get('attacker_ip')}` 的带时间戳事件 "
                f"（匹配 {ip_range.get('event_count', 0)} 条）"
            )

    lines.append(f"- **总事件数（最终保留）**: {summary.get('total_events', 0)}")
    if summary.get("asset_fetch_stats"):
        lines.append(f"- **累计拉取事件数（含重复）**: {summary.get('total_fetched_events', 0)}")
        lines.append(f"- **实际查询次数**: {summary.get('total_fetch_queries', 0)}")
        if summary.get("total_fetch_cache_hits"):
            lines.append(
                f"- **查询复用**: {summary.get('total_fetch_cache_hits', 0)} 次缓存命中 / "
                f"{summary.get('total_fetch_requests', 0)} 次取数请求"
            )
        if summary.get("failed_fetch_queries"):
            lines.append(f"- **失败查询次数**: {summary.get('failed_fetch_queries', 0)}")
    non_connector_by_type = summary.get("non_connector_by_asset_type") or {}
    if non_connector_by_type:
        detail = ", ".join(
            f"`{asset_type}`: {count}"
            for asset_type, count in sorted(non_connector_by_type.items())
        )
        lines.append(
            f"- **非 connector 拉取证据**: {summary.get('non_connector_event_count', 0)} "
            f"（{detail}；例如资产注册表注入）"
        )
    if summary.get("primary_alert_count"):
        lines.append(f"- **WAF 主告警数**: {summary['primary_alert_count']}")

    plan_count = summary.get("plan_task_count") or 0
    if plan_count:
        lines.append(f"- **关联取数任务**: {plan_count} 条")

    truncated = summary.get("truncated_asset_types") or []
    if truncated:
        lines.append(f"- **可能触顶 limit**: {', '.join(f'`{t}`' for t in truncated)}")
    skipped_assets = summary.get("skipped_assets") or []
    if skipped_assets:
        shown = ", ".join(
            f"`{item.get('asset_id')}`({item.get('reason', 'skipped')})"
            for item in skipped_assets[:8]
        )
        if len(skipped_assets) > 8:
            shown += f" … 共 {len(skipped_assets)} 个未执行资产"
        lines.append(f"- **声明但未执行查询**: {shown}")

    by_type = summary.get("by_asset_type") or {}
    by_asset = summary.get("asset_fetch_stats") or []
    if by_asset:
        lines.extend(
            [
                "",
                "### 按数据资产（拉取次数与数据量）",
                "",
                "| 数据资产 | asset_type | 取数请求 / 实际查询 / 缓存命中 | 成功 / 失败 | 拉取数据 | 保留数据 | 去重 | 窗口过滤 |",
                "|---|---|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for row in by_asset:
            retained = row.get("final_event_count")
            deduplicated = row.get("deduplicated_count")
            window_filtered = row.get("window_filtered_count")
            lines.append(
                f"| `{row.get('asset_id')}` | `{row.get('asset_type') or '—'}` | "
                f"{row.get('request_count', row.get('query_count', 0))} / "
                f"{row.get('query_count', 0)} / {row.get('cache_hit_count', 0)} | "
                f"{row.get('successful_query_count', 0)} / {row.get('failed_query_count', 0)} | "
                f"{row.get('cumulative_fetched_events', 0)} | "
                f"{retained if retained is not None else '—'} | "
                f"{deduplicated if deduplicated is not None else '—'} | "
                f"{window_filtered if window_filtered is not None else '—'} |"
            )
    if by_type:
        lines.extend(["", "### 按 asset_type", ""])
        for asset_type, count in sorted(by_type.items(), key=lambda x: (-x[1], x[0])):
            lines.append(f"- `{asset_type}`: {count}")
    else:
        lines.extend(["", "_本窗口无事件_", ""])

    return "\n".join(lines)


def enrich_result_with_fetch_summary(result: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """Copy fetch quality and its conclusion boundary onto one Skill output."""
    summary = payload.get("fetch_summary") or summarize_fetch(payload)
    if summary.get("total_events") or summary.get("fetch_mode") or payload.get("data_access"):
        result["fetch_summary"] = summary
        if summary.get("analysis_constraints"):
            result["analysis_constraints"] = dict(summary["analysis_constraints"])
    return result
