"""Batch summaries and Markdown rendering for alert confirmation."""

from __future__ import annotations

import sys
from collections import Counter
from typing import Any

from .paths import DATA_ACCESS_PATH

VIRUSTOTAL_KEY_CONFIG_HINT = (
    "请配置 VirusTotal API Key：可在运行参数传 virustotal_api_key/vt_api_key，"
    "或设置环境变量 VIRUSTOTAL_API_KEY/VT_API_KEY，"
    "或修复 ip-intel.json 中 virustotal.credentials_ref 指向的 vault 密钥。"
)


def _display_value(value: Any, default: str = "n/a") -> str:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in value) if value else default
    return str(value)


def _vt_config_hint(vt: dict[str, Any]) -> str:
    return str(
        vt.get("action_required_label")
        or vt.get("config_hint")
        or VIRUSTOTAL_KEY_CONFIG_HINT
    )


def _format_ip_profile_markdown(profile: dict[str, Any]) -> list[str]:
    if not profile:
        return []

    evidence_geo = profile.get("evidence_geo") or {}
    online = profile.get("online_lookup") or {}
    source_bundles = evidence_geo.get("source_bundles") or []
    evidence_refs = evidence_geo.get("evidence_refs") or []
    attrs = profile.get("attributes") or []
    geo_parts = [evidence_geo.get("country"), evidence_geo.get("province"), evidence_geo.get("city")]
    geo_text = " / ".join(str(v) for v in geo_parts if v) or _display_value(evidence_geo.get("geo_info"))

    lines = ["### 攻击源 IP 属性", ""]
    lines.extend(
        [
            f"- **IP**: {_display_value(profile.get('ip'))}",
            f"- **地址范围**: {_display_value(profile.get('scope'))}",
            f"- **日志地理**: {geo_text}",
            (
                "- **日志证据来源**: "
                f"bundles={_display_value(source_bundles)}; "
                f"event_count={_display_value(evidence_geo.get('event_count'))}; "
                f"evidence_refs={_display_value(evidence_refs[:10])}"
            ),
            (
                "- **在线情报来源**: "
                f"provider={_display_value(online.get('provider'))}; "
                f"status={_display_value(online.get('status'), 'not_attempted')}; "
                f"query={_display_value(online.get('query') or profile.get('ip'))}"
            ),
            (
                "- **运营商/组织/ASN**: "
                f"isp={_display_value(online.get('isp'))}; "
                f"org={_display_value(online.get('org') or online.get('as_owner'))}; "
                f"asn={_display_value(online.get('asn'))}; "
                f"as={_display_value(online.get('as'))}"
            ),
            f"- **网络段**: {_display_value(online.get('network'))}",
            (
                "- **NAT/共享出口相关字段**: "
                f"mobile={_display_value(online.get('mobile'))}; "
                f"proxy={_display_value(online.get('proxy'))}; "
                f"hosting={_display_value(online.get('hosting'))}; "
                f"tags={_display_value(online.get('tags'))}"
            ),
            f"- **属性标签**: {_display_value(attrs)}",
        ]
    )
    if online.get("provider") == "virustotal":
        stats = online.get("last_analysis_stats") or {}
        lines.append(
            "- **VirusTotal 检测**: "
            f"malicious={_display_value(stats.get('malicious'))}; "
            f"suspicious={_display_value(stats.get('suspicious'))}; "
            f"reputation={_display_value(online.get('reputation'))}"
        )
        if online.get("status") == "config_missing":
            lines.append(
                "- **VirusTotal 配置提示**: "
                f"{_vt_config_hint(online)}; "
                f"message={_display_value(online.get('message') or online.get('error'))}"
            )
    vt = ((profile.get("threat_intel") or {}).get("virustotal") or {})
    if vt and vt is not online:
        stats = vt.get("last_analysis_stats") or {}
        lines.append(
            "- **VirusTotal 信息**: "
            f"provider={_display_value(vt.get('provider'), 'virustotal')}; "
            f"status={_display_value(vt.get('status'))}; "
            f"query={_display_value(vt.get('query') or profile.get('ip'))}; "
            f"malicious={_display_value(stats.get('malicious'))}; "
            f"suspicious={_display_value(stats.get('suspicious'))}; "
            f"reputation={_display_value(vt.get('reputation'))}; "
            f"asn={_display_value(vt.get('asn'))}; "
            f"owner={_display_value(vt.get('as_owner'))}; "
            f"network={_display_value(vt.get('network'))}; "
            f"tags={_display_value(vt.get('tags'))}; "
            f"message={_display_value(vt.get('message') or vt.get('error'))}"
        )
        if vt.get("status") == "config_missing":
            lines.append(
                "- **VirusTotal 配置提示**: "
                f"{_vt_config_hint(vt)}; "
                f"message={_display_value(vt.get('message') or vt.get('error'))}"
            )
    lines.append("")
    return lines


def batch_summary(results: list[dict], gateway_miss_scan: dict[str, Any] | None = None) -> dict:
    """Summarize outcomes and keep unavailable gateway data separate from mismatches."""
    counter_verdict = Counter(r["alert_verdict"] for r in results)
    counter_type = Counter(r["attack_type"] for r in results if r["attack_type"] != "unknown")
    counter_ip = Counter()
    for result in results:
        src_ip = result.get("src_ip")
        if src_ip:
            counter_ip[str(src_ip)] += 1
    success = sum(1 for r in results if r["attack_outcome"] == "success_confirmed")
    escalate = sum(1 for r in results if r["recommended_action"] == "escalate_investigate")
    gateway_likely = sum(
        1 for r in results if (r.get("gateway_success_hint") or {}).get("level") == "likely"
    )
    gateway_possible = sum(
        1 for r in results if (r.get("gateway_success_hint") or {}).get("level") == "possible"
    )
    gateway_gap_counter = Counter(
        (r.get("gateway_access_coverage") or {}).get("reason") or "unknown"
        for r in results
        if (r.get("gateway_access_coverage") or {}).get("status") == "missing"
    )
    # A fallback time-window query can prove the gateway asset is populated even
    # when the alert's source IP/path does not match. Expose that distinction so
    # operators do not treat correlation gaps as missing log collection.
    gateway_log_missing_reasons = {"gateway_log_missing", "gateway_log_no_investigation_window"}
    gateway_log_unmatched_reasons = {"gateway_log_no_matching_request"}
    gateway_log_outside_tight_reasons = {"gateway_log_outside_tight_window"}
    gateway_log_missing_count = sum(
        count for reason, count in gateway_gap_counter.items() if reason in gateway_log_missing_reasons
    )
    gateway_log_unmatched_count = sum(
        count for reason, count in gateway_gap_counter.items() if reason in gateway_log_unmatched_reasons
    )
    gateway_log_outside_tight_count = sum(
        count for reason, count in gateway_gap_counter.items() if reason in gateway_log_outside_tight_reasons
    )
    ip_block_review = sum(1 for r in results if (r.get("ip_action_guard") or {}).get("downgraded"))
    direct_block = sum(1 for r in results if r.get("recommended_action") == "block_ip")
    miss_scan = gateway_miss_scan or (results[0].get("gateway_miss_scan") if results else None) or {}
    for item in miss_scan.get("items") or []:
        src_ip = item.get("src_ip")
        if src_ip:
            counter_ip[str(src_ip)] += 1

    return {
        "alert_type": "alert_confirmation_batch_summary",
        "total": len(results),
        "false_positive": counter_verdict.get("false_positive", 0),
        "scanning_or_probe": counter_verdict.get("scanning_or_probe", 0),
        "suspicious": counter_verdict.get("suspicious", 0),
        "confirmed_attack": counter_verdict.get("confirmed_attack", 0),
        "success_confirmed": success,
        "per_alert_success_confirmed": success,
        "gateway_success_hint_likely": gateway_likely,
        "gateway_success_hint_possible": gateway_possible,
        "gateway_log_missing_count": gateway_log_missing_count,
        "gateway_log_unmatched_count": gateway_log_unmatched_count,
        "gateway_log_outside_tight_window_count": gateway_log_outside_tight_count,
        "gateway_log_missing_reasons": dict(gateway_gap_counter),
        "gateway_miss_count": miss_scan.get("count", 0),
        "gateway_miss_top_patterns": (miss_scan.get("summary") or {}).get("top_patterns") or [],
        "gateway_miss_by_severity": (miss_scan.get("summary") or {}).get("by_severity") or {},
        "escalate_count": escalate,
        "direct_block_count": direct_block,
        "ip_block_review_count": ip_block_review,
        "top_attack_types": [t for t, _ in counter_type.most_common(5)],
        "top_ips": [ip for ip, _ in counter_ip.most_common(5)],
    }


def markdown_report(result: dict, payload: dict | None = None) -> str:
    """Render the skill report with separate gateway availability and match gaps."""
    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    from fetch_summary import format_fetch_summary_markdown  # noqa: E402

    lines = ["# Alert Confirmation Report", ""]
    summary = result.get("fetch_summary")
    if summary:
        lines.append(format_fetch_summary_markdown(summary))
        lines.append("")

    if result.get("status") == "no_primary_alerts":
        lines.extend([
            "## 无主告警 / No primary alerts", "",
            "没有可逐条确认的主告警；不等于没有攻击。请先核对取数缺口，再查看下方独立网关扫描。",
            "No per-alert verdict is available. Review query gaps and the independent gateway scan below.", "",
        ])

    batch = result.get("batch_summary")
    if batch:
        campaign = result.get("campaign_success") or {}
        attribution = campaign.get("attribution") or {}
        d2_corr = attribution.get("d2_correlation")
        target_keys = ",".join(str(v) for v in attribution.get("target_keys") or [])
        d2_line = f"- **D2 归因**: {d2_corr}" if d2_corr else ""
        if d2_line and target_keys:
            d2_line = f"{d2_line} | target={target_keys[:120]}"
        elif d2_line and attribution.get("reason"):
            d2_line = f"{d2_line} | reason={attribution.get('reason')}"
        lines.extend(
            [
                "## 研判汇总",
                "",
                f"- **告警总数**: {batch.get('total', 0)}",
                f"- **确认攻击**: {batch.get('confirmed_attack', 0)}",
                f"- **扫描/探测**: {batch.get('scanning_or_probe', 0)}",
                f"- **可疑**: {batch.get('suspicious', 0)}",
                f"- **单告警成功确认数**: {batch.get('per_alert_success_confirmed', batch.get('success_confirmed', 0))}",
                f"- **网关层疑似成功**: {batch.get('gateway_success_hint_likely', 0)}",
                f"- **网关层可疑响应**: {batch.get('gateway_success_hint_possible', 0)}",
                f"- **WAF 告警缺少网关数据**: {batch.get('gateway_log_missing_count', 0)}",
                f"- **网关资产有数据但未匹配到对应请求**: {batch.get('gateway_log_unmatched_count', 0)}",
                f"- **网关同源请求超出精确时间窗口**: {batch.get('gateway_log_outside_tight_window_count', 0)}",
                f"- **WAF 漏检（网关命中攻击 URL）**: {batch.get('gateway_miss_count', 0)}",
                f"- **直接封禁建议**: {batch.get('direct_block_count', 0)}",
                f"- **封禁前需 IP 属性复核**: {batch.get('ip_block_review_count', 0)}",
                f"- **活动级成功**: {campaign.get('attack_outcome', 'success_unknown')}",
                f"- **活动级建议**: {campaign.get('recommended_action', 'log_and_monitor')}",
                "",
            ]
        )
        if d2_line:
            lines.insert(-1, d2_line)
        lines.extend(_format_ip_profile_markdown(result.get("attacker_ip_profile") or {}))
        gateway_gap_items = [
            item
            for item in result.get("results") or []
            if (item.get("gateway_access_coverage") or {}).get("status") == "missing"
        ]
        gateway_missing_items = [
            item
            for item in gateway_gap_items
            if (item.get("gateway_access_coverage") or {}).get("reason")
            in {"gateway_log_missing", "gateway_log_no_investigation_window"}
        ]
        gateway_unmatched_items = [
            item
            for item in gateway_gap_items
            if (item.get("gateway_access_coverage") or {}).get("reason") == "gateway_log_no_matching_request"
        ]
        gateway_outside_items = [
            item
            for item in gateway_gap_items
            if (item.get("gateway_access_coverage") or {}).get("reason") == "gateway_log_outside_tight_window"
        ]
        if gateway_missing_items:
            lines.extend(["### 需补充网关日志的 WAF 告警", ""])
            for item in gateway_missing_items[:10]:
                coverage = item.get("gateway_access_coverage") or {}
                lines.append(
                    f"- `{item.get('alert_id')}` reason={coverage.get('reason', 'unknown')} "
                    f"| {coverage.get('message', '')}"
                )
            if len(gateway_missing_items) > 10:
                lines.append(f"- … 另有 {len(gateway_missing_items) - 10} 条")
            lines.append("")
        if gateway_unmatched_items:
            lines.extend(["### 网关资产有数据但未匹配到 WAF 请求", ""])
            for item in gateway_unmatched_items[:10]:
                coverage = item.get("gateway_access_coverage") or {}
                lines.append(
                    f"- `{item.get('alert_id')}` reason={coverage.get('reason', 'unknown')} "
                    f"| {coverage.get('message', '')}"
                )
            if len(gateway_unmatched_items) > 10:
                lines.append(f"- … 另有 {len(gateway_unmatched_items) - 10} 条")
            lines.append("")
        if gateway_outside_items:
            lines.extend(["### 网关有同源请求但未落入精确时间窗口", ""])
            for item in gateway_outside_items[:10]:
                coverage = item.get("gateway_access_coverage") or {}
                lines.append(
                    f"- `{item.get('alert_id')}` reason={coverage.get('reason', 'unknown')} "
                    f"| {coverage.get('message', '')}"
                )
            if len(gateway_outside_items) > 10:
                lines.append(f"- … 另有 {len(gateway_outside_items) - 10} 条")
            lines.append("")
        miss_scan = result.get("gateway_miss_scan") or {}
        miss_items = miss_scan.get("items") or []
        if miss_items:
            lines.extend(["### WAF 漏检样本（网关可见、无对应 WAF 告警）", ""])
            for item in miss_items[:10]:
                lines.append(
                    f"- `{item.get('src_ip')}` {item.get('url', '')[:120]} "
                    f"→ HTTP {item.get('status')} | severity={item.get('severity', 'unknown')} "
                    f"| patterns={','.join(item.get('pattern_hits') or [])}"
                )
            if len(miss_items) > 10:
                lines.append(f"- … 另有 {len(miss_items) - 10} 条")
            lines.append("")
        for item in result.get("results") or []:
            hint = item.get("gateway_success_hint") or {}
            hint_suffix = ""
            if hint.get("level"):
                hint_suffix = f" | gateway_hint={hint.get('level')}"
            lines.append(
                f"- `{item.get('alert_id')}` **{item.get('alert_verdict')}** "
                f"({item.get('attack_type_label')}) → {item.get('attack_outcome')} "
                f"| {item.get('recommended_action_label') or item.get('recommended_action')}"
                f"{hint_suffix}"
            )
        return "\n".join(lines)

    if result.get("alert_id"):
        lines.extend(
            [
                "## Alert Triage Report",
                "",
                f"**Alert ID**: {result.get('alert_id')}",
                f"**Layer 1**: {result.get('alert_verdict')} ({result.get('attack_type_label')})",
                f"**Layer 2**: {result.get('attack_outcome')} | success={result.get('attack_success')}",
            ]
        )
        hint = result.get("gateway_success_hint")
        if hint:
            lines.extend(
                [
                    f"**Gateway hint**: {hint.get('level')} — {hint.get('reason_label') or hint.get('reason')}",
                ]
            )
        coverage = result.get("gateway_access_coverage") or {}
        if coverage.get("status") == "missing":
            lines.append(f"**Gateway log coverage**: missing — {coverage.get('message')}")
        miss_scan = result.get("gateway_miss_scan") or {}
        if miss_scan.get("count"):
            lines.append(f"**WAF miss scan**: {miss_scan.get('count')} gateway exploit hits without WAF alert")
        lines.extend(_format_ip_profile_markdown(result.get("attacker_ip_profile") or {}))
        guard = result.get("ip_action_guard") or {}
        if guard.get("downgraded"):
            lines.append(f"**Block guard**: {guard.get('reason_label')}")
        lines.extend(
            [
                f"**Recommended**: {result.get('recommended_action_label') or result.get('recommended_action')}",
                "",
                result.get("summary") or "",
            ]
        )
    return "\n".join(lines)


def count_repeats(alerts: list[dict]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for a in alerts:
        key = f"{a.get('src_ip')}|{a.get('rule_id')}"
        counts[key] += 1
    return dict(counts)
