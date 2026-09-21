"""Render offline analysis results without an LLM, credentials or network access.

These reports expose the current result and its evidence, not an independent
investigation. The host agent must still review them under each analysis Skill.
No verdict or narrative is taken from catalog expectations or fixture metadata.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

VERDICT_LABELS = {
    "false_positive": "误报", "scanning_or_probe": "扫描／探测",
    "confirmed_attack": "规则判为真实攻击", "suspicious": "可疑",
    "success_confirmed": "确认成功", "success_unknown": "成功与否未知",
    "blocked": "已拦截", "not_applicable": "不适用",
    "confirmed_intrusion_chain": "观察到主机执行及横向证据，入口因果关系仍需复核",
    "scanning_or_attempt_only": "仅观察到扫描或尝试",
    "initial_access_only": "观察到主机执行，未确认横向成功",
    "high_risk_detected": "检测到需调查的风险行为",
    "no_risk_detected": "本例没有需要告警的风险项",
    "insufficient_data": "证据不足或未达规则阈值",
    "full_traceable": "登记数据源齐备，可开始取证",
    "partial_traceable": "数据源部分齐备，结论受缺口限制",
    "not_traceable": "缺少关键数据源，溯源受阻",
    "alert_triage_only": "仅能做告警分类，不能确认攻击成功",
}


def label(value: Any) -> str:
    """Translate known verdict codes while retaining the machine value for audit."""
    return f"{VERDICT_LABELS[value]}（{value}）" if value in VERDICT_LABELS else str(value or "未提供")


def describe(event: dict[str, Any]) -> str:
    """Select readable observations; raw JSON remains the complete evidence source."""
    keys = {
        "src_ip": "来源", "dst_ip": "目的", "dst_port": "目的端口", "user": "用户",
        "method": "方法", "url": "路径", "payload": "载荷", "status": "响应状态",
        "action": "动作", "result": "结果", "auth_method": "认证方式", "path": "文件",
        "query": "查询", "response": "应答", "rcode": "DNS 返回码", "message": "消息",
    }
    details = []
    command = event.get("command_line") or event.get("command")
    if command:
        details.append(f"命令：{command}")
    details.extend(f"{title}：{event[key]}" for key, title in keys.items() if key in event)
    return "；".join(details) if details else json.dumps(event, ensure_ascii=False)


def text(value: Any) -> str:
    """Quote evidence as literal Markdown text, including hostile log content."""
    if value is None or value == "":
        return "未提供"
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    value = html.escape(str(value), quote=False).replace("\n", "；").replace("\r", "")
    for character in ("\\", "`", "*", "_", "[", "]"):
        value = value.replace(character, "\\" + character)
    return value.replace("|", "&#124;")


def table(headers: list[str], rows: Any) -> str:
    """Keep arbitrary evidence, including shell pipes, inside table cells."""
    return (
        "| " + " | ".join(headers) + " |\n"
        + "|" + "|".join("---" for _ in headers) + "|\n"
        + "".join("| " + " | ".join(text(v) for v in row) + " |\n" for row in rows)
        + "\n"
    )


def link(label: str, path: Path) -> str:
    """Use local absolute links that survive spaces and Markdown punctuation."""
    return f"[{text(label)}](<{quote(str(path.resolve()), safe='/:-._~')}>)"


def verdict(result: dict[str, Any]) -> str:
    """Preserve the difference between alert authenticity and attack success."""
    if "batch_summary" in result:
        batch = result["batch_summary"]
        return (f"批量告警 {batch.get('total', 0)} 条；误报 {batch.get('false_positive', 0)}；"
                f"扫描 {batch.get('scanning_or_probe', 0)}；真实攻击 {batch.get('confirmed_attack', 0)}；"
                f"确认成功 {batch.get('success_confirmed', 0)}")
    if "alert_verdict" in result:
        return f"{label(result['alert_verdict'])} / {label(result.get('attack_outcome'))}"
    return label(result.get("overall_verdict"))


def constraints(result: dict[str, Any]) -> dict[str, Any]:
    """Use the shared evidence boundary even when a Skill nests it in statistics."""
    return result.get("analysis_constraints") or result.get("fetch_summary", {}).get("analysis_constraints", {})


def limitations(result: dict[str, Any]) -> list[str]:
    """Collect current gaps without converting empty results into negative proof."""
    gaps = list(result.get("data_gaps_impact") or result.get("data_gaps") or [])
    for alert in result.get("results", []):
        gaps.extend(alert.get("data_gaps_impact", []))
    if result.get("block_reason"):
        gaps.append(result["block_reason"])
    for requirement in result.get("requirements_evaluated", []):
        if requirement.get("status") != "ready":
            gaps.append(f"{requirement.get('label')}: {requirement.get('status')} {requirement.get('gaps', [])}")
    for note in result.get("capability_notes", []):
        gaps.append(note.get("message", str(note)))
    return list(dict.fromkeys(str(gap) for gap in gaps))


def render_case(case: dict[str, Any], evidence: dict[str, Any], result: dict[str, Any],
                input_path: Path, json_path: Path) -> str:
    """Build a readable baseline from observed fields, never from expected values.

    Recorded fetch attempts in synthetic inputs can say live/failed. They are
    shown as replayed metadata, not as network calls made by this offline run.
    Unknown Skills retain the common evidence/gap view instead of fabricated
    interpretations. Rich causal narrative remains the host agent's job.
    """
    sections = ["# 数据取数统计\n\n",
                "离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。\n\n"]
    fetch = result.get("fetch_summary", {})
    if fetch:
        sections.append("查询计数来自结果元数据；输入预录的查询成功／超时也会计入，不能视为本次真实联网。\n\n")
        sections.append(table(["记录数", "累计取数", "请求", "查询", "失败查询", "查询完整性"], [[
            fetch.get(k) for k in ("total_events", "total_fetched_events", "total_fetch_requests",
                                  "total_fetch_queries", "failed_fetch_queries")
        ] + [fetch.get("query_integrity", {}).get("status")]]))
        sections.append(table(["数据类型", "记录数"], fetch.get("by_asset_type", {}).items()))
        sections.append(table(["去重", "窗口过滤", "截断类型"], [[fetch.get(k) for k in
                              ("total_deduplicated_events", "total_window_filtered_events", "truncated_asset_types")]]))
        assets = fetch.get("asset_fetch_stats", [])
        sections.append(table(["数据资产", "类型", "查询", "成功", "失败", "累计取数", "保留", "去重", "窗口过滤"],
                              [[a.get(k) for k in ("asset_id", "asset_type", "query_count", "successful_query_count",
                                "failed_query_count", "cumulative_fetched_events", "final_event_count",
                                "deduplicated_count", "window_filtered_count")] for a in assets])
                        if assets else "逐资产取数明细为空；离线输入不等于生产环境完整覆盖。\n\n")
    else:
        sections.append(f"只有 {len(evidence.get('registered_assets', []))} 份数据源登记信息，无事件取数；能力评分不代表攻击发生概率。\n\n")
    params = evidence.get("params", {})
    sections.append(table(["开始时间", "结束时间", "告警锚点"], [[params.get(k) for k in
                          ("time_start", "time_end", "alert_time")]]))
    sections.extend([f"## {text(case.get('title_zh') or case['case_id'])}\n\n",
                     "**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。\n\n",
                     f"案例：{text(case['case_id'])}；Skill：{text(case['skill'])}。\n\n",
                     f"### 结论\n\n{text(verdict(result))}\n\n"])
    boundary = constraints(result)
    sections.append(table(["原始置信度", "顶层上限", "证据约束建议上限", "证据范围"], [[
        result.get("confidence"), result.get("confidence_ceiling"),
        boundary.get("recommended_confidence_ceiling"), boundary.get("scope")]]))
    sections.append("规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。\n\n")

    if case["skill"] == "alert-confirmation":
        alerts = result.get("results", [result])
        sections.append("### 告警真实性与攻击结果\n\n")
        sections.append(table(["告警", "真实性", "攻击结果", "成功证据", "原始置信度", "建议动作"],
                              [[a.get("alert_id"), label(a.get("alert_verdict")), label(a.get("attack_outcome")),
                                a.get("evidence", {}).get("success_proof"), a.get("confidence"),
                                a.get("recommended_action_label") or a.get("recommended_action")] for a in alerts]))
        for alert in alerts:
            sections.append(f"{text(alert.get('alert_id'))}：{text(alert.get('payload_analysis', {}).get('notes'))}。"
                            f"活动级结果：{text(label(alert.get('campaign_success', {}).get('attack_outcome')))}。\n\n")
    elif case["skill"] == "risk-identification":
        sections.append("### 风险项与规则\n\n")
        sections.append(table(["主机", "等级", "规则判定", "证据", "规则", "策略", "需告警", "ATT&CK", "建议动作"],
                              [[r.get("host"), r.get("severity"), r.get("verdict"), r.get("evidence_refs"),
                                r.get("matched_rules"), r.get("policy_rule_id"), r.get("alert_required"),
                                r.get("mitre_attack", {}).get("technique_ids"), r.get("recommended_action")]
                               for r in result.get("risk_items", [])]))
        sections.append(f"实际模块：{text(result.get('risk_modules_run'))}；覆盖：{text(result.get('coverage_level'))}。\n\n")
        sections.append(table(["统计", "值"], result.get("summary", {}).items()))
        sections.append(table(["白名单", "动作", "原因"], [[r.get(k) for k in ("rule_id", "action", "reason")]
                                                           for r in result.get("whitelist_hits", [])]))
    elif case["skill"] == "data-source-completeness":
        sections.append("### 数据源能力\n\n")
        sections.append(table(["可溯源", "具备打穿确认能力", "下一技能受阻", "下一技能"], [[result.get(k) for k in
                              ("can_trace", "can_confirm_breach", "next_skill_blocked", "next_skill")]]))
        sections.append(table(["需求", "优先级", "状态", "缺口"], [[r.get(k) for k in
                              ("label", "priority", "status", "gaps")] for r in result.get("requirements_evaluated", [])]))
        sections.append(table(["接入顺序", "数据源", "缺失影响", "采集建议"], [[r.get(k) for k in
                              ("rank", "source_name", "impact_if_missing", "collection_hint")]
                               for r in result.get("recommendations", [])]))
    elif case["skill"] == "traceability-analysis":
        entry = result.get("initial_access") or {}
        sections.append("### 入口与横向证据\n\n")
        sections.append(table(["观察目标", "入口角色", "首次攻破点状态", "URL", "主要证据"], [[entry.get(k) for k in
                              ("host", "entry_point_role", "first_compromise_point_status", "url", "primary_evidence_refs")]]))
        sections.append("观察到的控制点不等于原始攻破方式；规范化 URL、关联边和 ATT&CK 标签需结合原始证据复核。\n\n")
        lateral = result.get("lateral_findings", {})
        sections.append(table(["横向分类", "来源", "目标", "账号", "确认时间", "证据"], [
            [kind, item.get("source_host"), item.get("host"), item.get("user"), item.get("confirmed_timestamp"), item.get("evidence_refs")]
            for kind in ("confirmed", "likely", "suspected") for item in lateral.get(kind, [])]))
        sections.append(table(["影响目标（脚本标签）", "角色", "排查优先级"], [[a.get(k) for k in
                              ("host", "role", "priority")] for a in result.get("impacted_assets", [])]))
        sections.append(table(["建议动作"], [[a] for a in result.get("recommended_actions", [])]))
        sections.append(f"ATT&CK（规则映射）：{text(result.get('mitre_attack', {}).get('technique_ids'))}。\n\n")

    rows = []
    bundles = evidence.get("evidence_bundles") or evidence.get("correlated_evidence") or {}
    for source, events in bundles.items():
        for event in events:
            rows.append([event.get("timestamp"), source, event.get("evidence_id"),
                         event.get("host") or event.get("target_ip") or event.get("client_ip"), describe(event)])
    for alert in evidence.get("primary_alerts", []):
        rows.append([alert.get("timestamp"), "primary_alert", alert.get("alert_id"), alert.get("host"), describe(alert)])
    rows.sort(key=lambda row: str(row[0] or ""))
    sections.append("### 原始证据时间线\n\n")
    sections.append(table(["时间", "来源", "证据 ID", "主机／目标", "记录"], rows)
                    if rows else "本例没有实际事件；只评估登记数据源。\n\n")
    if evidence.get("registered_assets"):
        sections.append(table(["数据源", "类型", "覆盖", "字段"], [[a.get(k) for k in
                              ("asset_id", "type", "coverage", "fields")] for a in evidence["registered_assets"]]))
    sections.append("### 数据缺口与结论边界\n\n")
    sections.append("".join(f"- {text(gap)}\n" for gap in limitations(result)) or "未单列缺口，不代表证据完整。\n")
    sections.append("\n上述动作均为建议，本次未执行隔离、封禁或凭证修改。\n\n")
    sections.append("### 可复核来源\n\n" + link("离线输入", input_path) + " · " + link("本次 JSON", json_path) + "\n")
    return "".join(sections)


def render_suite(summary: dict[str, Any]) -> str:
    """Index only current successes; stale artifacts from failures stay unlinked."""
    sections = ["# 数据取数统计\n\n离线合成案例；无真实网络取数。逐例输入统计和预录查询缺口见对应报告。\n\n",
                "## SecWeaver 离线案例汇总\n\n",
                f"共 {summary['total']} 例，通过 {summary['passed']}，失败 {summary['failed']}。\n\n",
                "自动生成结构化结果报告；执行通过不等于攻击成功，也不表示已完成智能体证据复核。\n\n",
                "| 案例 | 状态 | 当前结论 | 主要缺口 | 可读报告 | JSON |\n|---|---|---|---|---|---|\n"]
    for result in summary["results"]:
        if result["ok"]:
            report = link("报告", Path(result["report"]))
            raw = link("JSON", Path(result["output"]))
            detail = result.get("verdict", "未提供")
            gaps = result.get("limitations", [])
            gap_text = "；".join(gaps[:2]) if gaps else "未单列；仍受离线证据范围限制"
            if len(gaps) > 2:
                gap_text += f"；共 {len(gaps)} 项，详见逐例报告"
        else:
            report = raw = "—"
            detail = result["error"]
            gap_text = "本例未完成"
        sections.append(f"| {text(result['case_id'])} | {'通过' if result['ok'] else '失败'} | {text(detail)} | {text(gap_text)} | {report} | {raw} |\n")
    sections.append("\n失败案例的旧文件不属于本次成功结果。继续复核成功案例，并处理失败原因。\n")
    return "".join(sections)
