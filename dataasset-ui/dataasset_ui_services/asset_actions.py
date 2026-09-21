"""Asset action services for connectivity and log-format discovery."""

from __future__ import annotations

import json
import subprocess
from typing import Any

from .common import ROOT, SECWEAVER_CLI, parse_cli_json, subprocess_env, trim_error_output, validation_python


def summarize_connection_result(asset_id: str, result: subprocess.CompletedProcess[str]) -> tuple[str, dict[str, Any]]:
    data = parse_cli_json(result.stdout)
    if result.returncode != 0:
        summary = {
            "asset_id": asset_id,
            "status": "failed",
            "returncode": result.returncode,
            "error": trim_error_output(result.stdout, result.stderr),
        }
        return "连通测试失败\n\n" + summary["error"], summary

    if not isinstance(data, dict):
        summary = {
            "asset_id": asset_id,
            "status": "ok",
            "returncode": result.returncode,
            "message": "命令执行成功，但返回内容不是 JSON。",
        }
        return "连通测试成功，但无法解析连接器摘要。", summary

    query_meta = data.get("query_meta") if isinstance(data.get("query_meta"), dict) else {}
    events = data.get("events") if isinstance(data.get("events"), list) else []
    rows_returned = query_meta.get("rows_returned", len(events))
    summary = {
        "asset_id": asset_id,
        "status": "ok",
        "returncode": result.returncode,
        "connector_id": data.get("connector_id"),
        "connector_type": data.get("connector_type"),
        "template_id": data.get("template_id"),
        "credentials_ref": data.get("credentials_ref"),
        "rows_returned": rows_returned,
        "truncated": query_meta.get("truncated"),
        "time_range": query_meta.get("time_range"),
        "fetched_at": query_meta.get("fetched_at"),
    }
    lines = [
        "连通测试结果：OK",
        f"资产：{asset_id}",
        f"Connector：{summary.get('connector_id') or '-'} ({summary.get('connector_type') or '-'})",
        f"查询模板：{summary.get('template_id') or '-'}",
        f"返回行数：{rows_returned}",
    ]
    if summary.get("time_range"):
        lines.append(f"时间范围：{summary['time_range'][0]} ~ {summary['time_range'][1]}")
    if summary.get("fetched_at"):
        lines.append(f"拉取时间：{summary['fetched_at']}")
    return "\n".join(lines), summary


def summarize_discovery_result(asset_id: str, result: subprocess.CompletedProcess[str]) -> tuple[str, dict[str, Any]]:
    data = parse_cli_json(result.stdout)
    if result.returncode != 0:
        summary = {
            "asset_id": asset_id,
            "status": "failed",
            "returncode": result.returncode,
            "error": trim_error_output(result.stdout, result.stderr),
        }
        return "日志格式发现失败\n\n" + summary["error"], summary

    if not isinstance(data, dict):
        summary = {
            "asset_id": asset_id,
            "status": "ok",
            "returncode": result.returncode,
            "message": "命令执行成功，但返回内容不是 JSON。",
        }
        return "日志格式发现成功，但无法解析格式摘要。", summary

    gap = data.get("gap_analysis") if isinstance(data.get("gap_analysis"), dict) else {}
    schema = data.get("proposed_asset_schema") if isinstance(data.get("proposed_asset_schema"), dict) else {}
    observed = data.get("observed_json_keys") if isinstance(data.get("observed_json_keys"), dict) else {}
    aliases = data.get("proposed_field_aliases") if isinstance(data.get("proposed_field_aliases"), dict) else {}
    requirements = data.get("requirements") if isinstance(data.get("requirements"), dict) else {}
    top_fields = sorted(observed.keys())[:30]
    missing_required = gap.get("missing_required") or []
    missing_recommended = gap.get("missing_recommended") or []
    summary = {
        "asset_id": asset_id,
        "status": "ok",
        "returncode": result.returncode,
        "detected_format": data.get("detected_format"),
        "asset_type": data.get("asset_type"),
        "connector_type": data.get("connector_type"),
        "sample_count": data.get("sample_count"),
        "confidence": data.get("confidence"),
        "fields": schema.get("fields") or [],
        "time_field": schema.get("time_field"),
        "required_fields": requirements.get("required") or [],
        "recommended_fields": requirements.get("recommended") or [],
        "observed_fields": top_fields,
        "proposed_field_aliases": aliases,
        "missing_required": missing_required,
        "missing_recommended": missing_recommended,
        "llm_review_required": data.get("llm_review_required"),
    }
    lines = [
        "日志格式发现结果：OK",
        f"资产：{asset_id}",
        f"资产类型：{summary.get('asset_type') or '-'}",
        f"Connector 类型：{summary.get('connector_type') or '-'}",
        f"识别格式：{summary.get('detected_format') or '-'}",
        f"样本数量：{summary.get('sample_count') or 0}",
        f"置信度：{summary.get('confidence') or '-'}",
        "",
        "字段梳理：",
        "- 建议字段：" + (", ".join(summary["fields"]) if summary["fields"] else "-"),
        f"- 时间字段：{summary.get('time_field') or '-'}",
        "- 观测字段：" + (", ".join(top_fields) if top_fields else "-"),
        "- 字段别名：" + (json.dumps(aliases, ensure_ascii=False) if aliases else "无"),
        "",
        "缺口检查：",
        "- 缺失 required：" + (", ".join(missing_required) if missing_required else "无"),
        "- 缺失 recommended：" + (", ".join(missing_recommended) if missing_recommended else "无"),
    ]
    return "\n".join(lines), summary


def run_asset_action(asset_id: str, action: str) -> dict[str, Any]:
    python_bin = validation_python()
    if action == "test_connection":
        cmd = [python_bin, str(SECWEAVER_CLI), "asset", "test", asset_id]
        result = subprocess.run(cmd, cwd=ROOT, env=subprocess_env(), text=True, capture_output=True, timeout=90, check=False)
        output, summary = summarize_connection_result(asset_id, result)
        return {
            "ok": result.returncode == 0,
            "action": action,
            "title": "连通测试",
            "command": " ".join(cmd),
            "returncode": result.returncode,
            "output": output,
            "summary": summary,
        }
    if action == "discover_format":
        cmd = [python_bin, str(SECWEAVER_CLI), "asset", "discover-format", asset_id]
        result = subprocess.run(cmd, cwd=ROOT, env=subprocess_env(), text=True, capture_output=True, timeout=120, check=False)
        output, summary = summarize_discovery_result(asset_id, result)
        return {
            "ok": result.returncode == 0,
            "action": action,
            "title": "发现日志格式",
            "command": " ".join(cmd),
            "returncode": result.returncode,
            "output": output,
            "summary": summary,
        }
    raise ValueError(f"未知资产操作：{action}")
