#!/usr/bin/env python3
"""SecWeaver 证据取数 — 只拉 evidence_bundles，不做风险/告警/溯源研判。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPTS_DIR.parent
DATA_ACCESS_PATH = SCRIPTS_DIR.parents[1] / "_shared" / "data-access"

sys.path.insert(0, str(DATA_ACCESS_PATH))

# Payload adaptation belongs to the upper runtime, not the fetch layer.
sys.path.insert(0, str(DATA_ACCESS_PATH.parent))
from skill_runtime.inputs import (  # noqa: E402
    add_bundle_arguments,
    build_evidence_fetch_payload,
    load_input_payload,
    parse_params,
)
from fetch_summary import format_fetch_summary_markdown, summarize_fetch  # noqa: E402


def run_fetch(payload: dict[str, Any]) -> dict[str, Any]:
    """Reuse completed evidence; execute previews or an explicitly refreshed offline input.

    Offline fixtures are already evidence, not pending fetch plans. Preserve
    their original raw/retained counts and never contact a connector unless
    the caller explicitly asks to refresh, plan, or dry-run them.
    """
    data_access = payload.get("data_access") or {}
    mode = data_access.get("fetch_mode")
    requested_mode = "plan_only" if not payload.get("_fetch_live", True) else (
        "dry_run" if payload.get("_dry_run", False) else "live"
    )
    if (
        mode in {"offline", "offline_fixture"}
        and not payload.get("_explicit_fetch", False)
        and requested_mode == "live"
    ):
        if not isinstance(payload.get("evidence_bundles"), dict) or not isinstance(payload.get("fetch_summary"), dict):
            raise ValueError("offline evidence input needs evidence_bundles and fetch_summary")
        return payload
    if mode == "live" or mode == requested_mode:
        payload["fetch_summary"] = summarize_fetch(payload)
        return payload

    # Saved previews are not evidence; rebuild from their declared asset scope
    # instead of returning an empty preview to a live investigation.
    if mode in {"plan_only", "dry_run"} and not (payload.get("asset_ids") or payload.get("bundle_id")):
        raise ValueError("saved fetch preview needs asset_ids or bundle_id before it can be executed")

    params = payload.get("params") or {}
    built = build_evidence_fetch_payload(
        params,
        bundle_id=payload.get("bundle_id"),
        asset_ids=payload.get("asset_ids"),
        investigation_intent=payload.get("investigation_intent"),
        scenarios=payload.get("scenarios"),
        anchor_pattern_id=payload.get("correlation_anchor_pattern"),
        fetch_live=payload.get("_fetch_live", True),
        dry_run=payload.get("_dry_run", False),
        include_completeness=bool(payload.get("completeness_precheck")),
    )
    for key in ("completeness_precheck", "investigation_intent", "scenarios", "scenario"):
        if key in payload and key not in built:
            built[key] = payload[key]
    built["fetch_summary"] = summarize_fetch(built)
    return built


def markdown_report(result: dict[str, Any]) -> str:
    summary = result.get("fetch_summary") or {}
    lines = [
        "# 证据取数报告",
        "",
        f"- **意图**: {result.get('investigation_intent', '—')}",
        "",
        format_fetch_summary_markdown(summary),
    ]
    plan = result.get("correlation_fetch_plan") or []
    if plan:
        lines.extend(["", "## correlation_fetch_plan", ""])
        for task in plan[:30]:
            lines.append(
                f"- `{task.get('join_id')}` {task.get('side')} "
                f"{task.get('asset_id')} / {task.get('template_id')}"
            )
        if len(plan) > 30:
            lines.append(f"- … 共 {len(plan)} 条任务")
    pre = result.get("completeness_precheck")
    if pre:
        lines.extend(
            [
                "",
                "## 完整性预检（参考）",
                "",
                f"- **overall_verdict**: {pre.get('overall_verdict')}",
                f"- **confidence**: {pre.get('confidence')}",
            ]
        )
    lines.extend(
        [
            "",
            "## 下游 Skill",
            "",
            "- 风险识别：传入 `evidence_bundles` + `params` → `risk-identification/scripts/assess.py`",
            "- 告警确认：传入 `correlated_evidence` / `primary_alerts` → `alert-confirmation/scripts/confirm.py`",
            "- 溯源分析：传入 `evidence_bundles` → `traceability-analysis/scripts/correlate.py`",
            "- **研判建议交给 Agent/大模型**，本 Skill 不输出 alert_verdict / risk_items",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SecWeaver evidence-fetch — 多源取数，输出 evidence_bundles（不研判）",
    )
    parser.add_argument("-i", "--input", help="输入 JSON（可含已有 evidence_bundles）")
    parser.add_argument("-o", "--output", help="输出 JSON 文件")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--pretty", action="store_true")
    add_bundle_arguments(parser, "fetch")
    args = parser.parse_args()

    if getattr(args, "from_bundle", False) or getattr(args, "asset_ids", None):
        payload = load_input_payload(args, "fetch", build_evidence_fetch_payload)
    elif args.input or not sys.stdin.isatty():
        payload = load_input_payload(args, "fetch", build_evidence_fetch_payload)
    else:
        parser.error("需要 --asset-id（配合 --params）、--from-bundle、-i 或 stdin JSON")

    payload["_fetch_live"] = not getattr(args, "plan_only", False)
    payload["_dry_run"] = getattr(args, "dry_run", False)
    payload["_explicit_fetch"] = getattr(args, "fetch", False)

    result = run_fetch(payload)
    result.pop("_fetch_live", None)
    result.pop("_dry_run", None)
    result.pop("_explicit_fetch", None)

    if args.format == "markdown":
        text = markdown_report(result)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text)
        return 0

    indent = 2 if args.pretty else None
    out = json.dumps(result, ensure_ascii=False, indent=indent)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
