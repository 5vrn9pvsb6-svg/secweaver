"""Command-line entrypoint for traceability analysis."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from risk_rules_bridge import load_trace_patterns  # noqa: E402

from .engine import analyze
from .paths import DATA_ACCESS_PATH
from .result import trace_markdown_report

def main() -> int:
    parser = argparse.ArgumentParser(description="SecWeaver 溯源分析关联脚本")
    parser.add_argument("-i", "--input", help="输入 JSON 文件")
    parser.add_argument("-o", "--output", help="输出 JSON 文件")
    parser.add_argument(
        "--patterns",
        default="",
        help="Override risk-identification/rules/chain-patterns.json path",
    )
    notify_group = parser.add_argument_group("webhook notification")
    notify_group.add_argument(
        "--notify",
        action="store_true",
        help="分析完成后推送报告到 webhook-config.json 配置的钉钉/飞书/企业微信",
    )
    notify_group.add_argument(
        "--no-notify",
        action="store_true",
        help="跳过 webhook 通知（即使 webhook-config.json 已启用）",
    )
    notify_group.add_argument(
        "--webhook-config",
        metavar="PATH",
        help="webhook 配置文件路径（默认 traceability-analysis/webhook-config.json）",
    )
    notify_group.add_argument(
        "--notify-dry-run",
        action="store_true",
        help="构建通知内容但不实际 POST",
    )
    parser.add_argument(
        "--report-locale",
        default="en",
        choices=("zh-CN", "en"),
        help="markdown_report locale (default en; script report only, see --no-markdown-report)",
    )
    parser.add_argument(
        "--no-markdown-report",
        action="store_true",
        help="不生成 trace_report_markdown.py 脚本报告；由 Agent 按 SKILL 模板基于 JSON 撰写（推荐对话场景）",
    )
    parser.add_argument(
        "--no-ip-intel",
        action="store_true",
        help="跳过攻击源 IP 网络属性查询（resolve_attacker_ip_profile=false）",
    )

    # Payload adaptation belongs to the upper runtime, not the fetch layer.
    sys.path.insert(0, str(DATA_ACCESS_PATH.parent))
    from skill_runtime.contracts import ensure_skill_envelope
    from skill_runtime.inputs import add_bundle_arguments, build_traceability_payload, load_input_payload

    add_bundle_arguments(parser, "traceability")
    args = parser.parse_args()

    if args.patterns:
        patterns = load_trace_patterns(Path(args.patterns))
    else:
        patterns = load_trace_patterns()

    try:
        payload = load_input_payload(args, "traceability", build_traceability_payload)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if getattr(args, "no_ip_intel", False):
        payload.setdefault("params", {})["resolve_attacker_ip_profile"] = False

    result = analyze(payload, patterns)
    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    from fetch_summary import enrich_result_with_fetch_summary  # noqa: E402

    enrich_result_with_fetch_summary(result, payload)
    report_locale = getattr(args, "report_locale", None) or payload.get("report_locale") or "en"
    result["report_locale"] = report_locale
    if getattr(args, "no_markdown_report", False):
        result["report_mode"] = "agent"
        result["markdown_report"] = None
    else:
        result["report_mode"] = "script"
        result["markdown_report"] = trace_markdown_report(result, locale=report_locale)

    from webhook_notify import maybe_notify_traceability_report  # noqa: E402

    notify_meta = maybe_notify_traceability_report(
        result,
        payload=payload,
        config_path=getattr(args, "webhook_config", None),
        force_notify=getattr(args, "notify", False),
        skip_notify=getattr(args, "no_notify", False),
        dry_run=getattr(args, "notify_dry_run", False),
        report_output_path=args.output,
    )
    if notify_meta is not None:
        result["notification"] = notify_meta
        if notify_meta.get("attempted") and not notify_meta.get("skipped"):
            ok = notify_meta.get("ok")
            status = "ok" if ok else "partial/failed"
            print(f"webhook notification: {status}", file=sys.stderr)
            for ch in notify_meta.get("channels") or []:
                if not ch.get("ok"):
                    print(
                        f"  - {ch.get('name') or ch.get('type')}: {ch.get('error') or ch.get('response')}",
                        file=sys.stderr,
                    )

    ensure_skill_envelope(result, "traceability-analysis")
    out = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    return 0
