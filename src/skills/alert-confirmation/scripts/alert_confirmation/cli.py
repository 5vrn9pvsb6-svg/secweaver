"""Command-line entrypoint for alert confirmation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .common import load_json
from .engine import analyze
from .paths import ATTACK_TYPES_PATH, DATA_ACCESS_PATH, FP_PATTERNS_PATH
from .report import markdown_report

def main() -> int:
    """Preserve valid empty batches; signal actual analysis errors to callers."""
    parser = argparse.ArgumentParser(description="SecWeaver 告警确认")
    parser.add_argument("-i", "--input", help="输入 JSON")
    parser.add_argument("-o", "--output", help="输出 JSON")

    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    # Payload adaptation belongs to the upper runtime, not the fetch layer.
    sys.path.insert(0, str(DATA_ACCESS_PATH.parent))
    from skill_runtime.contracts import ensure_skill_envelope
    from skill_runtime.inputs import add_bundle_arguments, build_alert_payload, load_input_payload

    add_bundle_arguments(parser, "alert")
    args = parser.parse_args()

    attack_catalog = load_json(ATTACK_TYPES_PATH)
    fp_catalog = load_json(FP_PATTERNS_PATH)

    try:
        payload = load_input_payload(args, "alert", build_alert_payload)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 1

    result = analyze(payload, attack_catalog, fp_catalog)
    if isinstance(result, dict) and "error" not in result:
        if str(DATA_ACCESS_PATH) not in sys.path:
            sys.path.insert(0, str(DATA_ACCESS_PATH))
        from fetch_summary import enrich_result_with_fetch_summary  # noqa: E402

        envelope = result if "results" in result else {"results": [result]}
        enrich_result_with_fetch_summary(envelope, payload)
        fetch_summary = envelope.get("fetch_summary")
        if "results" in result:
            result["fetch_summary"] = fetch_summary
            result["markdown_report"] = markdown_report(result)
        else:
            result["fetch_summary"] = fetch_summary
            result["markdown_report"] = markdown_report(
                {"fetch_summary": fetch_summary, "results": [result]}
            )
    ensure_skill_envelope(result, "alert-confirmation")
    out = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    return 1 if isinstance(result, dict) and "error" in result else 0
