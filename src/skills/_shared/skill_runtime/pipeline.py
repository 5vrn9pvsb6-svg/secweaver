#!/usr/bin/env python3
"""Upper-layer bundle pipeline; evidence access and Skill execution stay separate."""

from __future__ import annotations

import argparse
import json
from .inputs import (
    DEFAULT_BUNDLE,
    build_alert_payload,
    build_completeness_payload,
    build_risk_payload,
    build_traceability_payload,
    parse_params,
)
from .execution import assess_payload, run_completeness_assess


def run_completeness(bundle_id: str, params: dict, intent: str | None) -> dict:
    """Build the input first, then invoke only the canonical Skill assessment."""
    payload = build_completeness_payload(bundle_id, params, investigation_intent=intent)
    return run_completeness_assess(payload)


def run_traceability(bundle_id: str, params: dict, intent: str | None, fetch: bool, dry_run: bool) -> dict:
    """Build the input first, then invoke only the canonical Skill assessment."""
    payload = build_traceability_payload(
        bundle_id, params, investigation_intent=intent, fetch_live=fetch, dry_run=dry_run
    )
    return assess_payload("traceability", payload)


def run_alert(bundle_id: str, params: dict, intent: str | None, fetch: bool, dry_run: bool) -> dict:
    """Build the input first, then invoke only the canonical Skill assessment."""
    payload = build_alert_payload(
        bundle_id, params, investigation_intent=intent, fetch_live=fetch, dry_run=dry_run
    )
    return assess_payload("alert", payload)


def run_risk(bundle_id: str, params: dict, intent: str | None, fetch: bool, dry_run: bool) -> dict:
    """Build the input first, then invoke only the canonical Skill assessment."""
    payload = build_risk_payload(
        bundle_id, params, investigation_intent=intent, fetch_live=fetch, dry_run=dry_run
    )
    return assess_payload("risk", payload)


def main() -> int:
    """Keep legacy modes/output keys; no implicit live fetch or notification."""
    parser = argparse.ArgumentParser(description="SecWeaver dataasset + Vault pipeline")
    parser.add_argument(
        "skill",
        choices=["completeness", "trace", "alert", "risk", "trace-chain", "alert-chain", "risk-chain"],
        help="completeness | trace | alert | risk | trace-chain | alert-chain | risk-chain (完整性+风险)",
    )
    parser.add_argument("--bundle", help="bundle id（省略则用各 skill 默认包）")
    parser.add_argument("--intent")
    parser.add_argument("--params", default="{}")
    parser.add_argument("--params-file")
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    params = parse_params(args.params, args.params_file)
    bundle = args.bundle
    indent = 2 if args.pretty else None

    if args.skill == "completeness":
        bid = bundle or DEFAULT_BUNDLE["completeness"]
        result = run_completeness(bid, params, args.intent)
    elif args.skill == "trace":
        bid = bundle or DEFAULT_BUNDLE["traceability"]
        result = run_traceability(bid, params, args.intent, args.fetch, args.dry_run)
    elif args.skill == "alert":
        bid = bundle or DEFAULT_BUNDLE["alert"]
        result = run_alert(bid, params, args.intent, args.fetch, args.dry_run)
    elif args.skill == "risk":
        bid = bundle or DEFAULT_BUNDLE["risk"]
        result = run_risk(bid, params, args.intent, args.fetch, args.dry_run)
    elif args.skill == "trace-chain":
        bid = bundle or DEFAULT_BUNDLE["traceability"]
        pre = run_completeness(bid, params, args.intent)
        trace = run_traceability(bid, params, args.intent, args.fetch, args.dry_run)
        result = {"completeness": pre, "traceability": trace}
    elif args.skill == "risk-chain":
        bid = bundle or DEFAULT_BUNDLE["risk"]
        pre = run_completeness(bid, params, args.intent or "S5 主机行为完整性")
        risk = run_risk(bid, params, args.intent, args.fetch, args.dry_run)
        result = {"completeness": pre, "risk_identification": risk}
    else:  # alert-chain
        bid = bundle or DEFAULT_BUNDLE["alert"]
        pre = run_completeness(bid, params, args.intent or "告警确认前完整性")
        alert = run_alert(bid, params, args.intent, args.fetch, args.dry_run)
        result = {"completeness": pre, "alert_confirmation": alert}

    print(json.dumps(result, ensure_ascii=False, indent=indent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
