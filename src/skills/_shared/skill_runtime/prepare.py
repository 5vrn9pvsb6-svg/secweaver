#!/usr/bin/env python3
"""Prepare skill input from dataasset bundles + optional live fetch via SOPS Vault."""

from __future__ import annotations

import argparse
import json
from .inputs import (
    build_alert_payload,
    build_completeness_payload,
    build_risk_payload,
    build_traceability_payload,
    parse_params,
)
from .execution import assess_payload


def main() -> int:
    """Prepare by default; explicit --run-skill adds the canonical assessment."""
    parser = argparse.ArgumentParser(description="Prepare skill input from dataasset + SOPS Vault")
    parser.add_argument("--bundle", required=True, help="bundle id")
    parser.add_argument("--intent")
    parser.add_argument("--params", default="{}")
    parser.add_argument("--params-file")
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--run-skill", choices=["completeness", "traceability", "alert", "risk"])
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    params = parse_params(args.params, args.params_file)
    skill = args.run_skill or "completeness"

    if skill == "completeness":
        payload = build_completeness_payload(args.bundle, params, investigation_intent=args.intent)
    elif skill == "traceability":
        payload = build_traceability_payload(
            args.bundle, params, investigation_intent=args.intent,
            fetch_live=args.fetch, dry_run=args.dry_run,
        )
    elif skill == "risk":
        payload = build_risk_payload(
            args.bundle, params, investigation_intent=args.intent,
            fetch_live=args.fetch, dry_run=args.dry_run,
        )
    else:
        payload = build_alert_payload(
            args.bundle, params, investigation_intent=args.intent,
            fetch_live=args.fetch, dry_run=args.dry_run,
        )

    # --run-skill means assessment for all four modes, not just payload creation.
    # Default preparation still emits metadata only and never runs a Skill.
    if args.run_skill:
        payload["skill_result"] = assess_payload(args.run_skill, payload)

    indent = 2 if args.pretty else None
    print(json.dumps(payload, ensure_ascii=False, indent=indent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
