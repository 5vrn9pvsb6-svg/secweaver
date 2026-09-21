#!/usr/bin/env python3
"""Validate behavior-policy.md ↔ behavior-policy.rules.json sync for CI."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MD = SKILL_ROOT / "behavior-policy.md"
DEFAULT_RULES = SKILL_ROOT / "rules" / "behavior-policy.rules.json"

RULE_HEADER_RE = re.compile(r"^###\s+([A-Z0-9-]+)\｜", re.M)

# Section titles that are not policy rule IDs.
NON_RULE_HEADERS = frozenset(
    {
        "谁改什么",
        "运营改规则的标准流程",
        "执行方式（CLI vs Agent）",
    }
)

TIER_BY_MD_SECTION = {
    "二、绝不允许降级（硬护栏）": "hard_guardrail",
    "三、必须告警（P0 / P1，force alert）": "force_alert",
    "四、降噪与例外（运维 / 演练 / Agent）": "downgrade",
}


def load_md_rule_ids(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    ids = set(RULE_HEADER_RE.findall(text))
    return {rid for rid in ids if rid not in NON_RULE_HEADERS and re.match(r"^[A-Z0-9-]+$", rid)}


def load_json_rule_ids(path: Path) -> set[str]:
    sys.path.insert(0, str(SKILL_ROOT / "scripts"))
    from policy_engine import get_policy_rules, list_rule_ids

    pack = get_policy_rules(path)
    return list_rule_ids(pack)


def validate(*, md_path: Path, rules_path: Path, strict: bool) -> list[str]:
    errors: list[str] = []
    if not md_path.is_file():
        errors.append(f"MD not found: {md_path}")
    if not rules_path.is_file():
        errors.append(f"rules JSON not found: {rules_path}")
    if errors:
        return errors

    md_ids = load_md_rule_ids(md_path)
    json_ids = load_json_rule_ids(rules_path)

    missing_in_json = sorted(md_ids - json_ids)
    missing_in_md = sorted(
        rid
        for rid in (json_ids - md_ids)
        if not rid.startswith(("HARD-GUARDRAIL-", "DEFAULT-"))
    )

    if missing_in_json:
        errors.append(f"MD rule IDs missing in JSON: {missing_in_json}")
    if strict and missing_in_md:
        errors.append(f"JSON rule IDs missing MD ### header: {missing_in_md}")

    pack = json.loads(rules_path.read_text(encoding="utf-8"))
    for rule in pack.get("rules") or []:
        rule_id = str(rule.get("id") or "")
        if not rule.get("when"):
            errors.append(f"Rule {rule_id} missing when")
        if not rule.get("decision"):
            errors.append(f"Rule {rule_id} missing decision")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate behavior-policy MD/JSON sync")
    parser.add_argument("--md", type=Path, default=DEFAULT_MD)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--strict", action="store_true", help="JSON ids must also exist in MD")
    args = parser.parse_args()

    errors = validate(md_path=args.md, rules_path=args.rules, strict=args.strict)
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1
    print(f"OK: {args.md.name} ↔ {args.rules.name} in sync ({len(load_md_rule_ids(args.md))} MD ids)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
