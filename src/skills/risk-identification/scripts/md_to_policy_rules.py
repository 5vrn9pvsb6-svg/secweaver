#!/usr/bin/env python3
"""Draft behavior-policy.rules.json fragments from behavior-policy.md sections."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MD = SKILL_ROOT / "behavior-policy.md"
DEFAULT_RULES = SKILL_ROOT / "rules" / "behavior-policy.rules.json"

RULE_HEADER_RE = re.compile(r"^###\s+([A-Z0-9-]+)\｜([^\n]+)", re.M)
DECISION_SEVERITY_RE = re.compile(r"决策[：:]\s*(P[0-3])", re.I)
DECISION_ALERT_RE = re.compile(r"(必须告警|需要告警|不告警|降噪|suppress)", re.I)


def _infer_tier(section_title: str, body: str) -> str:
    title = section_title.strip()
    if "硬护栏" in title or title.startswith("二、"):
        return "hard_guardrail"
    if "必须告警" in title or title.startswith("三、"):
        return "force_alert"
    if "降噪" in title or title.startswith("四、"):
        return "downgrade"
    if re.search(r"不告警|降噪|P3", body):
        return "downgrade"
    if re.search(r"必须告警|P0", body):
        return "force_alert"
    return "downgrade"


def _infer_modules(body: str) -> list[str]:
    modules: list[str] = []
    lower = body.lower()
    if "syslog" in lower:
        modules.append("syslog")
    if "ssh" in lower and "sshd" in lower:
        modules.append("exec")
    if "外连" in body or "connect" in lower or "c2" in lower:
        modules.append("connect")
    if "exec" in lower or "命令" in body or "listener" in lower or not modules:
        modules.append("exec")
    return sorted(set(modules))


def _draft_decision(body: str, tier: str) -> dict[str, Any]:
    sev_match = DECISION_SEVERITY_RE.search(body)
    severity = sev_match.group(1).upper() if sev_match else ("P0" if tier == "force_alert" else "P3")
    alert_required = tier in {"force_alert", "hard_guardrail"}
    alert_suppressed = tier == "downgrade" and bool(re.search(r"不告警|降噪|suppress", body, re.I))
    if re.search(r"必须告警|需要告警", body):
        alert_required = True
        alert_suppressed = False
    verdict = "confirmed_attack" if severity in {"P0", "P1"} and alert_required else "benign"
    if tier == "downgrade":
        verdict = "benign" if alert_suppressed else "likely_false_positive"
    return {
        "severity": severity,
        "alert_required": alert_required,
        "alert_suppressed": alert_suppressed,
        "verdict": verdict,
        "recommended_action": "investigate" if alert_required else "log_only",
        "reason": "TODO: 从 MD 摘要粘贴",
    }


def _draft_when(body: str) -> dict[str, Any]:
    lower = body.lower()
    if "matched_rules" in lower or "检测层" in body:
        return {"matched_rules_any": ["TODO_matched_rule_id"]}
    if "sshd" in lower and "22" in body:
        return {"all": [{"predicate": "is_sshd_session"}, {"command_regex": "TODO", "flags": "i"}]}
    if "nginx" in lower or "web" in lower:
        return {"all": [{"predicate": "is_web_entry"}, {"predicate": "is_shell_command"}]}
    return {"command_regex": "TODO_pattern", "flags": "i"}


def parse_md_sections(md_text: str) -> list[dict[str, Any]]:
    current_section = ""
    drafts: list[dict[str, Any]] = []
    for line in md_text.splitlines():
        if line.startswith("## "):
            current_section = line[3:].strip()
    # Re-split by rule headers with section context
    parts = re.split(r"(?=^###\s+[A-Z0-9-]+\｜)", md_text, flags=re.M)
    section = ""
    for part in parts:
        for line in part.splitlines():
            if line.startswith("## "):
                section = line[3:].strip()
        for match in RULE_HEADER_RE.finditer(part):
            rule_id = match.group(1)
            if not re.match(r"^[A-Z0-9-]+$", rule_id):
                continue
            body = part[match.end() :].strip()
            tier = _infer_tier(section, body)
            drafts.append(
                {
                    "id": rule_id,
                    "tier": tier,
                    "modules": _infer_modules(body),
                    "when": _draft_when(body),
                    "unless": [],
                    "decision": _draft_decision(body, tier),
                    "_draft_from_md": True,
                    "_md_section": section,
                }
            )
    return drafts


def merge_with_existing(drafts: list[dict[str, Any]], existing: dict[str, Any]) -> dict[str, Any]:
    by_id = {str(r["id"]): r for r in existing.get("rules") or [] if r.get("id")}
    for draft in drafts:
        rid = draft["id"]
        if rid not in by_id:
            by_id[rid] = {k: v for k, v in draft.items() if not k.startswith("_")}
    merged = dict(existing)
    merged["rules"] = list(by_id.values())
    return merged


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate policy rule JSON drafts from behavior-policy.md")
    parser.add_argument("--md", type=Path, default=DEFAULT_MD)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--merge", action="store_true", help="Merge missing ids into existing rules file")
    parser.add_argument("--output", type=Path, help="Write merged/full pack (default stdout JSON)")
    parser.add_argument("--id", dest="rule_id", help="Only emit draft for one RULE-ID")
    args = parser.parse_args()

    md_text = args.md.read_text(encoding="utf-8")
    drafts = parse_md_sections(md_text)
    if args.rule_id:
        drafts = [d for d in drafts if d["id"] == args.rule_id]
        if not drafts:
            print(f"No ### {args.rule_id} found in {args.md}", file=sys.stderr)
            return 1

    if args.merge:
        existing = json.loads(args.rules.read_text(encoding="utf-8")) if args.rules.is_file() else {}
        output = merge_with_existing(drafts, existing)
    else:
        output = {"drafts": [{k: v for k, v in d.items() if not k.startswith("_")} for d in drafts]}

    text = json.dumps(output, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
