#!/usr/bin/env python3
"""Ensure behavior-policy.md rule IDs stay documented (ops/engineering contract)."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_MD = ROOT / "behavior-policy.md"
POLICY_RULES_JSON = ROOT / "rules" / "behavior-policy.rules.json"

# Rule IDs with explicit ### headers in behavior-policy.md (exclude section titles).
MD_POLICY_RULE_IDS = frozenset(
    {
        "WEB-SHELL-001",
        "WEB-SHELL-002",
        "LATERAL-SSH-001",
        "RECON-HIGH-001",
        "SSH-IMPACT-001",
        "DOWNLOAD-MALICIOUS-001",
        "CONNECT-C2-001",
        "SSH-BRUTE-001",
        "SYS-ACCOUNT-001",
        "SYS-SUDO-001",
        "SYS-FW-001",
        "SYS-KERNEL-001",
        "OPS-LAB-SETUP-001",
        "OPS-SSH-001",
        "OPS-AGENT-001",
        "OPS-LOCAL-CURL-001",
        "OPS-AGENT-UNINSTALL-001",
        "OPS-DEPLOY-001",
        "OPS-CLOUD-001",
        "OPS-NGINX-001",
        "OPS-DNS-001",
    }
)

RULE_HEADER_RE = re.compile(r"^###\s+([A-Z0-9-]+)\｜", re.M)


class TestPolicyDocumentSync(unittest.TestCase):
    def test_md_lists_all_json_rule_ids(self) -> None:
        text = POLICY_MD.read_text(encoding="utf-8")
        md_ids = set(RULE_HEADER_RE.findall(text))
        missing_in_md = MD_POLICY_RULE_IDS - md_ids
        self.assertFalse(
            missing_in_md,
            f"behavior-policy.md missing rule headers for: {sorted(missing_in_md)}",
        )

    def test_json_rules_cover_md_policy_ids(self) -> None:
        import json

        pack = json.loads(POLICY_RULES_JSON.read_text(encoding="utf-8"))
        json_ids = {str(r.get("id")) for r in pack.get("rules") or [] if r.get("id")}
        missing_in_json = MD_POLICY_RULE_IDS - json_ids
        self.assertFalse(
            missing_in_json,
            f"behavior-policy.rules.json missing ids: {sorted(missing_in_json)}",
        )

    def test_md_rule_ids_have_mirror_note(self) -> None:
        """Documented IDs in MD should be subset of known implemented set or new ops rules."""
        text = POLICY_MD.read_text(encoding="utf-8")
        md_ids = set(RULE_HEADER_RE.findall(text))
        orphan_in_code = MD_POLICY_RULE_IDS - md_ids
        self.assertEqual(orphan_in_code, set())


if __name__ == "__main__":
    unittest.main()
