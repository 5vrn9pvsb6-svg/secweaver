#!/usr/bin/env python3
"""Tests for validate_policy_sync and md_to_policy_rules scripts."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"


class ValidatePolicySyncScriptTests(unittest.TestCase):
    def test_default_pack_passes_strict(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "validate_policy_sync.py"), "--strict"],
            cwd=SKILL_ROOT.parents[2],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)

    def test_missing_json_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            md = Path(tmp) / "policy.md"
            rules = Path(tmp) / "rules.json"
            md.write_text("### OPS-NEW-001｜test\n\n**决策**：P3，不告警\n", encoding="utf-8")
            base = json.loads((SKILL_ROOT / "rules" / "behavior-policy.rules.json").read_text(encoding="utf-8"))
            rules.write_text(json.dumps(base, ensure_ascii=False, indent=2), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS / "validate_policy_sync.py"), "--md", str(md), "--rules", str(rules)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)


class MdToPolicyRulesTests(unittest.TestCase):
    def test_draft_single_rule(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "md_to_policy_rules.py"),
                "--id",
                "OPS-SSH-001",
            ],
            cwd=SKILL_ROOT.parents[2],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["drafts"])
        self.assertEqual(data["drafts"][0]["id"], "OPS-SSH-001")


if __name__ == "__main__":
    unittest.main()
