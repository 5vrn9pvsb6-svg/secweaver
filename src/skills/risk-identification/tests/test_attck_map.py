#!/usr/bin/env python3
"""Tests for MITRE ATT&CK mapping (rules/attck-map.json)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from attck_map import apply_mitre_attack, format_mitre_attack_short, resolve_mitre_attack  # noqa: E402
from rule_loader import load_rule_pack, validate_rule_pack  # noqa: E402


class TestAttckMap(unittest.TestCase):
    def test_attck_map_validates(self) -> None:
        pack = load_rule_pack(default_name="attck-map.json")
        self.assertIn("matched_rules", pack)
        validate_rule_pack(pack, "attck-map.json")

    def test_resolve_from_matched_rules(self) -> None:
        item = {
            "matched_rules": ["external_listener_shell_exec", "webshell_write"],
            "policy_rule_id": None,
        }
        mitre = resolve_mitre_attack(item)
        ids = mitre["technique_ids"]
        self.assertIn("T1059.004", ids)
        self.assertIn("T1505.003", ids)
        self.assertTrue(mitre["tactics"])

    def test_resolve_policy_rule(self) -> None:
        item = {
            "matched_rules": ["noise_command"],
            "policy_rule_id": "WEB-SHELL-001",
        }
        mitre = resolve_mitre_attack(item)
        self.assertIn("T1505.003", mitre["technique_ids"])

    def test_apply_to_items(self) -> None:
        items = [
            {
                "risk_id": "r1",
                "matched_rules": ["ssh_bruteforce"],
                "policy_rule_id": "SSH-BRUTE-001",
            }
        ]
        apply_mitre_attack(items)
        self.assertIn("T1110.001", items[0]["mitre_attack"]["technique_ids"])

    def test_format_short(self) -> None:
        text = format_mitre_attack_short(
            {
                "techniques": [
                    {"id": "T1505.003", "name": "Web Shell", "tactic": "persistence"},
                    {"id": "T1059.004", "name": "Unix Shell", "tactic": "execution"},
                ]
            },
            limit=2,
        )
        self.assertIn("T1505.003", text)
        self.assertIn("Web Shell", text)


if __name__ == "__main__":
    unittest.main()
