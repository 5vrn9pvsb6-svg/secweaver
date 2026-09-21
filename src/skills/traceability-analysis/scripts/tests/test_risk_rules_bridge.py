#!/usr/bin/env python3
"""Tests for risk-identification rule bridge."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from risk_rules_bridge import (  # noqa: E402
    download_exec_patterns_from_exec_rules,
    load_trace_patterns,
    match_chain_pattern,
    policy_rules_by_chain,
    resolve_matched_pattern_from_payload,
    webshell_url_patterns_from_exec_rules,
)


class RiskRulesBridgeTests(unittest.TestCase):
    def test_load_trace_patterns_has_derived_literals(self) -> None:
        patterns = load_trace_patterns()
        self.assertIn("webshell_url_patterns", patterns)
        self.assertIn("s.phtml", patterns["webshell_url_patterns"])
        self.assertIn("curl", patterns["download_exec_patterns"])
        self.assertIn("sshpass", patterns["lateral_tools"])

    def test_policy_rules_by_chain(self) -> None:
        mapping = policy_rules_by_chain()
        self.assertIn("WEB-SHELL-001", mapping["web_shell_to_ssh_lateral"])

    def test_resolve_from_risk_payload(self) -> None:
        payload = {
            "risk_identification": {
                "matched_pattern": "web_shell_to_ssh_lateral",
            }
        }
        self.assertEqual(
            resolve_matched_pattern_from_payload(payload),
            "web_shell_to_ssh_lateral",
        )

    def test_webshell_literals_from_exec_rules(self) -> None:
        literals = webshell_url_patterns_from_exec_rules()
        self.assertTrue(any("phtml" in x for x in literals))

    def test_download_literals_from_exec_rules(self) -> None:
        literals = download_exec_patterns_from_exec_rules()
        self.assertIn("wget", literals)

    def test_literal_tokens_for_rule_id(self) -> None:
        from risk_rules_bridge import literal_tokens_for_rule_id

        tokens = literal_tokens_for_rule_id("LATERAL-SSH-001")
        self.assertIn("sshpass", tokens)

    def test_match_chain_pattern_by_stage_rules(self) -> None:
        patterns = load_trace_patterns()
        chain = [
            {
                "stage": "initial_access",
                "description": "nginx webshell",
                "evidence_refs": [],
            },
            {
                "stage": "execution",
                "description": "curl download",
                "evidence_refs": [],
            },
            {
                "stage": "lateral_movement",
                "description": "sshpass ssh lateral",
                "evidence_refs": [],
            },
        ]
        self.assertEqual(match_chain_pattern(chain, patterns), "web_shell_to_ssh_lateral")


if __name__ == "__main__":
    unittest.main()
