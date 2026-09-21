#!/usr/bin/env python3
"""Tests for attack pattern matching."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from pattern_matcher import match_attack_pattern  # noqa: E402
from risk_rules_bridge import load_trace_patterns  # noqa: E402

PATTERNS = load_trace_patterns()


class PatternMatcherTests(unittest.TestCase):
    def test_match_web_shell_to_ssh_lateral(self) -> None:
        chain = [
            {"stage": "initial_access", "description": "webshell upload.php", "host": "10.0.1.5", "evidence_refs": ["waf-1"]},
            {"stage": "execution", "description": "curl wget bash sshpass", "host": "10.0.1.5", "evidence_refs": ["exec-1"]},
            {"stage": "lateral_movement", "description": "ssh Accepted devops", "host": "10.0.2.10", "evidence_refs": ["ssh-1"]},
        ]
        self.assertEqual(match_attack_pattern(chain, PATTERNS), "web_shell_to_ssh_lateral")

    def test_no_match_empty_chain(self) -> None:
        self.assertIsNone(match_attack_pattern([], PATTERNS))


if __name__ == "__main__":
    unittest.main()
