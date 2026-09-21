#!/usr/bin/env python3
"""Tests for post-lateral target host high-risk exec impact signals."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from source_adapters.tigersec_target_impact import (  # noqa: E402
    classify_high_risk_exec,
    find_post_lateral_target_exec_signals,
    upgrade_suspected_lateral_with_target_exec,
)


class TargetImpactTests(unittest.TestCase):
    def test_classify_high_risk_exec(self) -> None:
        cats = classify_high_risk_exec("cat /etc/shadow")
        self.assertIn("credential_access", cats)

    def test_passwd_file_read_is_not_persistence(self) -> None:
        cats = classify_high_risk_exec("cat /etc/passwd")
        self.assertIn("credential_access", cats)
        self.assertNotIn("persistence", cats)

    def test_passwd_command_is_persistence(self) -> None:
        cats = classify_high_risk_exec("passwd alice")
        self.assertIn("persistence", cats)

    def test_target_exec_burst_upgrades_suspected_lateral(self) -> None:
        suspected = [
            {
                "stage": "lateral_movement",
                "timestamp": "2026-07-01T17:22:50+08:00",
                "host": "192.0.2.92",
                "source_host": "192.0.2.91",
                "lateral_class": "suspected_lateral",
                "confidence": 0.78,
                "description": "exec 推断横向",
                "evidence_refs": ["host-exec-src-1"],
                "join_ids": ["lateral_from_exec"],
            }
        ]
        exec_on_92 = [
            {
                "timestamp": "2026-07-01T17:23:05+08:00",
                "host_ip": "192.0.2.92",
                "command_line": "cat /etc/shadow",
                "evidence_id": "host-exec-92-shadow",
            },
            {
                "timestamp": "2026-07-01T17:23:10+08:00",
                "host_ip": "192.0.2.92",
                "command_line": "sudo -l",
                "evidence_id": "host-exec-92-sudo",
            },
            {
                "timestamp": "2026-07-01T17:23:15+08:00",
                "host_ip": "192.0.2.92",
                "command_line": "nmap -Pn 192.0.2.0/24",
                "evidence_id": "host-exec-92-nmap",
            },
        ]
        signals = find_post_lateral_target_exec_signals(exec_on_92, suspected)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["lateral_class"], "likely_lateral")
        self.assertGreaterEqual(signals[0]["confidence"], 0.86)

        upgraded = upgrade_suspected_lateral_with_target_exec(suspected, signals)
        self.assertEqual(upgraded[0]["lateral_class"], "likely_lateral")
        self.assertIn("lateral_from_target_exec", upgraded[0]["join_ids"])
        self.assertGreaterEqual(upgraded[0]["confidence"], 0.86)

    def test_no_upgrade_without_enough_high_risk(self) -> None:
        suspected = [
            {
                "stage": "lateral_movement",
                "timestamp": "2026-07-01T17:22:50+08:00",
                "host": "192.0.2.92",
                "source_host": "192.0.2.91",
                "lateral_class": "suspected_lateral",
            }
        ]
        exec_on_92 = [
            {
                "timestamp": "2026-07-01T17:23:05+08:00",
                "host_ip": "192.0.2.92",
                "command_line": "ls -la",
                "evidence_id": "host-exec-92-ls",
            }
        ]
        signals = find_post_lateral_target_exec_signals(exec_on_92, suspected)
        self.assertEqual(signals, [])


if __name__ == "__main__":
    unittest.main()
