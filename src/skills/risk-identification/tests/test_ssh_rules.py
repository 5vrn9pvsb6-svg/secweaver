#!/usr/bin/env python3
"""Tests for SSH brute-force detection from syslog-risk-json events."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from assess import assess, load_scenarios  # noqa: E402
from ssh_rules import (  # noqa: E402
    assess_ssh_bruteforce,
    collect_ssh_events,
    detect_bruteforce_bursts,
    normalize_ssh_event,
)


class TestSshRules(unittest.TestCase):
    def test_normalize_syslog_risk_failure(self) -> None:
        ev = {
            "host_name": "192.0.2.92",
            "timestamp": "2026-07-01T17:08:29+08:00",
            "event_type": "auth_failure",
            "message": "pam_unix(sshd:auth): authentication failure; rhost=192.0.2.91 user=devops",
            "src_ip": "192.0.2.91",
            "user": "devops",
        }
        norm = normalize_ssh_event(ev)
        self.assertIsNotNone(norm)
        assert norm is not None
        self.assertEqual(norm["result"], "failed")
        self.assertEqual(norm["src_ip"], "192.0.2.91")

    def test_detect_burst(self) -> None:
        events = []
        for i in range(12):
            events.append(
                {
                    "host": "192.0.2.92",
                    "timestamp": f"2026-07-01T17:08:{i:02d}+08:00",
                    "src_ip": "192.0.2.91",
                    "user": "devops",
                    "result": "failed",
                }
            )
        bursts = detect_bruteforce_bursts(events, window_sec=300, threshold=10)
        self.assertEqual(len(bursts), 1)
        self.assertGreaterEqual(bursts[0]["fail_count"], 10)
        self.assertEqual(bursts[0]["src_ip"], "192.0.2.91")
        self.assertEqual(bursts[0]["wave_index"], 1)

    def test_detect_multiple_waves(self) -> None:
        events = []
        for i in range(12):
            events.append(
                {
                    "host": "192.0.2.92",
                    "timestamp": f"2026-07-01T14:57:{i:02d}+08:00",
                    "src_ip": "192.0.2.91",
                    "user": "devops",
                    "result": "failed",
                }
            )
        for i in range(12):
            events.append(
                {
                    "host": "192.0.2.92",
                    "timestamp": f"2026-07-01T17:22:{i:02d}+08:00",
                    "src_ip": "192.0.2.91",
                    "user": "devops",
                    "result": "failed",
                }
            )
        bursts = detect_bruteforce_bursts(events, window_sec=300, threshold=10)
        self.assertEqual(len(bursts), 2)
        self.assertEqual(bursts[0]["wave_index"], 1)
        self.assertEqual(bursts[1]["wave_index"], 2)

    def test_self_loop_suppressed(self) -> None:
        events = []
        for i in range(12):
            events.append(
                {
                    "host": "192.0.2.92",
                    "timestamp": f"2026-07-01T14:57:{i:02d}+08:00",
                    "src_ip": "192.0.2.92",
                    "user": "root",
                    "result": "failed",
                }
            )
        bursts = detect_bruteforce_bursts(events, window_sec=300, threshold=10)
        self.assertEqual(len(bursts), 0)

    def test_assess_returns_waves(self) -> None:
        events = []
        for i in range(12):
            events.append(
                {
                    "host": "192.0.2.92",
                    "timestamp": f"2026-07-01T14:57:{i:02d}+08:00",
                    "src_ip": "192.0.2.91",
                    "user": "devops",
                    "result": "failed",
                }
            )
        items, waves = assess_ssh_bruteforce(
            events, ceiling=1.0, severity_floor="P2", window_sec=300, threshold=10
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(len(waves), 1)
        self.assertEqual(items[0]["wave_index"], 1)

    def test_assess_ssh_module_offline(self) -> None:
        catalog = load_scenarios(ROOT / "scenarios.json")
        failures = []
        for i in range(12):
            failures.append(
                {
                    "evidence_id": f"auth-{i}",
                    "host_name": "192.0.2.92",
                    "host": "192.0.2.92",
                    "timestamp": f"2026-07-01T17:08:{i:02d}+08:00",
                    "event_type": "ssh_login_failed",
                    "message": "Failed password for devops from 192.0.2.91 port 22 ssh2",
                    "src_ip": "192.0.2.91",
                    "user": "devops",
                }
            )
        payload = {
            "scenario": "S5",
            "params": {
                "hosts": ["192.0.2.92"],
                "time_start": "2026-06-01T00:00:00+08:00",
                "time_end": "2026-07-02T23:59:59+08:00",
                "severity_floor": "P2",
            },
            "completeness_precheck": {
                "overall_verdict": "full_traceable",
                "confidence": 0.9,
                "next_skill_blocked": False,
            },
            "evidence_bundles": {
                "host_exec": [],
                "host_connect": [],
                "ssh_auth": failures,
            },
        }
        result = assess(payload, catalog)
        ssh_items = [it for it in result["risk_items"] if it.get("risk_module") == "ssh"]
        self.assertEqual(len(ssh_items), 1)
        self.assertEqual(ssh_items[0]["policy_rule_id"], "SSH-BRUTE-001")
        self.assertTrue(ssh_items[0]["alert_required"])
        self.assertEqual(len(result.get("ssh_brute_waves") or []), 1)


if __name__ == "__main__":
    unittest.main()
