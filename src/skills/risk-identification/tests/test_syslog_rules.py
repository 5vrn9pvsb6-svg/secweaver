#!/usr/bin/env python3
"""Tests for syslog_risk_alert detection from rules/syslog-rules.json."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from assess import assess, load_scenarios  # noqa: E402
from behavior_policy import evaluate_item  # noqa: E402
from syslog_rules import (  # noqa: E402
    assess_syslog_events,
    configure_syslog_rules,
    filter_syslog_events,
    get_syslog_rules_engine,
)


class TestSyslogRules(unittest.TestCase):
    def test_excludes_ssh_auth_raw(self) -> None:
        engine = get_syslog_rules_engine()
        ev = {"event_type": "auth_failure", "message": "Failed password"}
        self.assertTrue(engine.is_excluded(ev))

    def test_account_created_p0(self) -> None:
        ev = {
            "host": "192.0.2.92",
            "timestamp": "2026-07-01T14:35:00+08:00",
            "event_type": "account_created",
            "user": "backdoor",
            "command": "useradd backdoor",
            "risk_level": "critical",
        }
        items = assess_syslog_events([ev], ceiling=1.0, severity_floor="P2", warnings=[])
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["severity"], "P0")
        self.assertIn("account_created", items[0]["matched_rules"])
        self.assertEqual(items[0]["risk_module"], "syslog")

    def test_sudo_useradd_message_rule(self) -> None:
        ev = {
            "host": "192.0.2.92",
            "timestamp": "2026-07-01T14:36:00+08:00",
            "event_type": "sudo_command",
            "user": "root",
            "command": "sudo useradd attacker",
            "risk_level": "medium",
        }
        items = assess_syslog_events([ev], ceiling=1.0, severity_floor="P2", warnings=[])
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["severity"], "P0")
        self.assertIn("sudo_useradd", items[0]["matched_rules"])

    def test_filter_respects_hosts(self) -> None:
        events = [
            {"host": "192.0.2.92", "event_type": "firewall_event", "timestamp": "2026-07-01T12:00:00+08:00"},
            {"host": "192.0.2.93", "event_type": "firewall_event", "timestamp": "2026-07-01T12:00:00+08:00"},
        ]
        out = filter_syslog_events(
            events,
            {"hosts": ["192.0.2.92"], "time_start": "2026-06-01T00:00:00+08:00", "time_end": "2026-07-02T23:59:59+08:00"},
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["host"], "192.0.2.92")

    def test_policy_force_alert_account(self) -> None:
        item = {
            "risk_module": "syslog",
            "severity": "P0",
            "event_type": "account_created",
            "command": "useradd evil",
            "matched_rules": ["account_created"],
        }
        updated, hit = evaluate_item(item)
        self.assertEqual(hit["rule_id"], "SYS-ACCOUNT-001")
        self.assertTrue(updated["alert_required"])

    def test_policy_lab_setup_downgrade(self) -> None:
        item = {
            "risk_module": "syslog",
            "severity": "P0",
            "event_type": "account_created",
            "user": "devops",
            "command": "useradd devops",
            "matched_rules": ["account_created"],
        }
        updated, hit = evaluate_item(item)
        self.assertEqual(hit["rule_id"], "OPS-LAB-SETUP-001")
        self.assertFalse(updated["alert_required"])
        self.assertTrue(updated["alert_suppressed"])

    def test_assess_syslog_module_integration(self) -> None:
        catalog = load_scenarios(ROOT / "scenarios.json")
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
                "syslog_risk_alert": [
                    {
                        "evidence_id": "sys-1",
                        "host": "192.0.2.92",
                        "timestamp": "2026-07-01T14:35:00+08:00",
                        "event_type": "firewall_event",
                        "message": "iptables -A INPUT -j DROP",
                        "risk_level": "high",
                    }
                ],
            },
        }
        result = assess(payload, catalog)
        self.assertIn("syslog", result["risk_modules_run"])
        syslog_items = [it for it in result["risk_items"] if it.get("risk_module") == "syslog"]
        self.assertEqual(len(syslog_items), 1)
        self.assertEqual(syslog_items[0]["policy_rule_id"], "SYS-FW-001")
        self.assertTrue(syslog_items[0]["alert_required"])


if __name__ == "__main__":
    unittest.main()
