#!/usr/bin/env python3
"""Tests for incident aggregation and P0 behavior-policy rules."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from behavior_policy import evaluate_item  # noqa: E402
from incident_aggregator import aggregate_incidents  # noqa: E402


class TestP0BehaviorPolicy(unittest.TestCase):
    def test_sshd_monitor_suppress(self) -> None:
        item = {
            "risk_id": "risk-sshd",
            "risk_module": "exec",
            "severity": "P0",
            "listener_port": 22,
            "listener_process": "sshd",
            "command": ["/usr/sbin/sshd", "-D", "-R"],
            "matched_rules": ["external_listener_shell_exec"],
        }
        updated, hit = evaluate_item(item)
        self.assertEqual(hit["rule_id"], "OPS-AGENT-001")
        self.assertFalse(updated["alert_required"])

    def test_sshd_monitor_json_string_suppress(self) -> None:
        """SLS stores command as JSON argv string (live 192.0.2.92 drill shape)."""
        item = {
            "risk_id": "risk-sshd-json",
            "risk_module": "exec",
            "severity": "P1",
            "listener_port": 22,
            "listener_process": "sshd",
            "command": '["/usr/sbin/sshd","-D","-R"]',
            "matched_rules": [],
        }
        updated, hit = evaluate_item(item)
        self.assertEqual(hit["rule_id"], "OPS-AGENT-001")
        self.assertTrue(updated["alert_suppressed"])
        self.assertFalse(updated["alert_required"])
        self.assertEqual(updated["severity"], "P3")

    def test_local_curl_suppress(self) -> None:
        item = {
            "risk_id": "risk-curl",
            "risk_module": "exec",
            "severity": "P0",
            "listener_port": 22,
            "listener_process": "sshd",
            "command": '["bash","-c","curl -so/dev/null -w%{http_code} http://127.0.0.1/"]',
            "matched_rules": ["download_and_execute"],
        }
        updated, hit = evaluate_item(item)
        self.assertEqual(hit["rule_id"], "OPS-LOCAL-CURL-001")
        self.assertFalse(updated["alert_required"])

    def test_agent_uninstall_suppress(self) -> None:
        item = {
            "risk_id": "risk-rm",
            "risk_module": "exec",
            "severity": "P0",
            "listener_port": 22,
            "listener_process": "sshd",
            "command": ["rm", "-f", "/etc/systemd/system/loongcollectord.service"],
            "matched_rules": ["persistence_modify"],
        }
        updated, hit = evaluate_item(item)
        self.assertEqual(hit["rule_id"], "OPS-AGENT-UNINSTALL-001")
        self.assertFalse(updated["alert_required"])

    def test_lab_setup_suppress(self) -> None:
        item = {
            "risk_id": "risk-lab",
            "risk_module": "exec",
            "severity": "P0",
            "listener_port": 22,
            "listener_process": "sshd",
            "command": (
                "bash -c sudo useradd -m devops; echo devops:devops123 | sudo chpasswd; "
                "sudo tee /opt/db-credentials.conf"
            ),
            "matched_rules": ["persistence_modify"],
        }
        updated, hit = evaluate_item(item)
        self.assertEqual(hit["rule_id"], "OPS-LAB-SETUP-001")
        self.assertFalse(updated["alert_required"])
        self.assertTrue(updated["alert_suppressed"])

    def test_webshell_002_sshd_sphtml(self) -> None:
        item = {
            "risk_id": "risk-ws2",
            "risk_module": "exec",
            "severity": "P1",
            "listener_port": 22,
            "listener_process": "sshd",
            "command": ["curl", "-s", "http://127.0.0.1/uploads/s.phtml?c=id"],
            "matched_rules": ["webshell_write"],
        }
        updated, hit = evaluate_item(item)
        self.assertEqual(hit["rule_id"], "WEB-SHELL-002")
        self.assertTrue(updated["alert_required"])
        self.assertEqual(updated["severity"], "P0")


class TestIncidentAggregator(unittest.TestCase):
    def test_aggregate_repeated_events(self) -> None:
        items = []
        for i in range(5):
            items.append(
                {
                    "risk_id": f"risk-{i}",
                    "host": "192.0.2.92",
                    "risk_module": "exec",
                    "severity": "P0",
                    "policy_rule_id": "OPS-AGENT-001",
                    "listener_process": "sshd",
                    "listener_port": 22,
                    "command": ["/usr/sbin/sshd", "-D", "-R"],
                    "alert_required": False,
                    "alert_suppressed": True,
                    "summary": "sshd monitor",
                }
            )
        items.append(
            {
                "risk_id": "risk-web",
                "host": "192.0.2.91",
                "risk_module": "exec",
                "severity": "P0",
                "policy_rule_id": "WEB-SHELL-001",
                "listener_process": "nginx",
                "listener_port": 80,
                "command": ["sh", "-c", "id"],
                "alert_required": True,
                "summary": "webshell id",
            }
        )
        incidents = aggregate_incidents(items, top_n=10, alerting_only=True)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["policy_rule_id"], "WEB-SHELL-001")
        self.assertEqual(incidents[0]["event_count"], 1)

        all_incidents = aggregate_incidents(items, top_n=10, alerting_only=False)
        self.assertEqual(all_incidents[0]["policy_rule_id"], "WEB-SHELL-001")
        self.assertEqual(all_incidents[1]["event_count"], 5)


if __name__ == "__main__":
    unittest.main()
