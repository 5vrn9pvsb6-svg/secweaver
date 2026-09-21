#!/usr/bin/env python3
"""Tests for declarative policy_engine."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from behavior_policy import apply_behavior_policy  # noqa: E402
from policy_engine import evaluate_item_declarative, get_policy_rules, load_policy_rules  # noqa: E402


class PolicyEngineTests(unittest.TestCase):
    def test_load_rules_pack(self) -> None:
        pack = load_policy_rules()
        self.assertEqual(pack["policy_id"], "risk-identification-default")
        self.assertGreaterEqual(len(pack.get("rules") or []), 20)

    def test_web_shell_force_alert(self) -> None:
        item = {
            "risk_module": "exec",
            "severity": "P1",
            "listener_process": "nginx",
            "listener_port": "80",
            "command": '["sh","-c","id"]',
            "matched_rules": ["external_listener_shell_exec"],
        }
        decision = evaluate_item_declarative(item, get_policy_rules())
        self.assertEqual(decision.rule_id, "WEB-SHELL-001")
        self.assertTrue(decision.alert_required)

    def test_ops_ssh_downgrade(self) -> None:
        item = {
            "risk_module": "exec",
            "severity": "P0",
            "listener_process": "sshd",
            "listener_port": "22",
            "command": "grep ERROR /var/log/messages",
            "matched_rules": ["noise_command"],
        }
        decision = evaluate_item_declarative(item, get_policy_rules())
        self.assertEqual(decision.rule_id, "OPS-SSH-001")
        self.assertTrue(decision.alert_suppressed)

    def test_apply_behavior_policy_integration(self) -> None:
        items = [
            {
                "risk_id": "r1",
                "risk_module": "ssh",
                "severity": "P0",
                "matched_rules": ["ssh_bruteforce"],
            }
        ]
        out, hits, meta = apply_behavior_policy(items)
        self.assertEqual(meta.get("rules_engine"), "policy_engine_v3")
        self.assertFalse(Path(meta["path"]).is_absolute())
        self.assertFalse(Path(meta["rules_pack"]).is_absolute())
        self.assertEqual(out[0]["policy_rule_id"], "SSH-BRUTE-001")
        self.assertTrue(out[0]["alert_required"])
        self.assertEqual(hits[0]["rule_id"], "SSH-BRUTE-001")

    def test_json_predicate_plugin(self) -> None:
        import json
        import tempfile

        default = load_policy_rules()
        pack = dict(default)
        pack["policy_id"] = "test-custom-predicate"
        pack["predicates"] = dict(pack.get("predicates") or {})
        pack["predicates"]["is_healthcheck"] = {"command_contains": "healthcheck.sh"}
        pack["rules"] = list(pack.get("rules") or []) + [
            {
                "id": "OPS-TEST-HEALTH-001",
                "tier": "downgrade",
                "modules": ["exec"],
                "when": {"predicate": "is_healthcheck"},
                "decision": {
                    "severity": "P3",
                    "alert_required": False,
                    "alert_suppressed": True,
                    "verdict": "benign",
                    "recommended_action": "log_only",
                    "reason": "healthcheck script",
                },
            }
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            json.dump(pack, handle, ensure_ascii=False, indent=2)
            path = handle.name
        item = {
            "risk_module": "exec",
            "severity": "P0",
            "listener_process": "sshd",
            "listener_port": "22",
            "command": "/opt/company/healthcheck.sh",
            "matched_rules": ["external_listener_shell_exec"],
        }
        from policy_engine import evaluate_item_with_engine

        updated, hit = evaluate_item_with_engine(item, rules_path=path)
        self.assertEqual(hit["rule_id"], "OPS-TEST-HEALTH-001")
        self.assertTrue(updated["alert_suppressed"])


if __name__ == "__main__":
    unittest.main()
