#!/usr/bin/env python3
"""Tests for gateway_success_hint in alert-confirmation."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_ROOT = SKILL_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import confirm  # noqa: E402


def load_catalog() -> dict:
    with (SKILL_ROOT / "attack-types.json").open(encoding="utf-8") as f:
        return json.load(f)


def load_fp() -> dict:
    with (SKILL_ROOT / "fp-patterns.json").open(encoding="utf-8") as f:
        return json.load(f)


class GatewaySuccessHintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_catalog()
        self.fp = load_fp()

    def test_waf_pass_sqli_200_likely(self) -> None:
        alert = {
            "alert_id": "waf-pass-sqli",
            "timestamp": "2026-07-04T22:45:23+08:00",
            "src_ip": "38.148.253.160",
            "url": "https://test.example/sqli/search.php?q='+UNION+SELECT+1,version(),user()--+-",
            "payload": "https://test.example/sqli/search.php?q='+UNION+SELECT+1,version(),user()--+-",
            "rule_name": "PHP动态函数调用行为",
            "action": "pass",
        }
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-sqli-1",
                    "src_ip": "38.148.253.160",
                    "timestamp": "2026-07-04T22:45:23+08:00",
                    "url": "/sqli/search.php?q='+UNION+SELECT+1,version(),user()--+-",
                    "status": 200,
                    "upstream_status": 200,
                    "bytes_sent": 707,
                }
            ],
            "host_exec": [{"evidence_id": "exec-1", "host_ip": "10.0.0.1", "timestamp": "2026-07-04T22:50:00+08:00", "command": ["sshd"]}],
        }
        result = confirm.confirm_alert(alert, evidence, None, self.catalog, self.fp)
        hint = result.get("gateway_success_hint")
        self.assertIsNotNone(hint)
        self.assertEqual(hint["level"], "likely")
        self.assertEqual(result["attack_outcome"], "attempt_failed")
        self.assertFalse(result["attack_success"])
        self.assertEqual(result["recommended_action"], "manual_review_30m")
        self.assertIn("web-sqli-1", hint["evidence_refs"])

    def test_waf_block_but_gateway_200_bypass(self) -> None:
        alert = {
            "alert_id": "waf-block-cmdi",
            "timestamp": "2026-07-04T23:34:28+08:00",
            "src_ip": "38.148.253.160",
            "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;cat+/etc/passwd",
            "payload": "/cmdi/diag.php?tool=ping&host=127.0.0.1;cat+/etc/passwd",
            "rule_name": "危险文件尝试",
            "action": "block",
        }
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-cmdi-1",
                    "src_ip": "38.148.253.160",
                    "timestamp": "2026-07-04T23:34:28+08:00",
                    "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;cat+/etc/passwd",
                    "status": 200,
                    "upstream_status": 200,
                    "bytes_sent": 1924,
                }
            ],
            "host_exec": [],
        }
        result = confirm.confirm_alert(alert, evidence, None, self.catalog, self.fp)
        hint = result.get("gateway_success_hint")
        self.assertIsNotNone(hint)
        self.assertEqual(hint["level"], "likely")
        self.assertEqual(result["attack_outcome"], "blocked")
        self.assertFalse(result["attack_success"])
        self.assertEqual(hint["reason"], "waf_block_bypass_backend_200")

    def test_gateway_403_no_hint(self) -> None:
        alert = {
            "alert_id": "waf-block-403",
            "timestamp": "2026-06-21T14:30:05+08:00",
            "src_ip": "203.0.113.10",
            "url": "/api/user?id=1' OR 1=1--",
            "payload": "id=1' OR 1=1--",
            "rule_name": "SQL Injection",
            "action": "blocked",
        }
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-403",
                    "src_ip": "203.0.113.10",
                    "timestamp": "2026-06-21T14:30:04+08:00",
                    "url": "/api/user?id=1' OR 1=1--",
                    "status": 403,
                }
            ]
        }
        result = confirm.confirm_alert(alert, evidence, None, self.catalog, self.fp)
        self.assertIsNone(result.get("gateway_success_hint"))

    def test_d2_success_confirmed_no_gateway_hint(self) -> None:
        alert = {
            "alert_id": "success-shell",
            "timestamp": "2026-06-21T14:30:05+08:00",
            "src_ip": "203.0.113.10",
            "url": "/upload/shell.php?cmd=whoami",
            "payload": "cmd=whoami",
            "rule_name": "WebShell",
            "action": "pass",
            "host": "web-01",
        }
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-shell",
                    "src_ip": "203.0.113.10",
                    "target_ip": "web-01",
                    "timestamp": "2026-06-21T14:30:06+08:00",
                    "url": "/upload/shell.php?cmd=whoami",
                    "status": 200,
                    "bytes_sent": 120,
                }
            ],
            "host_exec": [
                {
                    "evidence_id": "exec-shell",
                    "host": "web-01",
                    "timestamp": "2026-06-21T14:30:10+08:00",
                    "command": ["whoami"],
                }
            ],
        }
        result = confirm.confirm_alert(alert, evidence, None, self.catalog, self.fp)
        self.assertEqual(result["attack_outcome"], "success_confirmed")
        self.assertIsNone(result.get("gateway_success_hint"))


if __name__ == "__main__":
    unittest.main()
