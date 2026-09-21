#!/usr/bin/env python3
"""Tests for shared syslog_risk_normalize."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from syslog_risk_normalize import is_null_field, repair_syslog_risk_event, syslog_to_ssh_auth_event


class SharedSyslogNormalizeTests(unittest.TestCase):
    def test_is_null_field(self) -> None:
        self.assertTrue(is_null_field("null"))
        self.assertTrue(is_null_field(None))
        self.assertFalse(is_null_field("ssh_login_success"))

    def test_repair_keeps_valid_event(self) -> None:
        ev = {"event_type": "sudo_command", "host": "192.0.2.92", "user": "root"}
        self.assertEqual(repair_syslog_risk_event(ev)["event_type"], "sudo_command")

    def test_repair_maps_source_to_host_ip(self) -> None:
        ev = {
            "__source__": "192.0.2.92",
            "event_type": "ssh_login_success",
            "src_ip": "192.0.2.91",
            "host_name": "localhost.localdomain",
        }
        fixed = repair_syslog_risk_event(ev)
        self.assertEqual(fixed["host_ip"], "192.0.2.92")
        self.assertEqual(fixed["host"], "192.0.2.92")

    def test_ssh_auth_failed_mapping(self) -> None:
        ev = {
            "event_type": "ssh_login_failed",
            "host_ip": "192.0.2.92",
            "src_ip": "192.0.2.91",
            "user": "devops",
            "timestamp": "2026-07-01T17:20:00+08:00",
        }
        ssh = syslog_to_ssh_auth_event(ev)
        self.assertIsNotNone(ssh)
        assert ssh is not None
        self.assertEqual(ssh["result"], "failed")


if __name__ == "__main__":
    unittest.main()
