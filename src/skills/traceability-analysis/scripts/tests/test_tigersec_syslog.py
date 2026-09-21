#!/usr/bin/env python3
"""Tests for syslog_risk_alert normalization and traceability lateral confirm."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

DATA_ACCESS = Path(__file__).resolve().parents[3] / "_shared" / "data-access"
TRACE_SCRIPTS = Path(__file__).resolve().parents[1]
if str(DATA_ACCESS) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS))
if str(TRACE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(TRACE_SCRIPTS))

from syslog_risk_normalize import (  # noqa: E402
    inject_ssh_auth_from_syslog_risk,
    repair_syslog_risk_event,
    syslog_to_ssh_auth_event,
)
from source_adapters.tigersec_syslog import (  # noqa: E402
    find_lateral_confirmations_from_syslog,
    upgrade_suspected_lateral_with_syslog,
)


SAMPLE_LOGIN = {
    "timestamp": "2026-07-01T17:23:10+08:00",
    "host_name": "localhost.localdomain",
    "__source__": "192.0.2.92",
    "event_type": "ssh_login_success",
    "severity": "high",
    "risk_level": "high",
    "rule_name": "SSH successful login",
    "user": "devops",
    "src_ip": "192.0.2.91",
    "port": "22",
    "message": "Accepted password for devops from 192.0.2.91 port 22 ssh2",
    "evidence_id": "syslog-risk-test-001",
}


class SyslogRiskNormalizeTests(unittest.TestCase):
    def test_repair_unwraps_json_content(self) -> None:
        inner = dict(SAMPLE_LOGIN)
        wrapped = {"content": json.dumps(inner), "event_type": "null", "host_name": "null"}
        fixed = repair_syslog_risk_event(wrapped)
        self.assertEqual(fixed["event_type"], "ssh_login_success")
        self.assertEqual(fixed["src_ip"], "192.0.2.91")

    def test_syslog_to_ssh_auth_success(self) -> None:
        ssh = syslog_to_ssh_auth_event(SAMPLE_LOGIN)
        self.assertIsNotNone(ssh)
        assert ssh is not None
        self.assertEqual(ssh["result"], "accepted")
        self.assertEqual(ssh["src_ip"], "192.0.2.91")
        self.assertEqual(ssh["_derived_from"], "syslog_risk_alert")

    def test_inject_ssh_auth_from_syslog(self) -> None:
        bundles, n = inject_ssh_auth_from_syslog_risk({"syslog_risk_alert": [SAMPLE_LOGIN]})
        self.assertEqual(n, 1)
        self.assertEqual(len(bundles["ssh_auth"]), 1)
        self.assertEqual(bundles["ssh_auth"][0]["result"], "accepted")


class SyslogLateralConfirmTests(unittest.TestCase):
    def test_confirm_91_to_92_login(self) -> None:
        hits = find_lateral_confirmations_from_syslog(
            [SAMPLE_LOGIN],
            source_hosts={"192.0.2.91"},
            target_hosts={"192.0.2.92"},
            anchor=None,
            t_end=None,
        )
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["lateral_class"], "confirmed_lateral")
        self.assertEqual(hits[0]["host"], "192.0.2.92")

    def test_confirm_91_to_92_login_from_message_only_identity(self) -> None:
        event = dict(SAMPLE_LOGIN)
        event.pop("src_ip")
        event.pop("user")
        hits = find_lateral_confirmations_from_syslog(
            [event],
            source_hosts={"192.0.2.91"},
            target_hosts={"192.0.2.92"},
            anchor=None,
            t_end=None,
        )
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["source_host"], "192.0.2.91")
        self.assertEqual(hits[0]["user"], "devops")

    def test_upgrade_suspected_lateral(self) -> None:
        suspected = [
            {
                "stage": "lateral_movement",
                "timestamp": "2026-07-01T17:22:50+08:00",
                "host": "192.0.2.92",
                "source_host": "192.0.2.91",
                "lateral_class": "suspected_lateral",
                "confidence": 0.78,
                "description": "exec 推断",
                "evidence_refs": ["host-exec-test-001"],
                "join_ids": ["lateral_from_exec"],
            }
        ]
        confirmed = find_lateral_confirmations_from_syslog(
            [SAMPLE_LOGIN],
            source_hosts={"192.0.2.91"},
            target_hosts={"192.0.2.92"},
            anchor=None,
            t_end=None,
        )
        upgraded = upgrade_suspected_lateral_with_syslog(suspected, confirmed)
        self.assertEqual(upgraded[0]["lateral_class"], "confirmed_lateral")
        self.assertGreaterEqual(upgraded[0]["confidence"], 0.92)
        self.assertIn("host-exec-test-001", upgraded[0]["evidence_refs"])
        self.assertIn("syslog-risk-test-001", upgraded[0]["evidence_refs"])
        self.assertIn("lateral_from_syslog", upgraded[0]["join_ids"])
        self.assertEqual(upgraded[0]["attempt_timestamp"], "2026-07-01T17:22:50+08:00")
        self.assertEqual(upgraded[0]["confirmed_timestamp"], "2026-07-01T17:23:10+08:00")


if __name__ == "__main__":
    unittest.main()
