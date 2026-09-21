#!/usr/bin/env python3
"""Tests for declarative trace_profile engine."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trace_profile import (  # noqa: E402
    exec_session_signals,
    extract_ssh_lateral_targets,
    is_web_listener_exec,
    load_trace_profile_template,
    repair_event,
    resolve_trace_profile,
    syslog_to_ssh_auth_event,
)


class TraceProfileTests(unittest.TestCase):
    def test_load_tigersec_syslog_template(self) -> None:
        profile = load_trace_profile_template("secweaver-syslog-risk-alert")
        # dataasset_my resolves the compatibility id to the deployed TigerSec profile.
        self.assertIn(profile["profile_id"], {"secweaver-syslog-risk-alert", "tigersec-syslog-risk-alert"})
        self.assertTrue(profile.get("event_repairs"))

    def test_repair_unwraps_json_content(self) -> None:
        profile = load_trace_profile_template("secweaver-syslog-risk-alert")
        wrapped = {
            "content": '{"event_type":"ssh_login_success","user":"root","src_ip":"192.0.2.91"}',
            "__source__": "192.0.2.92",
        }
        fixed = repair_event(wrapped, profile)
        self.assertEqual(fixed["event_type"], "ssh_login_success")
        self.assertEqual(fixed["host_ip"], "192.0.2.92")

    def test_resolve_from_asset_id(self) -> None:
        asset = {"asset_type": "host_exec", "trace_profile_id": "secweaver-host-exec"}
        profile = resolve_trace_profile(asset)
        assert profile is not None
        # Keep the test valid for both the public compatibility root and dataasset_my.
        self.assertIn(profile["profile_id"], {"secweaver-host-exec", "tigersec-host-exec"})

    def test_ssh_auth_derivation(self) -> None:
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

    def test_ssh_auth_derivation_keeps_rule_and_raw_message(self) -> None:
        ev = {
            "event_type": "ssh_login_success",
            "rule_id": "secure_ssh_login_success",
            "host_ip": "192.0.2.92",
            "src_ip": "192.0.2.91",
            "user": "devops",
            "message": "Accepted password for devops from 192.0.2.91 port 52844 ssh2",
        }
        ssh = syslog_to_ssh_auth_event(ev)
        self.assertIsNotNone(ssh)
        assert ssh is not None
        self.assertEqual(ssh["event_type"], "ssh_login_success")
        self.assertEqual(ssh["rule_id"], "secure_ssh_login_success")
        self.assertIn("Accepted password", ssh["raw_behavior"])

    def test_ssh_auth_derivation_falls_back_to_message_identity(self) -> None:
        ssh = syslog_to_ssh_auth_event(
            {
                "event_type": "ssh_login_success",
                "rule_id": "secure_ssh_login_success",
                "host_ip": "192.0.2.92",
                "message": "Accepted password for devops from 192.0.2.91 port 52844 ssh2",
            }
        )
        self.assertIsNotNone(ssh)
        assert ssh is not None
        self.assertEqual(ssh["src_ip"], "192.0.2.91")
        self.assertEqual(ssh["user"], "devops")
        self.assertEqual(ssh["port"], "52844")

    def test_exec_session_signals_webshell_no_tty(self) -> None:
        profile = load_trace_profile_template("secweaver-host-exec")
        ev = {"has_tty": False, "tty": "(none)"}
        signals = exec_session_signals(ev, profile)
        self.assertTrue(signals["non_interactive"])

    def test_exec_session_signals_missing_tty_remains_unknown(self) -> None:
        profile = load_trace_profile_template("secweaver-host-exec")
        signals = exec_session_signals({}, profile)
        self.assertIsNone(signals["has_tty"])
        self.assertIsNone(signals["non_interactive"])

    def test_is_web_listener_exec_nginx(self) -> None:
        profile = load_trace_profile_template("secweaver-host-exec")
        ev = {
            "listener_process": "nginx",
            "listener_port": "80",
            "has_tty": False,
            "command": '["sh","-c","id"]',
        }
        self.assertTrue(is_web_listener_exec(ev, [], profile))

    def test_extract_ssh_lateral_targets(self) -> None:
        profile = load_trace_profile_template("secweaver-host-exec")
        text = 'sshpass -p x ssh devops@192.0.2.92 "id"'
        targets = extract_ssh_lateral_targets(text, profile)
        self.assertIn(("devops", "192.0.2.92"), targets)


if __name__ == "__main__":
    unittest.main()
