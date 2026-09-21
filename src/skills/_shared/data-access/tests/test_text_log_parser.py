"""Tests for config-driven text log parsing."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from text_log_parser import parse_log_lines, parse_text_line, resolve_text_parser_id  # noqa: E402


class TestTextLogParser(unittest.TestCase):
    def test_resolve_from_asset_config(self) -> None:
        asset = {"asset_type": "ssh_auth", "text_parser": "syslog_auth"}
        self.assertEqual(resolve_text_parser_id(asset, log_path="/var/log/messages"), "syslog_auth")

    def test_parse_syslog_auth(self) -> None:
        line = "Jun 21 08:15:01 web-01 sshd[1]: Accepted publickey for deploy from 203.0.113.10 port 22"
        ev = parse_text_line(line, parser_id="syslog_auth", host="web-01")
        self.assertEqual(ev["user"], "deploy")
        self.assertEqual(ev["src_ip"], "203.0.113.10")

    def test_parse_json_lines(self) -> None:
        line = '{"client_ip":"203.0.113.10","url":"/api"}'
        ev = parse_text_line(line, parser_id="json_lines", host="web-01")
        self.assertEqual(ev["client_ip"], "203.0.113.10")

    def test_parse_json_lines2_expands_nested_json_fields(self) -> None:
        line = '{"event_type":"ssh_login","fields":"{\\"user\\":\\"root(uid=0\\",\\"session\\":{\\"tty\\":\\"pts/0\\"}}"}'
        ev = parse_text_line(line, parser_id="json_lines2", host="web-01")
        self.assertEqual(ev["event_type"], "ssh_login")
        self.assertEqual(ev["fields.user"], "root(uid=0")
        self.assertEqual(ev["fields.session.tty"], "pts/0")

    def test_batch(self) -> None:
        raw = "Jun 21 08:15:01 web-01 sshd[1]: Failed password for root from 10.0.0.1 port 22\n"
        asset = {"asset_type": "ssh_auth", "text_parser": "syslog_auth"}
        events = parse_log_lines(raw, asset=asset, host="web-01", log_path="/var/log/auth.log")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["result"], "Failed")


if __name__ == "__main__":
    unittest.main()
