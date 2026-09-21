"""Unit tests for SSH log fetch (no live SSH required)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssh_fetch import (  # noqa: E402
    enrich_ssh_params,
    parse_auth_line,
    parse_nginx_line,
    validate_ssh_command,
)


CONNECTOR = {
    "connector_id": "conn-ssh-web-01-auth",
    "connector_type": "ssh_file",
    "config": {
        "host": "10.0.1.5",
        "hostname": "web-01",
        "log_paths": {
            "ssh_auth": "/var/log/auth.log",
            "web_access_log": "/var/log/nginx/access.log",
        },
    },
    "constraints": {
        "max_lines_per_query": 10000,
        "allowed_grep_patterns": ["Accepted", "Failed", "sshd"],
        "forbidden_paths": ["/etc/shadow"],
    },
}


class TestValidateSshCommand(unittest.TestCase):
    def test_valid_grep_tail(self) -> None:
        cmd = "grep -E '203.0.113.10' /var/log/auth.log | tail -n 500"
        meta = validate_ssh_command(cmd, CONNECTOR)
        self.assertEqual(meta["grep_pattern"], "203.0.113.10")
        self.assertEqual(meta["log_path"], "/var/log/auth.log")

    def test_reject_shell_injection(self) -> None:
        cmd = "grep -E 'x; rm -rf /' /var/log/auth.log | tail -n 10"
        with self.assertRaises(ValueError):
            validate_ssh_command(cmd, CONNECTOR)

    def test_reject_forbidden_path(self) -> None:
        cmd = "grep -E 'root' /etc/shadow | tail -n 10"
        with self.assertRaises(ValueError):
            validate_ssh_command(cmd, CONNECTOR)

    def test_reject_unknown_path(self) -> None:
        cmd = "grep -E 'root' /tmp/secret.log | tail -n 10"
        with self.assertRaises(ValueError):
            validate_ssh_command(cmd, CONNECTOR)


class TestParseLines(unittest.TestCase):
    def test_auth_accepted(self) -> None:
        line = (
            "Jun 21 08:15:01 web-01 sshd[12345]: Accepted publickey for deploy "
            "from 203.0.113.10 port 54321 ssh2"
        )
        ev = parse_auth_line(line, host="web-01")
        assert ev is not None
        self.assertEqual(ev["src_ip"], "203.0.113.10")
        self.assertEqual(ev["user"], "deploy")
        self.assertEqual(ev["result"], "Accepted")

    def test_auth_failed(self) -> None:
        line = "Jun 21 09:00:00 web-01 sshd[99]: Failed password for invalid user admin from 10.0.1.9 port 22 ssh2"
        ev = parse_auth_line(line, host="web-01")
        assert ev is not None
        self.assertEqual(ev["result"], "Failed")
        self.assertEqual(ev["src_ip"], "10.0.1.9")

    def test_nginx_access(self) -> None:
        line = (
            '203.0.113.10 - - [21/Jun/2026:08:15:01 +0800] "GET /api HTTP/1.1" 200 1234'
        )
        ev = parse_nginx_line(line, host="web-01")
        assert ev is not None
        self.assertEqual(ev["src_ip"], "203.0.113.10")
        self.assertEqual(ev["url"], "/api")
        self.assertEqual(ev["status"], 200)


class TestEnrichParams(unittest.TestCase):
    def test_src_ip_to_grep_pattern(self) -> None:
        asset = {"asset_type": "ssh_auth"}
        out = enrich_ssh_params(
            asset,
            CONNECTOR,
            {"attacker_ip": "203.0.113.10"},
        )
        self.assertEqual(out["grep_pattern"], "203.0.113.10")
        self.assertEqual(out["log_path"], "/var/log/auth.log")


if __name__ == "__main__":
    unittest.main()
