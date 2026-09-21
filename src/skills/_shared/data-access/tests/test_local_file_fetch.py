"""Unit tests for local file log fetch (no live filesystem outside temp)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[3]
sys.path.insert(0, str(ROOT))

from local_file_fetch import fetch_local_file, read_grep_tail, resolve_log_path  # noqa: E402


SAMPLE = REPO_ROOT / "dataasset" / "samples" / "local-logs" / "web-01" / "auth.log"


class TestLocalFileFetch(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        log = self.base / "auth.log"
        log.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
        self.connector = {
            "connector_id": "conn-local-test",
            "connector_type": "local_file",
            "config": {
                "hostname": "web-01",
                "base_path": str(self.base),
                "log_paths": {"ssh_auth": "auth.log"},
            },
            "constraints": {
                "max_lines_per_query": 10000,
                "allowed_grep_patterns": ["Accepted", "Failed", "sshd"],
                "forbidden_paths": ["/etc/shadow"],
            },
        }
        self.asset = {"asset_type": "ssh_auth", "text_parser": "syslog_auth"}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_resolve_relative_path(self) -> None:
        path = resolve_log_path(self.connector, "auth.log")
        self.assertTrue(path.is_file())

    def test_read_grep_tail(self) -> None:
        path = self.base / "auth.log"
        raw = read_grep_tail(path, "203.0.113.10", 500)
        self.assertIn("203.0.113.10", raw)
        self.assertEqual(len(raw.splitlines()), 2)

    def test_fetch_local_file(self) -> None:
        cmd = "grep -E '203.0.113.10' auth.log | tail -n 500"
        events, meta = fetch_local_file(self.asset, self.connector, cmd)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["src_ip"], "203.0.113.10")
        self.assertEqual(meta["rows_returned"], 2)

    def test_reject_path_traversal(self) -> None:
        with self.assertRaises(ValueError):
            resolve_log_path(self.connector, "../outside.log")


if __name__ == "__main__":
    unittest.main()
