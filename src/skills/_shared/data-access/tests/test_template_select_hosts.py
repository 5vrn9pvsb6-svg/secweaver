#!/usr/bin/env python3
"""Tests for multi-host fetch param expansion and template ordering."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from template_select import expand_multi_host_fetch_params, ordered_template_candidates  # noqa: E402


class TestTemplateSelectHosts(unittest.TestCase):
    def test_expand_multi_host_fetch_params(self) -> None:
        expanded = expand_multi_host_fetch_params(
            {
                "hosts": ["192.0.2.91", "192.0.2.92"],
                "time_start": "2026-07-01T00:00:00+08:00",
                "time_end": "2026-07-02T00:00:00+08:00",
            }
        )
        self.assertEqual(len(expanded), 2)
        self.assertEqual(expanded[0]["host_ip"], "192.0.2.91")
        self.assertEqual(expanded[1]["host_ip"], "192.0.2.92")

    def test_ordered_template_prefers_host_ip_template(self) -> None:
        asset = {
            "query_template_ids": [
                "host_exec_by_time",
                "host_exec_by_host_ip_time",
                "host_exec_by_host_time",
            ]
        }
        ordered = ordered_template_candidates(
            asset,
            {"host_ip": "192.0.2.91", "time_start": "t0", "time_end": "t1", "limit": 10},
        )
        self.assertEqual(ordered[0], "host_exec_by_host_ip_time")
        self.assertNotEqual(ordered[0], "host_exec_by_time")


if __name__ == "__main__":
    unittest.main()
