#!/usr/bin/env python3
"""Tests for risk-identification event filtering helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from assess import dedupe_items, event_timestamp, filter_events, host_matches, related_in_window  # noqa: E402


class TestAssessFilters(unittest.TestCase):
    def test_host_matches_uses_host_ip(self) -> None:
        ev = {
            "host": "localhost.localdomain",
            "host_ip": "192.0.2.91",
        }
        self.assertTrue(host_matches(ev, {"hosts": ["192.0.2.91"]}))
        self.assertFalse(host_matches(ev, {"hosts": ["192.0.2.92"]}))

    def test_filter_events_uses_time_field(self) -> None:
        events = [
            {
                "host_ip": "192.0.2.91",
                "host": "192.0.2.91",
                "time": "2026-07-01T10:00:00+08:00",
            }
        ]
        filtered = filter_events(
            events,
            {
                "hosts": ["192.0.2.91"],
                "time_start": "2026-07-01T00:00:00+08:00",
                "time_end": "2026-07-02T00:00:00+08:00",
            },
        )
        self.assertEqual(len(filtered), 1)
        self.assertEqual(event_timestamp(filtered[0]), "2026-07-01T10:00:00+08:00")

    def test_related_in_window_uses_host_ip_when_host_is_generic(self) -> None:
        anchor = {
            "host": "localhost.localdomain",
            "host_ip": "192.0.2.91",
            "timestamp": "2026-07-01T10:00:00+08:00",
            "listener_pid": 123,
        }
        events = [
            {
                "host": "192.0.2.91",
                "host_ip": "192.0.2.91",
                "timestamp": "2026-07-01T10:00:01+08:00",
                "listener_pid": 123,
            }
        ]
        self.assertEqual(related_in_window(anchor, events), events)

    def test_dedupe_items_keeps_highest_severity(self) -> None:
        items = [
            {
                "risk_module": "exec",
                "host": "192.0.2.91",
                "timestamp": "2026-07-01T10:00:00+08:00",
                "listener_port": 80,
                "severity": "P2",
                "matched_rules": ["noise_command"],
                "evidence_refs": ["exec-1"],
            },
            {
                "risk_module": "exec",
                "host": "192.0.2.91",
                "timestamp": "2026-07-01T10:00:00+08:00",
                "listener_port": 80,
                "severity": "P0",
                "matched_rules": ["external_listener_shell_exec"],
                "evidence_refs": ["exec-1"],
            },
        ]
        out = dedupe_items(items)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "P0")
        self.assertIn("external_listener_shell_exec", out[0]["matched_rules"])
        self.assertIn("noise_command", out[0]["matched_rules"])


if __name__ == "__main__":
    unittest.main()
