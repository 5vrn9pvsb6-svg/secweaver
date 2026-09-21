"""Tests for traceability D1 attacker IP bootstrap."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

DATA_ACCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DATA_ACCESS))

from trace_d1_bootstrap import (  # noqa: E402
    build_attacker_ip_resolution,
    extract_attacker_ips_from_d1,
    resolve_target_ip,
    should_trace_d1_bootstrap,
    victim_field_matches,
)


class TraceD1BootstrapTests(unittest.TestCase):
    def test_resolve_target_ip_from_hosts(self) -> None:
        self.assertEqual(resolve_target_ip({"hosts": ["192.0.2.91"]}), "192.0.2.91")

    def test_victim_field_matches_upstream_with_port(self) -> None:
        ev = {"upstream_addr": "192.0.2.91:80", "remote_addr": "39.144.124.99"}
        self.assertTrue(victim_field_matches(ev, "192.0.2.91"))

    def test_extract_attacker_ips_from_web_access(self) -> None:
        web = [
            {
                "remote_addr": "39.144.124.99",
                "upstream_addr": "192.0.2.91:80",
                "request_uri": "/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
            },
            {
                "remote_addr": "10.0.0.1",
                "upstream_addr": "192.0.2.91:80",
            },
        ]
        ips = extract_attacker_ips_from_d1(web, target_ip="192.0.2.91")
        self.assertEqual(ips, ["39.144.124.99"])

    def test_extract_private_attacker_ips_only_when_enabled(self) -> None:
        web = [
            {
                "remote_addr": "192.168.99.61",
                "upstream_addr": "192.0.2.91:80",
            }
        ]

        self.assertEqual(extract_attacker_ips_from_d1(web, target_ip="192.0.2.91"), [])
        self.assertEqual(
            extract_attacker_ips_from_d1(web, target_ip="192.0.2.91", include_private=True),
            ["192.168.99.61"],
        )

    def test_should_trace_d1_bootstrap_when_victim_only(self) -> None:
        self.assertTrue(
            should_trace_d1_bootstrap(
                ["S2", "S5"],
                ["S2_web_breach"],
                {"hosts": ["192.0.2.91"], "time_start": "2026-07-05T21:30:00+08:00"},
            )
        )

    def test_should_trace_d1_bootstrap_over_s4_when_target_ip(self) -> None:
        self.assertTrue(
            should_trace_d1_bootstrap(
                ["S4"],
                ["S4_alert_confirmation"],
                {
                    "target_ip": "192.0.2.91",
                    "time_start": "2026-07-05T21:30:00+08:00",
                },
            )
        )

    def test_should_not_bootstrap_when_attacker_known(self) -> None:
        self.assertFalse(
            should_trace_d1_bootstrap(
                ["S2"],
                ["S2_web_breach"],
                {
                    "attacker_ip": "1.2.3.4",
                    "hosts": ["192.0.2.91"],
                    "time_start": "2026-07-05T21:30:00+08:00",
                },
            )
        )

    def test_build_attacker_ip_resolution_d1(self) -> None:
        block = build_attacker_ip_resolution(
            {"target_ip": "192.0.2.91", "attacker_ip": "39.144.124.99"},
            "39.144.124.99",
            {"attacker_ip": "39.144.124.99", "correlation_source": "victim_target_ip"},
            {
                "trace_d1_bootstrap": {
                    "attacker_ips": ["39.144.124.99"],
                    "web_access_event_count": 47,
                    "waf_event_count": 1,
                }
            },
        )
        self.assertTrue(block["resolved"])
        self.assertEqual(block["method"], "d1_reverse_lookup")
        self.assertEqual(block["web_access_event_count"], 47)

    def test_build_attacker_ip_resolution_private_d1(self) -> None:
        block = build_attacker_ip_resolution(
            {"target_ip": "192.0.2.91", "attacker_ip": "192.168.99.61"},
            "192.168.99.61",
            {"attacker_ip": "192.168.99.61", "correlation_source": "victim_target_ip"},
            {
                "trace_d1_bootstrap": {
                    "attacker_ips": ["192.168.99.61"],
                    "attacker_ip_scope": "private",
                    "web_access_event_count": 40,
                    "waf_event_count": 22,
                }
            },
        )

        self.assertEqual(block["method"], "d1_reverse_lookup_private")
        self.assertEqual(block["attacker_ip_scope"], "private")


if __name__ == "__main__":
    unittest.main()
