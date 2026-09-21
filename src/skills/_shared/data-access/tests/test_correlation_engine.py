"""Tests for correlation_engine."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from correlation_engine import (  # noqa: E402
    apply_investigation_param_aliases,
    correlate_bundles,
    expand_path,
    extract_ip_addresses,
    fill_investigation_window,
    find_join_pairs,
    in_time_window,
    match_join_pair,
    normalize_url_path,
    plan_fetch,
    resolve_anchor_params,
    time_window_bounds,
    values_match,
)


class TestCorrelationEngine(unittest.TestCase):
    def test_expand_path_composite(self) -> None:
        steps = expand_path("waf_to_host_exec_via_web_access")
        self.assertEqual(
            steps,
            ["waf_to_web_access_by_ip", "web_access_to_host_exec"],
        )

    def test_path_prefix_match(self) -> None:
        self.assertTrue(
            values_match(
                "https://web.example.com/api/upload.php?x=1",
                "/api/upload.php",
                "path_prefix",
            )
        )

    def test_exact_ip_match_normalizes_export_quote(self) -> None:
        self.assertTrue(
            values_match(
                '"203.0.113.10',
                "203.0.113.10",
                "exact",
                left_field="src_ip",
                right_field="src_ip",
            )
        )

    def test_hostname_to_ip_via_cmdb(self) -> None:
        self.assertTrue(
            values_match(
                "web-01",
                "10.0.1.5",
                "hostname_to_ip_via_cmdb",
                host_ip_map={"web-01": "10.0.1.5"},
            )
        )

    def test_dns_answer_ip(self) -> None:
        self.assertTrue(
            values_match(
                "198.51.100.5",
                "evil.example A 198.51.100.5",
                "dns_answer_ip",
            )
        )
        self.assertIn("198.51.100.5", extract_ip_addresses('{"A":["198.51.100.5"]}'))

    def test_d2_exec_connect_join(self) -> None:
        bundles = {
            "host_exec": [
                {
                    "evidence_id": "exec-001",
                    "host_name": "web-01",
                    "timestamp": "2026-06-21T09:15:22+08:00",
                    "listener_pid": 1234,
                    "listener_port": 443,
                }
            ],
            "host_connect": [
                {
                    "evidence_id": "connect-001",
                    "host_name": "web-01",
                    "timestamp": "2026-06-21T09:15:25+08:00",
                    "listener_pid": 1234,
                    "listener_port": 443,
                    "dst_ip": "203.0.113.99",
                    "dst_port": 443,
                }
            ],
        }
        edges = find_join_pairs("d2_exec_connect_same_listener", bundles)
        self.assertGreaterEqual(len(edges), 1)
        edge = edges[0]
        self.assertEqual(edge["join_id"], "d2_exec_connect_same_listener")
        self.assertEqual(edge["left_ref"], "exec-001")
        self.assertEqual(edge["right_ref"], "connect-001")
        self.assertIn("host", edge["match_keys"])

    def test_waf_web_access_ip_join_raw_fields(self) -> None:
        left = {"evidence_id": "waf-1", "ip": "203.0.113.10", "timestamp": "2026-06-21T09:00:00+08:00"}
        right = {"evidence_id": "web-1", "src_ip": "203.0.113.10", "timestamp": "2026-06-21T09:00:05+08:00"}
        edge = match_join_pair("waf_to_web_access_by_ip", left, right)
        self.assertIsNotNone(edge)
        assert edge is not None
        self.assertEqual(edge["match_keys"]["src_ip"], "203.0.113.10")

    def test_attack_success_time_window(self) -> None:
        anchor = datetime(2026, 6, 21, 9, 0, tzinfo=timezone.utc)
        start, end = time_window_bounds(anchor, "attack_success")
        self.assertEqual((anchor - start).total_seconds(), 5 * 60)
        self.assertEqual((end - anchor).total_seconds(), 30 * 60)
        ev = datetime(2026, 6, 21, 9, 20, tzinfo=timezone.utc)
        self.assertTrue(in_time_window(ev, anchor, "attack_success"))

    def test_trace_default_investigation_window(self) -> None:
        out = fill_investigation_window(
            {"alert_time": "2026-06-21T10:00:00+08:00"},
            "trace_default",
        )
        self.assertEqual(out["time_start"], "2026-06-20T10:00:00+08:00")
        self.assertEqual(out["time_end"], "2026-06-21T16:00:00+08:00")

    def test_resolve_anchor_params_keeps_explicit_range(self) -> None:
        params = {
            "alert_time": "2026-06-21T10:00:00+08:00",
            "time_start": "2026-06-21T08:00:00+08:00",
            "time_end": "2026-06-21T20:00:00+08:00",
        }
        out = resolve_anchor_params("S1_external_ip_trace", params)
        self.assertEqual(out["time_start"], params["time_start"])
        self.assertEqual(out["time_end"], params["time_end"])

    def test_plan_fetch_s1_trace_default(self) -> None:
        tasks = plan_fetch(
            "S1_external_ip_trace",
            {
                "attacker_ip": "203.0.113.10",
                "alert_time": "2026-06-21T10:00:00+08:00",
            },
            asset_ids=["asset-waf-prod-01"],
        )
        self.assertTrue(tasks)
        self.assertEqual(tasks[0]["params"]["time_start"], "2026-06-20T10:00:00+08:00")
        self.assertEqual(tasks[0]["params"]["time_end"], "2026-06-21T16:00:00+08:00")

    def test_plan_fetch_uses_covered_asset_type(self) -> None:
        tasks = plan_fetch(
            "S1_external_ip_trace",
            {
                "attacker_ip": "203.0.113.10",
                "time_start": "2026-06-21T08:00:00+08:00",
                "time_end": "2026-06-21T20:00:00+08:00",
            },
            asset_ids=["asset-secweaver-sys-risk-alert"],
        )
        auth_tasks = [
            t
            for t in tasks
            if t["asset_id"] == "asset-secweaver-sys-risk-alert"
            and t["template_id"] == "ssh_auth_by_src_ip_time"
            and t["params"].get("src_ip") == "203.0.113.10"
        ]
        self.assertTrue(auth_tasks)
        self.assertEqual(auth_tasks[0]["asset_type"], "syslog_risk_alert")
        self.assertEqual(auth_tasks[0]["matched_asset_type"], "ssh_auth")

    def test_correlate_bundles_s4_chain(self) -> None:
        bundles = {
            "waf_alert": [
                {
                    "evidence_id": "waf-001",
                    "ip": "203.0.113.55",
                    "target_ip": "10.0.1.5",
                    "timestamp": "2026-06-22T09:08:05+08:00",
                }
            ],
            "web_access_log": [
                {
                    "evidence_id": "web-001",
                    "src_ip": "203.0.113.55",
                    "target_ip": "10.0.1.5",
                    "host": "web-01",
                    "timestamp": "2026-06-22T09:07:55+08:00",
                }
            ],
            "host_exec": [
                {
                    "evidence_id": "exec-001",
                    "host_ip": "10.0.1.5",
                    "host_name": "web-01",
                    "timestamp": "2026-06-22T09:10:00+08:00",
                    "command": "whoami",
                }
            ],
        }
        result = correlate_bundles(
            bundles,
            anchor_pattern_id="S4_alert_confirmation",
            params={"attacker_ip": "203.0.113.55", "target_ip": "10.0.1.5"},
        )
        join_ids = {e["join_id"] for e in result["join_edges"]}
        self.assertIn("waf_to_web_access_by_ip", join_ids)
        self.assertIn("waf_to_host_exec_direct", join_ids)

    def test_plan_fetch_s4(self) -> None:
        tasks = plan_fetch(
            "S4_alert_confirmation",
            {
                "attacker_ip": "203.0.113.10",
                "target_ip": "10.0.1.5",
                "time_start": "2026-06-21T08:00:00+08:00",
                "time_end": "2026-06-21T20:00:00+08:00",
            },
            asset_ids=["asset-waf-prod-01", "asset-secweaver-gateway-access", "asset-secweaver-host-exec"],
        )
        template_ids = {t["template_id"] for t in tasks}
        self.assertIn("waf_gateway_plugin_by_ip_time", template_ids)
        self.assertIn("web_access_by_remote_addr_time", template_ids)
        host_exec_tasks = [t for t in tasks if t["asset_type"] == "host_exec"]
        self.assertTrue(host_exec_tasks)
        self.assertEqual(host_exec_tasks[0]["template_id"], "host_exec_by_host_ip_time")
        self.assertEqual(host_exec_tasks[0]["params"]["host_ip"], "10.0.1.5")

    def test_normalize_url_path(self) -> None:
        self.assertEqual(
            normalize_url_path("https://x.com/api?id=1"),
            "/api?id=1",
        )

    def test_apply_investigation_param_aliases_seed_host(self) -> None:
        out = apply_investigation_param_aliases(
            {"seed_hosts": ["192.0.2.91"], "time_start": "2026-07-01T00:00:00+08:00"}
        )
        self.assertEqual(out["target_ip"], "192.0.2.91")

    def test_plan_fetch_s2_victim_target_ip(self) -> None:
        tasks = plan_fetch(
            "S2_web_breach",
            {
                "seed_hosts": ["192.0.2.91"],
                "time_start": "2026-07-01T00:00:00+08:00",
                "time_end": "2026-07-02T00:00:00+08:00",
            },
            asset_ids=[
                "asset-waf-prod-01",
                "asset-secweaver-gateway-access",
                "asset-secweaver-host-exec",
            ],
        )
        template_ids = {t["template_id"] for t in tasks}
        self.assertIn("waf_gateway_plugin_by_target_ip_time", template_ids)
        self.assertIn("web_access_by_target_ip_time", template_ids)
        waf_task = next(t for t in tasks if t["template_id"] == "waf_gateway_plugin_by_target_ip_time")
        self.assertEqual(waf_task["params"]["target_ip"], "192.0.2.91")

    def test_victim_host_to_waf_join(self) -> None:
        bundles = {
            "host_exec": [
                {
                    "evidence_id": "exec-v",
                    "host_ip": "192.0.2.91",
                    "timestamp": "2026-07-01T15:51:21+08:00",
                }
            ],
            "waf_alert": [
                {
                    "evidence_id": "waf-v",
                    "target_ip": "192.0.2.91",
                    "src_ip": "203.0.113.77",
                    "timestamp": "2026-07-01T15:51:10+08:00",
                    "url": "https://x/uploads/s.phtml",
                }
            ],
        }
        edges = find_join_pairs(
            "victim_host_to_waf_by_target_ip",
            bundles,
            anchor_ts=datetime(2026, 7, 1, 15, 51, 21, tzinfo=timezone.utc),
        )
        self.assertGreaterEqual(len(edges), 1)
        self.assertEqual(edges[0]["join_id"], "victim_host_to_waf_by_target_ip")


if __name__ == "__main__":
    unittest.main()
