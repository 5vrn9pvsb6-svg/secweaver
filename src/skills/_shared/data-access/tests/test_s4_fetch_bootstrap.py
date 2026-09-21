"""Tests for S4 two-phase fetch bootstrap."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

DATA_ACCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DATA_ACCESS))

from s4_fetch_bootstrap import (  # noqa: E402
    _merge_evidence_bundles,
    build_s4_bootstrap_plan,
    extract_attacker_ips,
    extract_target_ips,
    fetch_s4_bootstrap,
    should_s4_bootstrap,
    strip_upstream_ip,
)


class TestS4FetchBootstrap(unittest.TestCase):
    def test_should_s4_bootstrap_time_only(self) -> None:
        self.assertTrue(
            should_s4_bootstrap(
                ["S4"],
                ["S4_alert_confirmation"],
                {"time_start": "2026-07-04T21:00:00+08:00", "time_end": "2026-07-04T23:00:00+08:00"},
            )
        )

    def test_should_not_bootstrap_when_attacker_ip_set(self) -> None:
        self.assertFalse(
            should_s4_bootstrap(
                ["S4"],
                ["S4_alert_confirmation"],
                {"attacker_ip": "203.0.113.10", "time_start": "...", "time_end": "..."},
            )
        )

    def test_extract_attacker_ips(self) -> None:
        events = [
            {"src_ip": '"38.148.253.160'},
            {"ip": "39.183.168.99"},
            {"src_ip": "38.148.253.160"},
        ]
        self.assertEqual(
            extract_attacker_ips(events),
            ["38.148.253.160", "39.183.168.99"],
        )

    def test_extract_target_ips_strips_port(self) -> None:
        events = [{"upstream_addr": "192.0.2.91:8080"}, {"target_ip": "192.0.2.92"}]
        self.assertEqual(extract_target_ips(events), ["192.0.2.91", "192.0.2.92"])

    def test_strip_upstream_ip(self) -> None:
        self.assertEqual(strip_upstream_ip("10.0.1.5:30443"), "10.0.1.5")
        self.assertEqual(strip_upstream_ip("10.0.1.5"), "10.0.1.5")
        self.assertIsNone(strip_upstream_ip("-"))

    def test_merge_dedupes_overlapping_fetch_results(self) -> None:
        merged = _merge_evidence_bundles(
            {
                "waf_alert": [
                    {
                        "evidence_id": "waf-a",
                        "alert_id": "alert-1",
                        "timestamp": "2026-07-06T13:49:20+08:00",
                    }
                ],
                "web_access_log": [
                    {
                        "evidence_id": "web-a",
                        "timestamp": "2026-07-06T13:49:26+08:00",
                        "remote_addr": "192.168.99.61",
                        "request_uri": "/cmdi/diag.php?host=127.0.0.1;id",
                        "status": "200",
                        "upstream_addr": "192.0.2.91:80",
                    }
                ],
            },
            {
                "waf_alert": [
                    {
                        "evidence_id": "waf-b",
                        "alert_id": "alert-1",
                        "timestamp": "2026-07-06T13:49:20+08:00",
                    }
                ],
                "web_access_log": [
                    {
                        "evidence_id": "web-b",
                        "timestamp": "2026-07-06T13:49:26+08:00",
                        "remote_addr": "192.168.99.61",
                        "request_uri": "/cmdi/diag.php?host=127.0.0.1;id",
                        "status": "200",
                        "upstream_addr": "192.0.2.91:80",
                    }
                ],
            },
        )

        self.assertEqual(len(merged["waf_alert"]), 1)
        self.assertEqual(len(merged["web_access_log"]), 1)
        self.assertEqual(merged["waf_alert"][0]["evidence_id"], "waf-a")
        self.assertEqual(merged["web_access_log"][0]["evidence_id"], "web-a")

    def test_build_plan_phase1_waf_only(self) -> None:
        asset_ids = [
            "asset-waf-prod-01",
            "asset-secweaver-gateway-access",
            "asset-secweaver-host-exec",
        ]
        tasks, meta = build_s4_bootstrap_plan(
            asset_ids,
            {"time_start": "2026-07-04T21:00:00+08:00", "time_end": "2026-07-04T23:00:00+08:00"},
        )
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["template_id"], "waf_gateway_plugin_by_time")
        self.assertEqual(tasks[0]["asset_id"], "asset-waf-prod-01")
        self.assertEqual(meta["bootstrap_phase"], "plan")

    def test_build_plan_phase1_uses_attacker_ip_template(self) -> None:
        tasks, _meta = build_s4_bootstrap_plan(
            ["asset-waf-prod-01", "asset-secweaver-gateway-access"],
            {
                "attacker_ip": "115.194.3.17",
                "time_start": "2026-07-10T00:00:00+08:00",
                "time_end": "2026-07-10T23:59:59+08:00",
            },
        )

        self.assertEqual(tasks[0]["template_id"], "waf_gateway_plugin_by_ip_time")
        self.assertEqual(tasks[0]["params"]["src_ip"], "115.194.3.17")

    def test_build_plan_phase2_web_per_ip(self) -> None:
        asset_ids = [
            "asset-waf-prod-01",
            "asset-secweaver-gateway-access",
            "asset-secweaver-host-exec",
        ]
        waf_events = [{"src_ip": "38.148.253.160"}, {"src_ip": "39.183.168.99"}]
        tasks, meta = build_s4_bootstrap_plan(
            asset_ids,
            {"time_start": "2026-07-04T21:00:00+08:00", "time_end": "2026-07-04T23:00:00+08:00"},
            waf_events=waf_events,
        )
        web_tasks = [t for t in tasks if t["asset_id"] == "asset-secweaver-gateway-access"]
        self.assertEqual(len(web_tasks), 2)
        self.assertEqual(meta["attacker_ips"], ["38.148.253.160", "39.183.168.99"])
        self.assertIn(
            web_tasks[0]["template_id"],
            ("web_access_by_remote_addr_time", "web_access_by_ip_time", "web_access_by_src_ip_time"),
        )

    @patch("s4_fetch_bootstrap.fetch_correlation_plan_evidence")
    def test_fetch_s4_bootstrap_merges_phases(self, mock_fetch) -> None:
        asset_ids = [
            "asset-waf-prod-01",
            "asset-secweaver-gateway-access",
            "asset-secweaver-host-exec",
            "asset-secweaver-host-connect",
            "asset-secweaver-host-file-op",
        ]
        params = {
            "time_start": "2026-07-04T21:00:00+08:00",
            "time_end": "2026-07-04T23:00:00+08:00",
        }

        def side_effect(tasks, *, resolve_secrets=True):
            del resolve_secrets
            if any(t.get("template_id") == "waf_gateway_plugin_by_time" for t in tasks):
                return {"waf_alert": [{"src_ip": "38.148.253.160", "timestamp": "2026-07-04T22:00:00+08:00"}]}
            if any(t.get("template_id", "").startswith("web_access") for t in tasks):
                return {
                    "web_access_log": [
                        {
                            "remote_addr": "38.148.253.160",
                            "upstream_addr": "192.0.2.91:80",
                            "status": "200",
                        }
                    ]
                }
            if any(t.get("template_id") == "host_exec_by_host_ip_time" for t in tasks):
                return {
                    "host_exec": [{"host_ip": "192.0.2.91", "command": "id"}],
                    "host_connect": [{"host_ip": "192.0.2.91", "dst_ip": "203.0.113.10"}],
                    "host_file_op": [{"host_ip": "192.0.2.91", "path": "/etc/passwd", "action": "read"}],
                }
            return {}

        mock_fetch.side_effect = side_effect

        evidence, meta = fetch_s4_bootstrap(asset_ids, params, resolve_secrets=False)
        self.assertEqual(meta["fetch_strategy"], "s4_bootstrap")
        self.assertIn("fetch_attempts", meta)
        self.assertEqual(len(evidence.get("waf_alert") or []), 1)
        self.assertEqual(len(evidence.get("web_access_log") or []), 1)
        self.assertEqual(len(evidence.get("host_exec") or []), 1)
        self.assertEqual(len(evidence.get("host_connect") or []), 1)
        self.assertEqual(len(evidence.get("host_file_op") or []), 1)
        self.assertEqual(
            meta["executed_asset_ids"],
            [
                "asset-waf-prod-01",
                "asset-secweaver-gateway-access",
                "asset-secweaver-host-exec",
                "asset-secweaver-host-connect",
                "asset-secweaver-host-file-op",
            ],
        )
        self.assertEqual(meta["skipped_assets"], [])
        self.assertEqual(meta["enriched_params"]["attacker_ip"], "38.148.253.160")
        self.assertEqual(meta["enriched_params"]["target_ip"], "192.0.2.91")
        self.assertGreaterEqual(mock_fetch.call_count, 2)

    @patch("s4_fetch_bootstrap.fetch_correlation_plan_evidence")
    def test_fetch_s4_bootstrap_can_defer_host_side_until_window_narrows(self, mock_fetch) -> None:
        asset_ids = [
            "asset-waf-prod-01",
            "asset-secweaver-gateway-access",
            "asset-secweaver-host-exec",
            "asset-secweaver-host-connect",
        ]
        mock_fetch.side_effect = [
            {"waf_alert": [{"src_ip": "38.148.253.160"}]},
            {
                "web_access_log": [
                    {
                        "remote_addr": "38.148.253.160",
                        "upstream_addr": "192.0.2.91:80",
                    }
                ]
            },
        ]

        evidence, meta = fetch_s4_bootstrap(
            asset_ids,
            {
                "time_start": "2026-07-04T21:00:00+08:00",
                "time_end": "2026-07-04T23:00:00+08:00",
            },
            resolve_secrets=False,
            include_host_side=False,
        )

        self.assertEqual(mock_fetch.call_count, 2)
        self.assertNotIn("host_exec", evidence)
        self.assertNotIn("host_connect", evidence)
        self.assertEqual(meta["enriched_params"]["target_ip"], "192.0.2.91")
        self.assertEqual(
            meta["s4_bootstrap"]["host_side_skip_reason"],
            "deferred_until_attacker_window_narrowed",
        )

    @patch("s4_fetch_bootstrap.fetch_correlation_plan_evidence")
    def test_fetch_s4_bootstrap_falls_back_to_time_window_without_widening_d2(self, mock_fetch) -> None:
        asset_ids = [
            "asset-waf-prod-01",
            "asset-secweaver-gateway-access",
            "asset-secweaver-host-exec",
        ]

        def side_effect(tasks, *, resolve_secrets=True):
            del resolve_secrets
            template_ids = {str(task.get("template_id")) for task in tasks}
            if "waf_gateway_plugin_by_time" in template_ids:
                return {"waf_alert": [{"src_ip": "39.144.124.34"}]}
            if "web_access_by_remote_addr_time" in template_ids:
                return {}
            if "web_access_by_time" in template_ids:
                return {
                    "web_access_log": [
                        {
                            "src_ip": "107.172.89.112",
                            "upstream_addr": "192.0.2.91:80",
                            "timestamp": "2026-07-04T22:00:01+08:00",
                        }
                    ]
                }
            if any(str(task.get("template_id", "")).startswith("host_") for task in tasks):
                self.fail("unrelated time-window gateway rows must not trigger D2 fetch")
            return {}

        mock_fetch.side_effect = side_effect
        evidence, meta = fetch_s4_bootstrap(
            asset_ids,
            {
                "time_start": "2026-07-04T21:00:00+08:00",
                "time_end": "2026-07-04T23:00:00+08:00",
            },
            resolve_secrets=False,
        )

        fallback = meta["s4_bootstrap"]["web_access_fallback"]
        self.assertTrue(fallback["used"])
        self.assertEqual(fallback["reason"], "targeted_ip_query_returned_no_rows")
        self.assertEqual(fallback["fallback_event_count"], 1)
        self.assertEqual(len(evidence.get("web_access_log") or []), 1)
        self.assertEqual(meta["s4_bootstrap"]["target_ips"], [])
        self.assertEqual(
            meta["s4_bootstrap"]["host_side_skip_reason"],
            "no_valid_target_ip_from_waf_or_gateway",
        )

    @patch("s4_fetch_bootstrap.fetch_correlation_plan_evidence")
    def test_fetch_s4_bootstrap_reports_declared_but_unexecuted_assets(self, mock_fetch) -> None:
        asset_ids = [
            "asset-waf-prod-01",
            "asset-secweaver-gateway-access",
            "asset-secweaver-host-exec",
            "asset-secweaver-host-connect",
            "asset-secweaver-host-file-op",
            "asset-secweaver-sys-risk-alert",
        ]
        params = {
            "time_start": "2026-07-04T21:00:00+08:00",
            "time_end": "2026-07-04T23:00:00+08:00",
        }

        def side_effect(tasks, *, resolve_secrets=True):
            del resolve_secrets
            if any(t.get("template_id") == "waf_gateway_plugin_by_time" for t in tasks):
                return {"waf_alert": [{"src_ip": "38.148.253.160"}]}
            if any(t.get("template_id", "").startswith("web_access") for t in tasks):
                return {
                    "web_access_log": [
                        {
                            "src_ip": "38.148.253.160",
                            "upstream_addr": "192.0.2.91:80",
                        }
                    ]
                }
            if any(t.get("template_id") == "host_exec_by_host_ip_time" for t in tasks):
                return {
                    "host_exec": [{"host_ip": "192.0.2.91", "command": "id"}],
                    "host_connect": [],
                    "host_file_op": [],
                }
            return {}

        mock_fetch.side_effect = side_effect

        _evidence, meta = fetch_s4_bootstrap(asset_ids, params, resolve_secrets=False)
        skipped_ids = [item["asset_id"] for item in meta["skipped_assets"]]
        self.assertNotIn("asset-secweaver-host-connect", skipped_ids)
        self.assertNotIn("asset-secweaver-host-file-op", skipped_ids)
        self.assertIn("asset-secweaver-sys-risk-alert", skipped_ids)
        self.assertIn("asset-secweaver-host-connect", meta["executed_asset_ids"])
        self.assertIn("asset-secweaver-host-file-op", meta["executed_asset_ids"])
        self.assertEqual(
            {item["reason"] for item in meta["skipped_assets"]},
            {"not_selected_by_s4_bootstrap"},
        )

    @patch("s4_fetch_bootstrap.fetch_correlation_plan_evidence")
    def test_fetch_s4_bootstrap_skips_host_phase_without_waf_or_gateway_target(self, mock_fetch) -> None:
        asset_ids = [
            "asset-waf-prod-01",
            "asset-secweaver-gateway-access",
            "asset-secweaver-host-exec",
            "asset-secweaver-host-connect",
            "asset-secweaver-host-file-op",
        ]
        params = {
            "attacker_ip": "115.194.3.17",
            "time_start": "2026-07-10T00:00:00+08:00",
            "time_end": "2026-07-10T23:59:59+08:00",
        }
        requested_templates: list[str] = []

        def side_effect(tasks, *, resolve_secrets=True):
            del resolve_secrets
            requested_templates.extend(str(t.get("template_id")) for t in tasks)
            if any(t.get("template_id") == "waf_gateway_plugin_by_ip_time" for t in tasks):
                return {
                    "waf_alert": [
                        {
                            "src_ip": "115.194.3.17",
                            "target_ip": "-",
                            "upstream_addr": "-",
                            "timestamp": "2026-07-10T17:50:00+08:00",
                        }
                    ]
                }
            if any(t.get("template_id", "").startswith("web_access") for t in tasks):
                return {
                    "web_access_log": [
                        {
                            "src_ip": "115.194.3.17",
                            "target_ip": "-",
                            "upstream_addr": "-",
                            "upstream_status": "-",
                            "status": "480",
                        }
                    ]
                }
            if any(str(t.get("template_id", "")).startswith("host_") for t in tasks):
                self.fail("host-side fetch should not run without WAF or gateway target_ip")
            return {}

        mock_fetch.side_effect = side_effect

        evidence, meta = fetch_s4_bootstrap(asset_ids, params, resolve_secrets=False)

        self.assertNotIn("host_exec_by_host_ip_time", requested_templates)
        self.assertNotIn("host_connect_by_host_ip_time", requested_templates)
        self.assertNotIn("host_file_op_by_host_ip_time", requested_templates)
        self.assertEqual(evidence.get("host_exec"), None)
        self.assertTrue(meta["s4_bootstrap"]["host_side_fetch_skipped"])
        self.assertEqual(
            meta["s4_bootstrap"]["host_side_skip_reason"],
            "no_valid_target_ip_from_waf_or_gateway",
        )
        self.assertNotIn("asset-secweaver-host-exec", meta["executed_asset_ids"])

    @patch("s4_fetch_bootstrap.fetch_correlation_plan_evidence")
    def test_fetch_s4_bootstrap_uses_waf_target_when_gateway_has_no_upstream(self, mock_fetch) -> None:
        asset_ids = [
            "asset-waf-prod-01",
            "asset-secweaver-gateway-access",
            "asset-secweaver-host-exec",
        ]
        params = {
            "attacker_ip": "115.194.3.17",
            "time_start": "2026-07-10T00:00:00+08:00",
            "time_end": "2026-07-10T23:59:59+08:00",
        }

        def side_effect(tasks, *, resolve_secrets=True):
            del resolve_secrets
            if any(t.get("template_id") == "waf_gateway_plugin_by_ip_time" for t in tasks):
                return {
                    "waf_alert": [
                        {
                            "src_ip": "115.194.3.17",
                            "target_ip": "192.0.2.91",
                            "timestamp": "2026-07-10T17:50:00+08:00",
                        }
                    ]
                }
            if any(t.get("template_id", "").startswith("web_access") for t in tasks):
                return {"web_access_log": [{"src_ip": "115.194.3.17", "target_ip": "-", "status": "480"}]}
            if any(t.get("template_id") == "host_exec_by_host_ip_time" for t in tasks):
                self.assertEqual(tasks[0]["params"]["host_ip"], "192.0.2.91")
                return {"host_exec": [{"host_ip": "192.0.2.91", "command": "id"}]}
            return {}

        mock_fetch.side_effect = side_effect

        evidence, meta = fetch_s4_bootstrap(asset_ids, params, resolve_secrets=False)

        self.assertEqual(len(evidence.get("host_exec") or []), 1)
        self.assertFalse(meta["s4_bootstrap"]["host_side_fetch_skipped"])
        self.assertEqual(meta["s4_bootstrap"]["target_ips"], ["192.0.2.91"])


if __name__ == "__main__":
    unittest.main()
