#!/usr/bin/env python3
"""Tests for shared fetch_summary helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fetch_summary import (  # noqa: E402
    attach_fetch_summary,
    format_fetch_summary_markdown,
    summarize_fetch,
)


class TestFetchSummary(unittest.TestCase):
    def test_successful_fetch_clears_only_derived_precheck_gap(self):
        payload = {"completeness_precheck": {"data_gaps": ["missing_dns"]},
                   "data_access": {"fetch_mode": "live", "declared_asset_ids": ["exec"]}}
        attach_fetch_summary(payload)
        self.assertIn("query_results_incomplete", payload["completeness_precheck"]["data_gaps"])
        payload["data_access"]["fetch_attempts"] = [{"asset_id": "exec", "status": "success", "truncated": False}]
        attach_fetch_summary(payload)
        self.assertEqual(payload["completeness_precheck"]["data_gaps"], ["missing_dns"])

    def test_merged_pages_use_explicit_truncation_not_total_limit(self):
        payload = {"params": {"limit": 2}, "evidence_bundles": {"host_exec": [{}] * 4},
                   "data_access": {"fetch_attempts": [
                       {"asset_id": "exec", "asset_type": "host_exec", "status": "success", "truncated": False},
                       {"asset_id": "exec", "asset_type": "host_exec", "status": "success", "truncated": False}]}}
        self.assertEqual(summarize_fetch(payload)["truncated_asset_types"], [])
        payload["data_access"]["fetch_attempts"][1]["truncated"] = True
        self.assertEqual(summarize_fetch(payload)["truncated_asset_types"], ["host_exec"])
        payload["data_access"]["fetch_attempts"] = []
        self.assertEqual(summarize_fetch(payload)["truncated_asset_types"], ["host_exec"])

    def test_registry_ready_does_not_hide_unqueried_required_evidence(self):
        payload = {
            "evidence_bundles": {"host_process": [{"evidence_id": "p1"}]},
            "completeness_precheck": {
                "overall_verdict": "full_traceable", "confidence": 1.0, "next_skill_blocked": False,
                "requirements_evaluated": [{"priority": "P0", "requirement_id": "S5-P0-exec", "asset_type": "host_exec"}],
            },
            "data_access": {"fetch_mode": "live", "declared_asset_ids": ["exec", "process"],
                            "fetch_attempts": [{"asset_id": "process", "asset_type": "host_process", "status": "success", "returned_event_count": 1}]},
        }
        attach_fetch_summary(payload)
        pre = payload["completeness_precheck"]
        self.assertEqual(pre["metadata_readiness"]["overall_verdict"], "full_traceable")
        self.assertEqual(pre["assessment_basis"], "registry_metadata")
        self.assertEqual(pre["evidence_readiness"]["status"], "partial")
        self.assertEqual(pre["evidence_readiness"]["missing_required_evidence"][0]["requirement_id"], "S5-P0-exec")
        self.assertEqual(pre["query_integrity"]["incomplete_queries"][0]["reasons"], ["not_queried"])
        self.assertFalse(pre["analysis_constraints"]["negative_conclusion_allowed"])
        self.assertIn("实际证据", format_fetch_summary_markdown(payload["fetch_summary"]))

    def test_successful_empty_query_is_no_evidence_not_query_failure(self):
        payload = {"evidence_bundles": {}, "data_access": {
            "fetch_mode": "live", "declared_asset_ids": ["exec"],
            "fetch_attempts": [{"asset_id": "exec", "status": "success", "returned_event_count": 0}],
        }}
        summary = summarize_fetch(payload)
        self.assertEqual(summary["evidence_readiness"]["status"], "no_evidence")
        self.assertEqual(summary["query_integrity"]["status"], "no_known_gaps")
        self.assertFalse(summary["analysis_constraints"]["negative_conclusion_allowed"])
        self.assertEqual(summary["analysis_constraints"]["scope"], "queried_window_no_events")
        payload["data_access"] = {"fetch_mode": "dry_run", "declared_asset_ids": ["exec"]}
        summary = summarize_fetch(payload)
        self.assertEqual(summary["query_integrity"]["status"], "unknown")
        self.assertEqual(summary["evidence_readiness"]["status"], "not_evaluated")

    def test_query_gaps_survive_cache_and_update_precheck_and_report(self) -> None:
        for status, extra in (("success", {"partial": True, "incomplete_reasons": ["timeout"]}),
                              ("cache_hit", {"partial": True, "truncated": True}),
                              ("failed", {})):
            with self.subTest(status=status):
                payload = {"completeness_precheck": {"overall_verdict": "ready", "next_skill_blocked": False},
                           "data_access": {"fetch_mode": "live", "fetch_attempts": [
                               {"asset_id": "test", "connector_id": "es-test", "status": status, **extra}]}}
                attach_fetch_summary(payload)
                summary = payload["fetch_summary"]
                self.assertEqual(summary["query_integrity"]["status"], "incomplete")
                self.assertTrue(summary["query_integrity"]["absence_is_not_evidence"])
                self.assertEqual(summary["analysis_constraints"]["recommended_confidence_ceiling"], 0.65)
                self.assertIn("query_results_incomplete", payload["completeness_precheck"]["data_gaps"])
                self.assertFalse(payload["completeness_precheck"]["next_skill_blocked"])
                self.assertIn("Incomplete query results", format_fetch_summary_markdown(summary))

    def test_summarize_evidence_bundles(self) -> None:
        summary = summarize_fetch(
            {
                "bundle_id": "bundle-alert-confirm-min",
                "params": {
                    "time_start": "2026-07-03T17:00:00+08:00",
                    "time_end": "2026-07-04T17:00:00+08:00",
                    "limit": 5000,
                },
                "evidence_bundles": {
                    "waf_alert": [{}] * 14,
                    "web_access_log": [{}] * 5000,
                    "host_exec": [{}] * 282,
                },
                "data_access": {"fetch_mode": "live", "fetch_strategy": "correlation_fetch_plan"},
                "correlation_fetch_plan": [{"asset_id": "asset-waf-prod-01", "template_id": "waf_gateway_plugin_by_time"}],
            }
        )
        self.assertEqual(summary["total_events"], 5296)
        self.assertEqual(summary["by_asset_type"]["waf_alert"], 14)
        self.assertIn("web_access_log", summary["truncated_asset_types"])
        self.assertEqual(summary["asset_count"], 1)

    def test_summarize_correlated_and_primary_alerts(self) -> None:
        summary = summarize_fetch(
            {
                "primary_alerts": [{"alert_id": "a1"}, {"alert_id": "a2"}],
                "correlated_evidence": {"host_exec": [{}]},
                "data_access": {"fetch_mode": "live"},
            }
        )
        self.assertEqual(summary["primary_alert_count"], 2)
        self.assertEqual(summary["by_asset_type"]["waf_alert"], 2)
        self.assertEqual(summary["by_asset_type"]["host_exec"], 1)

    def test_summarize_attacker_ip_first_last_log_time(self) -> None:
        summary = summarize_fetch(
            {
                "params": {
                    "attacker_ip": "115.194.3.17",
                    "time_start": "2026-07-10T00:00:00+08:00",
                    "time_end": "2026-07-10T23:59:59+08:00",
                },
                "evidence_bundles": {
                    "waf_alert": [
                        {
                            "src_ip": "115.194.3.17",
                            "timestamp": "2026-07-10T18:01:11+08:00",
                        },
                        {
                            "src_ip": "203.0.113.9",
                            "timestamp": "2026-07-10T18:02:00+08:00",
                        },
                    ],
                    "web_access_log": [
                        {
                            "remote_addr": '"115.194.3.17',
                            "timestamp": "2026-07-10T17:42:10+08:00",
                        },
                        {
                            "src_ip": "115.194.3.17",
                            "timestamp": "2026-07-10T22:10:34+08:00",
                        },
                    ],
                },
            }
        )

        ip_range = summary["attacker_ip_log_time_range"]
        self.assertEqual(ip_range["attacker_ip"], "115.194.3.17")
        self.assertEqual(ip_range["event_count"], 3)
        self.assertEqual(ip_range["timestamped_event_count"], 3)
        self.assertEqual(ip_range["first_seen"], "2026-07-10T17:42:10+08:00")
        self.assertEqual(ip_range["last_seen"], "2026-07-10T22:10:34+08:00")
        self.assertEqual(ip_range["first_seen_asset_type"], "web_access_log")
        self.assertEqual(ip_range["last_seen_asset_type"], "web_access_log")
        self.assertEqual(ip_range["source_bundles"], ["waf_alert", "web_access_log"])

    def test_markdown_contains_counts(self) -> None:
        md = format_fetch_summary_markdown(
            {
                "fetch_mode": "live",
                "fetch_strategy": "asset_list",
                "total_events": 32,
                "by_asset_type": {"host_exec": 30, "syslog_risk_alert": 2},
                "time_window": {"time_start": "t0", "time_end": "t1"},
            }
        )
        self.assertIn("数据取数统计", md)
        self.assertIn("总事件数", md)
        self.assertIn("host_exec", md)

    def test_repeated_asset_fetches_are_accumulated(self) -> None:
        summary = summarize_fetch(
            {
                "evidence_bundles": {
                    "host_exec": [
                        {"evidence_id": "e1", "_source_asset_id": "asset-host-exec"},
                        {"evidence_id": "e2", "_source_asset_id": "asset-host-exec"},
                        {"evidence_id": "e3", "_source_asset_id": "asset-host-exec"},
                    ]
                },
                "data_access": {
                    "fetch_mode": "live",
                    "fetch_attempts": [
                        {
                            "asset_id": "asset-host-exec",
                            "asset_type": "host_exec",
                            "status": "success",
                            "returned_event_count": 5,
                            "template_id": "host_exec_by_host_time",
                        },
                        {
                            "asset_id": "asset-host-exec",
                            "asset_type": "host_exec",
                            "status": "success",
                            "returned_event_count": 4,
                            "template_id": "host_exec_by_host_time",
                        },
                        {
                            "asset_id": "asset-host-exec",
                            "asset_type": "host_exec",
                            "status": "failed",
                            "returned_event_count": 0,
                            "template_id": "host_exec_by_host_ip_time",
                        },
                        {
                            "asset_id": "asset-host-exec",
                            "asset_type": "host_exec",
                            "status": "cache_hit",
                            "returned_event_count": 5,
                            "template_id": "host_exec_by_host_time",
                        },
                    ],
                },
            }
        )

        self.assertEqual(summary["total_events"], 3)
        self.assertEqual(summary["total_fetched_events"], 9)
        self.assertEqual(summary["total_fetch_queries"], 3)
        self.assertEqual(summary["total_fetch_requests"], 4)
        self.assertEqual(summary["total_fetch_cache_hits"], 1)
        self.assertEqual(summary["failed_fetch_queries"], 1)
        row = summary["asset_fetch_stats"][0]
        self.assertEqual(row["query_count"], 3)
        self.assertEqual(row["request_count"], 4)
        self.assertEqual(row["cache_hit_count"], 1)
        self.assertEqual(row["successful_query_count"], 2)
        self.assertEqual(row["failed_query_count"], 1)
        self.assertEqual(row["cumulative_fetched_events"], 9)
        self.assertEqual(row["final_event_count"], 3)
        self.assertEqual(row["fetch_request_count"], 4)
        self.assertEqual(row["fetch_count"], 3)
        self.assertEqual(row["successful_fetch_count"], 2)
        self.assertEqual(row["failed_fetch_count"], 1)
        self.assertEqual(row["fetched_event_count"], 9)
        self.assertEqual(row["retained_event_count"], 3)
        self.assertEqual(row["duplicate_or_filtered_count"], 6)
        self.assertEqual(row["deduplicated_count"], 6)
        self.assertEqual(row["window_filtered_count"], 0)

        md = format_fetch_summary_markdown(summary)
        self.assertIn("按数据资产（拉取次数与数据量）", md)
        self.assertIn("取数请求 / 实际查询 / 缓存命中", md)
        self.assertIn("拉取数据", md)
        self.assertIn("保留数据", md)
        self.assertIn("| `asset-host-exec` | `host_exec` | 4 / 3 / 1 | 2 / 1 | 9 | 3 | 6 |", md)

    def test_window_filtered_and_deduplicated_counts_are_separate(self) -> None:
        summary = summarize_fetch(
            {
                "evidence_bundles": {
                    "host_exec": [
                        {"evidence_id": "e1", "_source_asset_id": "asset-host-exec"},
                        {"evidence_id": "e2", "_source_asset_id": "asset-host-exec"},
                        {"evidence_id": "e3", "_source_asset_id": "asset-host-exec"},
                    ]
                },
                "data_access": {
                    "fetch_attempts": [
                        {
                            "asset_id": "asset-host-exec",
                            "asset_type": "host_exec",
                            "status": "success",
                            "returned_event_count": 9,
                        }
                    ],
                    "attacker_ip_window_narrowing": {
                        "evidence_filter": {
                            "dropped_by_asset_id": {"asset-host-exec": 2},
                            "dropped_by_asset_type": {"host_exec": 2},
                        }
                    },
                },
            }
        )

        row = summary["asset_fetch_stats"][0]
        self.assertEqual(row["duplicate_or_filtered_count"], 6)
        self.assertEqual(row["deduplicated_count"], 4)
        self.assertEqual(row["window_filtered_count"], 2)
        self.assertEqual(summary["total_deduplicated_events"], 4)
        self.assertEqual(summary["total_window_filtered_events"], 2)
        md = format_fetch_summary_markdown(summary)
        self.assertIn("| 9 | 3 | 4 | 2 |", md)

    def test_non_connector_events_are_reported_separately(self) -> None:
        summary = summarize_fetch(
            {
                "evidence_bundles": {
                    "host_exec": [
                        {"evidence_id": "e1", "_source_asset_id": "asset-host-exec"},
                    ],
                    "asset_inventory": [{"host_id": "h1"}, {"host_id": "h2"}],
                },
                "data_access": {
                    "fetch_mode": "live",
                    "fetch_attempts": [
                        {
                            "asset_id": "asset-host-exec",
                            "asset_type": "host_exec",
                            "status": "success",
                            "returned_event_count": 1,
                        }
                    ],
                },
            }
        )

        self.assertEqual(summary["total_events"], 3)
        self.assertEqual(summary["non_connector_event_count"], 2)
        self.assertEqual(summary["non_connector_by_asset_type"], {"asset_inventory": 2})
        md = format_fetch_summary_markdown(summary)
        self.assertIn("非 connector 拉取证据", md)
        self.assertIn("`asset_inventory`: 2", md)

    def test_markdown_contains_attacker_ip_first_last_log_time(self) -> None:
        md = format_fetch_summary_markdown(
            {
                "fetch_mode": "live",
                "fetch_strategy": "s4_bootstrap",
                "total_events": 3,
                "by_asset_type": {"waf_alert": 1, "web_access_log": 2},
                "time_window": {
                    "time_start": "2026-07-10T00:00:00+08:00",
                    "time_end": "2026-07-10T23:59:59+08:00",
                    "attacker_ip": "115.194.3.17",
                },
                "attacker_ip_log_time_range": {
                    "attacker_ip": "115.194.3.17",
                    "event_count": 3,
                    "timestamped_event_count": 3,
                    "first_seen": "2026-07-10T17:42:10+08:00",
                    "last_seen": "2026-07-10T22:10:34+08:00",
                    "source_bundles": ["waf_alert", "web_access_log"],
                },
            }
        )

        self.assertIn("该 IP 日志时间范围", md)
        self.assertIn("2026-07-10T17:42:10+08:00", md)
        self.assertIn("2026-07-10T22:10:34+08:00", md)
        self.assertIn("匹配 3 条", md)

    def test_markdown_reports_skipped_assets(self) -> None:
        summary = summarize_fetch(
            {
                "bundle_id": "bundle-alert-confirm-min",
                "evidence_bundles": {"waf_alert": [{}]},
                "data_access": {
                    "fetch_mode": "live",
                    "fetch_strategy": "s4_bootstrap",
                    "declared_asset_ids": [
                        "asset-waf-prod-01",
                        "asset-secweaver-host-connect",
                    ],
                    "fetch_asset_ids": ["asset-waf-prod-01"],
                    "executed_asset_ids": ["asset-waf-prod-01"],
                    "skipped_assets": [
                        {
                            "asset_id": "asset-secweaver-host-connect",
                            "reason": "not_selected_by_s4_bootstrap",
                        }
                    ],
                },
            }
        )
        self.assertEqual(summary["skipped_asset_count"], 1)
        md = format_fetch_summary_markdown(summary)
        self.assertIn("声明资产", md)
        self.assertIn("实际执行查询资产", md)
        self.assertIn("声明但未执行查询", md)
        self.assertIn("asset-secweaver-host-connect", md)

    def test_markdown_reports_planned_assets_for_plan_only(self) -> None:
        summary = summarize_fetch(
            {
                "correlation_fetch_plan": [
                    {"asset_id": "asset-waf-prod-01"},
                    {"asset_id": "asset-secweaver-gateway-access"},
                ],
                "data_access": {
                    "fetch_mode": "plan_only",
                    "fetch_strategy": "correlation_fetch_plan",
                    "declared_asset_ids": [
                        "asset-waf-prod-01",
                        "asset-secweaver-gateway-access",
                        "asset-secweaver-host-connect",
                    ],
                    "fetch_asset_ids": [
                        "asset-waf-prod-01",
                        "asset-secweaver-gateway-access",
                    ],
                    "planned_asset_ids": [
                        "asset-waf-prod-01",
                        "asset-secweaver-gateway-access",
                    ],
                    "skipped_assets": [
                        {
                            "asset_id": "asset-secweaver-host-connect",
                            "reason": "not_selected_by_correlation_plan",
                        }
                    ],
                },
            }
        )
        self.assertIsNone(summary["executed_asset_ids"])
        self.assertEqual(summary["planned_asset_ids"], ["asset-waf-prod-01", "asset-secweaver-gateway-access"])
        md = format_fetch_summary_markdown(summary)
        self.assertIn("计划查询资产", md)
        self.assertNotIn("实际执行查询资产", md)

    def test_attach_fetch_summary(self) -> None:
        payload: dict = {"evidence_bundles": {"host_exec": []}, "data_access": {"fetch_mode": "live"}}
        attach_fetch_summary(payload)
        self.assertIn("fetch_summary", payload)
        self.assertEqual(payload["fetch_summary"]["total_events"], 0)


if __name__ == "__main__":
    unittest.main()
