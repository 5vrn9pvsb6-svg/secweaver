"""Tests for extended connector rendering and planning."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from extended_fetch import fetch_extended_connector  # noqa: E402
from template_select import connector_supports_template, select_template_for_asset  # noqa: E402


class TestExtendedConnectors(unittest.TestCase):
    def test_cloudwatch_template_selection(self) -> None:
        asset = {
            "asset_id": "asset-cloudtrail-prod",
            "asset_type": "app_api_log",
            "query_template_ids": ["cloudtrail_by_ip_time"],
        }
        connector = {"connector_id": "conn-aws-cloudwatch", "connector_type": "aws_cloudwatch"}
        templates = {
            "templates": {
                "cloudtrail_by_ip_time": {
                    "asset_types": ["app_api_log"],
                    "connector_types": ["aws_cloudwatch"],
                    "params": ["src_ip", "time_start", "time_end", "limit"],
                    "defaults": {"limit": 1000},
                    "cloudwatch_query": "fields @timestamp, @message | filter sourceIPAddress = '{src_ip}' | limit {limit}",
                }
            }
        }

        template_id, reason = select_template_for_asset(
            asset,
            connector,
            {
                "src_ip": "203.0.113.10",
                "time_start": "2026-06-21T08:00:00+08:00",
                "time_end": "2026-06-21T20:00:00+08:00",
            },
            templates,
        )

        self.assertEqual(template_id, "cloudtrail_by_ip_time")
        self.assertIsNone(reason)

    def test_extended_connector_requires_specific_query_key(self) -> None:
        self.assertTrue(
            connector_supports_template(
                {
                    "connector_types": ["splunk"],
                    "splunk_search": "index=security src_ip={src_ip}",
                },
                "splunk",
            )
        )
        self.assertFalse(
            connector_supports_template(
                {
                    "connector_types": ["splunk"],
                    "sls_query": "src_ip: {src_ip}",
                },
                "splunk",
            )
        )

    def test_cloud_log_without_endpoint_returns_planned_meta(self) -> None:
        events, meta = fetch_extended_connector(
            {
                "connector_id": "conn-aws-cloudwatch",
                "connector_type": "aws_cloudwatch",
                "config": {"region": "ap-southeast-1", "log_group": "/aws/cloudtrail"},
            },
            {},
            {
                "template_id": "cloudtrail_by_ip_time",
                "cloudwatch_query": "fields @timestamp, @message | limit 100",
                "params": {"limit": 100},
            },
        )

        self.assertEqual(events, [])
        self.assertEqual(meta["mode"], "planned")
        self.assertEqual(meta["backend"], "aws_cloudwatch")

    def test_planned_executor_connectors_render_query_keys(self) -> None:
        cases = [
            ("agent_stream", "stream_query"),
            ("syslog_ingest", "syslog_query"),
            ("object_storage", "object_query"),
        ]
        for connector_type, query_key in cases:
            with self.subTest(connector_type=connector_type):
                self.assertTrue(
                    connector_supports_template(
                        {
                            "connector_types": [connector_type],
                            query_key: "src_ip={src_ip}",
                        },
                        connector_type,
                    )
                )
                events, meta = fetch_extended_connector(
                    {
                        "connector_id": f"conn-{connector_type}",
                        "connector_type": connector_type,
                        "config": {},
                    },
                    {},
                    {
                        "template_id": f"{connector_type}-query",
                        query_key: "src_ip=203.0.113.10",
                        "params": {"src_ip": "203.0.113.10", "limit": 100},
                    },
                )

                self.assertEqual(events, [])
                self.assertEqual(meta["mode"], "planned")
                self.assertEqual(meta["backend"], connector_type)

    def test_planned_executor_reads_local_sample_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "events.jsonl"
            sample.write_text(
                "\n".join(
                    [
                        json.dumps({"timestamp": "2026-06-21T10:00:00+08:00", "src_ip": "203.0.113.10", "action": "block"}),
                        json.dumps({"timestamp": "2026-06-21T10:01:00+08:00", "src_ip": "198.51.100.8", "action": "allow"}),
                    ]
                ),
                encoding="utf-8",
            )

            events, meta = fetch_extended_connector(
                {
                    "connector_id": "conn-object-storage",
                    "connector_type": "object_storage",
                    "config": {"sample_file": str(sample)},
                },
                {},
                {
                    "template_id": "object-storage-query",
                    "object_query": "src_ip=203.0.113.10",
                    "params": {"src_ip": "203.0.113.10", "limit": 10},
                },
            )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["src_ip"], "203.0.113.10")
        self.assertEqual(meta["mode"], "local_sample")
        self.assertEqual(meta["rows_returned"], 1)

    def test_config_registered_connector_uses_external_executor(self) -> None:
        self.assertTrue(
            connector_supports_template(
                {
                    "connector_types": ["datadog_logs"],
                    "datadog_query": "source:security src_ip:{src_ip}",
                },
                "datadog_logs",
            )
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "datadog.jsonl"
            sample.write_text(
                json.dumps({"src_ip": "203.0.113.10", "message": "blocked"}) + "\n",
                encoding="utf-8",
            )
            events, meta = fetch_extended_connector(
                {
                    "connector_id": "conn-datadog",
                    "connector_type": "datadog_logs",
                    "config": {"sample_file": str(sample)},
                },
                {},
                {
                    "template_id": "datadog-by-src-ip",
                    "datadog_query": "source:security src_ip:203.0.113.10",
                    "params": {"src_ip": "203.0.113.10", "limit": 10},
                },
            )

        self.assertEqual(len(events), 1)
        self.assertEqual(meta["mode"], "local_sample")
        self.assertEqual(meta["backend"], "datadog_logs")


if __name__ == "__main__":
    unittest.main()
