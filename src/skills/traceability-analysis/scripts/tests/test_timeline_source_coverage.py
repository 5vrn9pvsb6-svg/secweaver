"""Tests for timeline source coverage columns."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from timeline_source_coverage import (  # noqa: E402
    TIMELINE_CHECK,
    TIMELINE_MISS,
    build_source_coverage,
    format_source_coverage_cells,
    resolve_timeline_source_types,
)
from trace_report_markdown import render_traceability_report  # noqa: E402


class TimelineSourceCoverageTests(unittest.TestCase):
    def test_resolve_source_types_from_fetch_summary(self) -> None:
        types = resolve_timeline_source_types(
            {
                "fetch_summary": {
                    "by_asset_type": {"host_exec": 10, "web_access_log": 5},
                    "asset_ids": ["asset-secweaver-sys-risk-alert"],
                },
                "evidence_index": {},
            }
        )
        self.assertEqual(types[0], "web_access_log")
        self.assertIn("host_exec", types)
        self.assertIn("syslog_risk_alert", types)

    def test_build_source_coverage_marks_refs(self) -> None:
        coverage = build_source_coverage(
            ["web-001", "exec-001"],
            {
                "web-001": {"bundle": "web_access_log"},
                "exec-001": {"bundle": "host_exec"},
            },
            ["web_access_log", "host_exec", "waf_alert"],
        )
        self.assertTrue(coverage["web_access_log"])
        self.assertTrue(coverage["host_exec"])
        self.assertFalse(coverage["waf_alert"])
        cells = format_source_coverage_cells(coverage, ["web_access_log", "host_exec", "waf_alert"])
        self.assertEqual(cells, [TIMELINE_CHECK, TIMELINE_CHECK, TIMELINE_MISS])

    def test_markdown_timeline_includes_source_columns(self) -> None:
        result = {
            "scenario": ["S1"],
            "overall_verdict": "initial_access_only",
            "confidence": 0.7,
            "confidence_ceiling": 0.8,
            "summary": "test",
            "initial_access": {
                "host": "192.0.2.91",
                "timestamp": "2026-07-06T07:25:28+08:00",
                "evidence_refs": ["web-001", "exec-001"],
            },
            "timeline_source_types": ["web_access_log", "host_exec", "waf_alert"],
            "timeline": [
                {
                    "timestamp": "2026-07-06T07:25:28+08:00",
                    "stage": "initial_access",
                    "host": "192.0.2.91",
                    "description": "entry",
                    "evidence_refs": ["web-001", "exec-001"],
                    "source_coverage": {
                        "web_access_log": True,
                        "host_exec": True,
                        "waf_alert": False,
                    },
                },
                {
                    "timestamp": "2026-07-06T07:25:56+08:00",
                    "stage": "execution",
                    "host": "192.0.2.91",
                    "description": "exfil",
                    "evidence_refs": ["exec-002"],
                    "source_coverage": {
                        "web_access_log": False,
                        "host_exec": True,
                        "waf_alert": False,
                    },
                },
            ],
            "evidence_index": {
                "web-001": {"bundle": "web_access_log"},
                "exec-001": {"bundle": "host_exec"},
                "exec-002": {"bundle": "host_exec"},
            },
            "fetch_summary": {
                "by_asset_type": {"web_access_log": 1, "host_exec": 2},
            },
            "impacted_assets": [],
        }
        report = render_traceability_report(result, locale="zh-CN")
        self.assertNotIn("traceability-scroll-table", report)
        self.assertNotIn("<table", report)
        self.assertNotIn("```text", report)
        self.assertIn("| 时间 | 阶段 | 主机 | 描述 | ATT&CK | 证据 |", report)
        self.assertIn("详细 URL/命令保留在 JSON", report)
        self.assertNotIn("原始行为", report)
        self.assertIn("网关Access", report)
        self.assertIn("主机Exec", report)
        self.assertIn("WAF", report)
        self.assertIn("✓", report)
        self.assertIn("✗", report)
        self.assertIn("数据源列", report)


if __name__ == "__main__":
    unittest.main()
