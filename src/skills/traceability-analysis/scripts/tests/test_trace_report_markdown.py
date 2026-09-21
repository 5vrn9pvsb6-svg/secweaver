"""Tests for full traceability Markdown report."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
REPO = SCRIPTS.parents[3]
EXAMPLE = REPO / "examples" / "traceability" / "s1-web-shell-to-ssh-lateral.json"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from trace_report_markdown import render_traceability_report, _select_timeline_steps  # noqa: E402


class TraceReportMarkdownTests(unittest.TestCase):
    def test_report_shows_initial_evidence_groups_and_lateral_dual_times(self):
        result = {
            "scenario": ["S1", "S3"],
            "overall_verdict": "confirmed_intrusion_chain",
            "confidence": 0.9,
            "confidence_ceiling": 0.9,
            "summary": "confirmed",
            "initial_access": {
                "host": "192.0.2.91",
                "attacker_ip": "203.0.113.8",
                "timestamp": "2026-07-11T12:34:41+08:00",
                "url": "https://gateway.example/webshell/",
                "vector": "webshell",
                "entry_point_role": "compromise_trigger",
                "first_compromise_point_status": "supported",
                "first_observed_control_url": "https://gateway.example/webshell/",
                "primary_evidence_refs": ["web-primary"],
                "supporting_evidence_refs": [f"support-{i}" for i in range(10)],
                "evidence_refs": ["web-primary", *[f"support-{i}" for i in range(10)]],
            },
            "timeline": [
                {
                    "timestamp": "2026-07-11T12:35:04+08:00",
                    "stage": "lateral_movement",
                    "host": "192.0.2.92",
                    "attempt_timestamp": "2026-07-11T12:35:04+08:00",
                    "confirmed_timestamp": "2026-07-11T12:35:43+08:00",
                    "evidence_refs": ["exec-attempt", "ssh-accepted"],
                }
            ],
            "lateral_findings": {
                "confirmed": [
                    {
                        "host": "192.0.2.92",
                        "timestamp": "2026-07-11T12:35:04+08:00",
                        "attempt_timestamp": "2026-07-11T12:35:04+08:00",
                        "confirmed_timestamp": "2026-07-11T12:35:43+08:00",
                        "description": "SSH login confirmed",
                    }
                ]
            },
            "lateral_movement_graph": {"nodes": [], "edges": []},
            "impacted_assets": [],
        }

        report = render_traceability_report(result, locale="zh-CN")

        self.assertIn("**主证据**: web-primary", report)
        self.assertIn("**入口角色**: compromise_trigger", report)
        self.assertIn("**攻破点状态**: supported", report)
        self.assertIn("**最早观测控制页面**: https://gateway.example/webshell/", report)
        self.assertIn("(10 total)", report)
        normalized_report = report.replace("\u00a0", " ")
        self.assertIn("SSH 横向尝试 2026-07-11T12:35:04+08:00", normalized_report)
        self.assertIn("登录确认 2026-07-11T12:35:43+08:00", normalized_report)
        self.assertIn("首次尝试 2026-07-11T12:35:04+08:00", normalized_report)

    def test_render_contains_skill_sections_zh(self):
        payload = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        from correlate import analyze  # noqa: E402
        from risk_rules_bridge import load_trace_patterns  # noqa: E402

        result = analyze(payload, load_trace_patterns())
        report = render_traceability_report(result, locale="zh-CN")
        for section in (
            "## 溯源分析报告",
            "### 攻击叙事",
            "### 初始入口",
            "### 攻击路径图",
            "### 攻击时间线",
            "### MITRE ATT&CK",
            "### 横向移动",
            "### 影响范围",
            "### 处置建议",
        ):
            self.assertIn(section, report)

    def test_render_contains_skill_sections_en(self):
        payload = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        from correlate import analyze  # noqa: E402
        from risk_rules_bridge import load_trace_patterns  # noqa: E402

        result = analyze(payload, load_trace_patterns())
        report = render_traceability_report(result, locale="en")
        self.assertIn("## Traceability Analysis Report", report)
        self.assertIn("### Attack path graph", report)
        self.assertIn("### Attack timeline", report)
        self.assertIn("### Lateral movement", report)

    def test_render_attack_path_graph_without_lateral_edges(self):
        result = {
            "scenario": ["S5"],
            "overall_verdict": "initial_access_only",
            "confidence": 0.5,
            "confidence_ceiling": 0.5,
            "summary": "entry only",
            "initial_access": {
                "host": "192.0.2.91",
                "target_ip": "192.0.2.91",
                "attacker_ip": "39.144.124.143",
                "timestamp": "2026-07-10T13:04:11+08:00",
                "url": "http://portal.example.com/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
                "vector": "web_exploit:rce",
                "evidence_refs": ["web-001", "exec-001"],
            },
            "lateral_movement_graph": {"nodes": [], "edges": []},
            "impacted_assets": [{"host": "192.0.2.91", "role": "initial_compromise", "priority": "P0"}],
            "host_high_risk_summary": {"192.0.2.91": ["凭据访问"]},
            "timeline": [],
        }

        report = render_traceability_report(result, locale="zh-CN")

        self.assertIn("### 攻击路径图", report)
        self.assertIn("```mermaid", report)
        self.assertIn("39.144.124.143", report)
        self.assertIn("192.0.2.91", report)
        self.assertIn("### 横向移动", report)
        self.assertIn("_(none)_", report)

    def test_attack_path_graph_shows_lateral_target_high_risk_commands(self):
        result = {
            "scenario": ["S5"],
            "overall_verdict": "likely_intrusion_chain",
            "confidence": 0.5,
            "confidence_ceiling": 0.5,
            "summary": "lateral target",
            "initial_access": {
                "host": "192.0.2.91",
                "target_ip": "192.0.2.91",
                "attacker_ip": "192.168.99.16",
                "timestamp": "2026-07-10T17:42:16+08:00",
                "url": "https://test1.u.yinshendun.com:30443/webshell/upload.php",
                "vector": "webshell",
                "evidence_refs": ["waf-001", "web-001"],
            },
            "lateral_movement_graph": {
                "nodes": [
                    {"id": "attacker", "label": "192.168.99.16"},
                    {"id": "192.0.2.91", "label": "192.0.2.91"},
                ],
                "edges": [
                    {"from": "attacker", "to": "192.0.2.91", "stage": "initial_access"},
                    {"from": "192.0.2.91", "to": "192.0.2.92", "stage": "lateral_movement"},
                ],
            },
            "impacted_assets": [
                {"host": "192.0.2.91", "role": "initial_compromise", "priority": "P0"},
                {"host": "192.0.2.92", "role": "lateral_target", "priority": "P0"},
            ],
            "host_high_risk_summary": {
                "192.0.2.92": ["窃取凭据文件", "sudo/提权", "侦察扫描"],
            },
            "timeline": [],
        }

        report = render_traceability_report(result, locale="zh-CN")

        self.assertIn("192.0.2.92", report)
        self.assertIn("高危: 窃取凭据文件; sudo/提权; 侦察扫描", report)

    def test_attack_path_graph_shows_waf_gateway_and_first_web_packet(self):
        result = {
            "scenario": ["S5"],
            "overall_verdict": "initial_access_only",
            "confidence": 0.5,
            "confidence_ceiling": 0.5,
            "summary": "web entry",
            "initial_access": {
                "host": "192.0.2.91",
                "target_ip": "192.0.2.91",
                "attacker_ip": "192.168.99.16",
                "timestamp": "2026-07-10T17:42:16+08:00",
                "url": "https://test1.u.yinshendun.com:30443/webshell/upload.php",
                "vector": "webshell",
                "evidence_refs": ["waf-001", "web-001"],
            },
            "lateral_movement_graph": {
                "nodes": [
                    {"id": "attacker", "label": "192.168.99.16"},
                    {"id": "192.0.2.91", "label": "192.0.2.91"},
                ],
                "edges": [{"from": "attacker", "to": "192.0.2.91", "stage": "initial_access"}],
            },
            "timeline": [
                {
                    "timestamp": "2026-07-10T17:42:13+08:00",
                    "stage": "web_attack",
                    "host": "192.0.2.91",
                    "raw_behavior": "GET https://test1.u.yinshendun.com:30443/.env action=block",
                    "evidence_refs": ["waf-001"],
                }
            ],
            "impacted_assets": [{"host": "192.0.2.91", "role": "initial_compromise", "priority": "P0"}],
        }

        report = render_traceability_report(result, locale="zh-CN")

        self.assertIn("WAF网关", report)
        self.assertIn("test1.u.yinshendun.com:30443", report)
        self.assertIn("首包 GET /.env", report)
        self.assertIn("命中 /webshell/upload.php", report)

    def test_attack_path_graph_derives_target_commands_when_summary_missing(self):
        result = {
            "scenario": ["S5"],
            "overall_verdict": "likely_intrusion_chain",
            "confidence": 0.5,
            "confidence_ceiling": 0.5,
            "summary": "lateral target",
            "initial_access": {
                "host": "192.0.2.91",
                "target_ip": "192.0.2.91",
                "attacker_ip": "192.168.99.16",
                "timestamp": "2026-07-10T17:42:16+08:00",
                "url": "https://test1.u.yinshendun.com:30443/webshell/upload.php",
                "vector": "webshell",
                "evidence_refs": ["waf-001", "web-001"],
            },
            "lateral_movement_graph": {
                "nodes": [{"id": "192.0.2.91", "label": "192.0.2.91"}],
                "edges": [{"from": "192.0.2.91", "to": "192.0.2.92", "stage": "lateral_movement"}],
            },
            "lateral_findings": {
                "likely": [
                    {
                        "host": "192.0.2.92",
                        "source_host": "192.0.2.91",
                        "high_risk_summary": {"categories": ["discovery", "privilege_escalation"]},
                    }
                ]
            },
            "host_high_risk_summary": {},
            "timeline": [
                {
                    "timestamp": "2026-07-10T17:43:21+08:00",
                    "stage": "execution",
                    "host": "192.0.2.91",
                    "raw_behavior": "sshpass -p devops123 ssh devops@192.0.2.92 cat /home/devops/.config/deploy-token.json",
                    "evidence_refs": ["exec-001"],
                }
            ],
            "impacted_assets": [{"host": "192.0.2.92", "role": "lateral_target", "priority": "P0"}],
        }

        report = render_traceability_report(result, locale="zh-CN")

        self.assertIn("192.0.2.92", report)
        self.assertIn("高危:", report)
        self.assertIn("侦察扫描", report)
        self.assertIn("sudo/提权", report)
        self.assertIn("窃取凭据文件", report)

    def test_timeline_deduplication(self):
        steps = [
            {"timestamp": "t1", "stage": "execution", "host": "a", "description": "same"},
            {"timestamp": "t2", "stage": "execution", "host": "a", "description": "same"},
            {"timestamp": "t3", "stage": "lateral_movement", "host": "b", "description": "ssh"},
        ]
        selected, total = _select_timeline_steps(steps, max_rows=10)
        self.assertEqual(total, 3)
        self.assertGreaterEqual(len(selected), 2)


if __name__ == "__main__":
    unittest.main()
