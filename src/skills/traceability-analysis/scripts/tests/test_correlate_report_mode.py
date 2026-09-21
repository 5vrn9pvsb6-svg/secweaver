"""Tests for correlate.py report_mode and timeline mitre_id."""

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

from correlate import analyze, trace_markdown_report  # noqa: E402
from risk_rules_bridge import load_trace_patterns  # noqa: E402
from trace_report_markdown import render_traceability_report  # noqa: E402


class CorrelateReportModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        self.patterns = load_trace_patterns()

    def test_timeline_includes_mitre_id(self) -> None:
        result = analyze(self.payload, self.patterns)
        chain_with_mitre = [s for s in result.get("attack_chain") or [] if s.get("mitre_id")]
        timeline_with_mitre = [s for s in result.get("timeline") or [] if s.get("mitre_id")]
        self.assertTrue(chain_with_mitre)
        context = [s for s in result["timeline"] if s.get("stage") == "network_activity"]
        self.assertTrue(context)
        self.assertTrue(all(not s.get("mitre_id") for s in context))
        self.assertEqual(len(timeline_with_mitre) + len(context), len(result["timeline"]))

    def test_timeline_includes_web_attack_and_raw_behavior(self) -> None:
        result = analyze(self.payload, self.patterns)
        timeline = result.get("timeline") or []
        web_steps = [s for s in timeline if s.get("stage") == "web_attack"]
        self.assertTrue(web_steps)
        self.assertTrue(any("upload.php" in str(s.get("raw_behavior") or "") for s in web_steps))

        execution_steps = [s for s in timeline if s.get("stage") == "execution"]
        self.assertTrue(execution_steps)
        self.assertTrue(any(s.get("raw_behavior") for s in execution_steps))

    def test_markdown_timeline_shows_mitre_when_present(self) -> None:
        result = analyze(self.payload, self.patterns)
        report = render_traceability_report(result, locale="zh-CN")
        self.assertIn("### 攻击时间线", report)
        self.assertNotIn("原始行为", report)
        self.assertIn("| 时间 | 阶段 | 主机 | 描述 | ATT&CK | 证据 |", report)
        self.assertNotIn("```text", report)
        self.assertNotIn("traceability-scroll-table", report)
        self.assertNotIn("<td", report)
        self.assertIn("T1190", report)

    def test_trace_markdown_report_still_available_for_script_mode(self) -> None:
        result = analyze(self.payload, self.patterns)
        md = trace_markdown_report(result, locale="zh-CN")
        self.assertIn("## 溯源分析报告", md)


if __name__ == "__main__":
    unittest.main()
