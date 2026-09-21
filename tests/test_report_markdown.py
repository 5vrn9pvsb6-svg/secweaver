"""Tests for Markdown report rendering."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from report_markdown import (  # noqa: E402
    DEMO_JSON_NAMES,
    render_investigation_bundle,
    render_markdown,
    write_demo_markdown_reports,
)

REPORTS_DIR = REPO_ROOT / "examples/reports"
CLI = REPO_ROOT / "src/secweaver.py"


class TestReportMarkdown(unittest.TestCase):
    def _load_demo(self, name: str) -> dict:
        path = REPORTS_DIR / DEMO_JSON_NAMES[name]
        return json.loads(path.read_text(encoding="utf-8"))

    def test_render_completeness_contains_key_sections(self) -> None:
        text = render_markdown(self._load_demo("completeness"))
        self.assertIn("# Data Source Completeness Report", text)
        self.assertIn("full_traceable", text)
        self.assertIn("Requirement evaluation", text)

    def test_render_alert_contains_verdict_and_join_edges(self) -> None:
        text = render_markdown(self._load_demo("alert"))
        self.assertIn("# Alert Confirmation Report", text)
        self.assertIn("confirmed_attack", text)
        self.assertIn("Join edges", text)

    def test_render_traceability_contains_timeline_and_actions(self) -> None:
        payload = self._load_demo("traceability")
        text = render_markdown(payload)
        if str(payload.get("report_locale") or "").startswith("zh"):
            self.assertIn("## 溯源分析报告", text)
            self.assertIn("攻击时间线", text)
            self.assertIn("处置建议", text)
        else:
            self.assertIn("## Traceability Analysis Report", text)
            self.assertIn("Attack timeline", text)
            self.assertIn("Recommended actions", text)

    def test_render_risk_contains_verdict(self) -> None:
        text = render_markdown(self._load_demo("risk"))
        self.assertIn("# Risk Identification Report", text)
        self.assertIn("high_risk_detected", text)

    def test_investigation_bundle_includes_all_sections(self) -> None:
        text = render_investigation_bundle(REPORTS_DIR)
        self.assertIn("# SecWeaver Investigation Bundle Report", text)
        self.assertIn("Data source completeness", text)
        self.assertIn("Alert confirmation", text)
        self.assertIn("Attack chain traceability", text)
        self.assertIn("Host risk identification", text)

    def test_write_demo_markdown_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            for filename in DEMO_JSON_NAMES.values():
                source = REPORTS_DIR / filename
                target = out_dir / filename
                target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
            outputs = write_demo_markdown_reports(out_dir)
            self.assertEqual(len(outputs), 4)
            for output in outputs:
                self.assertTrue(output.is_file())
                self.assertIn("#", output.read_text(encoding="utf-8"))


class TestReportCLI(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CLI), "report", "markdown", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_cli_report_single_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "alert.md"
            result = self.run_cli(
                "-i",
                str(REPORTS_DIR / "demo-alert-output.json"),
                "-o",
                str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())
            self.assertIn("Alert Confirmation Report", output.read_text(encoding="utf-8"))

    def test_cli_report_demo_all_with_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            for filename in DEMO_JSON_NAMES.values():
                source = REPORTS_DIR / filename
                target = Path(tmpdir) / filename
                target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
            result = self.run_cli("--demo", "all", "--input-dir", tmpdir, "--bundle")
            self.assertEqual(result.returncode, 0, result.stderr)
            bundle = Path(tmpdir) / "investigation-report.md"
            self.assertTrue(bundle.is_file())
            self.assertIn("Investigation Bundle Report", bundle.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
