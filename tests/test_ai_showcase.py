"""End-to-end checks for the credential-free AI Showcase catalog."""

from __future__ import annotations

import copy
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from typing import Any

from src.scripts.run_ai_showcase import main, validate_case
from src.scripts.ai_showcase_reports import render_case

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "src/scripts/run_ai_showcase.py"
CATALOG = REPO_ROOT / "examples/ai-showcase/cases.json"


def assert_expected(test: unittest.TestCase, actual: Any, expected: Any, path: str = "result") -> None:
    """Recursively compare the stable expected subset with a full Skill result."""
    if isinstance(expected, dict):
        test.assertIsInstance(actual, dict, path)
        for key, value in expected.items():
            test.assertIn(key, actual, f"{path}.{key}")
            assert_expected(test, actual[key], value, f"{path}.{key}")
        return
    test.assertEqual(actual, expected, path)


class TestAiShowcase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """Load the catalog once; individual cases remain isolated subprocesses."""
        cls.catalog = json.loads(CATALOG.read_text(encoding="utf-8"))

    def test_catalog_references_public_offline_inputs(self) -> None:
        cases = self.catalog["cases"]
        self.assertTrue(self.catalog["offline"])
        self.assertGreaterEqual(len(cases), 5)
        case_ids = [case["case_id"] for case in cases]
        self.assertEqual(len(case_ids), len(set(case_ids)))
        self.assertEqual(self.catalog["default_mode"], "all")
        # New assessment fixtures must join the public batch, without counting
        # the original five aliases as duplicate inputs.
        expected_inputs = {
            str(path.relative_to(REPO_ROOT))
            for folder in ("alert-confirmation", "data-source-completeness", "traceability", "risk-identification")
            for path in (REPO_ROOT / "examples" / folder).glob("*.json")
        }
        self.assertEqual({case["input"] for case in cases}, expected_inputs)
        self.assertEqual(len(cases), len(expected_inputs))

        for case in cases:
            with self.subTest(case=case["case_id"]):
                self.assertTrue(case["offline"])
                self.assertTrue((REPO_ROOT / case["input"]).is_file())
                self.assertTrue((REPO_ROOT / case["skill_doc"]).is_file())
                self.assertTrue(case["output"].startswith("outputs/ai-showcase/"))
                args = case["cli_args"]
                self.assertEqual(args[:2], ["skill", case["skill"]])
                self.assertNotIn("--fetch", args)
                self.assertNotIn("--notify", args)
                if case["skill"] == "traceability-analysis":
                    self.assertIn("--no-notify", args)
                    self.assertIn("--no-ip-intel", args)

    def test_traceability_case_requires_explicit_network_opt_outs(self) -> None:
        """A future public-IP fixture must not silently enable online intelligence."""
        case = next(item for item in self.catalog["cases"] if item["skill"] == "traceability-analysis")
        for flag in ("--no-notify", "--no-ip-intel"):
            with self.subTest(missing=flag):
                modified = copy.deepcopy(case)
                modified["cli_args"].remove(flag)
                with self.assertRaisesRegex(ValueError, flag):
                    validate_case(modified)

    def test_every_case_produces_expected_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            for case in self.catalog["cases"]:
                with self.subTest(case=case["case_id"]):
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(RUNNER),
                            case["case_id"],
                            "--json",
                            "--output-dir",
                            str(output_dir),
                        ],
                        cwd=REPO_ROOT,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    summary = json.loads(result.stdout)
                    self.assertTrue(summary["expected_verdict_matched"])
                    payload = json.loads((output_dir / f"{case['case_id']}.json").read_text(encoding="utf-8"))
                    assert_expected(self, payload, case["expected"])
                    report = Path(summary["report"]).read_text(encoding="utf-8")
                    self.assertTrue(report.startswith("# 数据取数统计"))
                    self.assertIn("结构化结果报告", report)
                    self.assertIn("原始证据时间线", report)
                    self.assertIn("数据缺口与结论边界", report)

    def test_default_and_explicit_all_run_every_case(self) -> None:
        """Both batch entrypoints persist all results and machine-readable counts."""
        for selection in ([], ["--all"]):
            with self.subTest(selection=selection), tempfile.TemporaryDirectory() as directory:
                process = subprocess.run(
                    [sys.executable, str(RUNNER), *selection, "--json", "--output-dir", directory],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, check=False,
                )
                self.assertEqual(process.returncode, 0, process.stderr)
                summary = json.loads(process.stdout)
                self.assertEqual(summary["total"], len(self.catalog["cases"]))
                self.assertEqual(summary["passed"], summary["total"])
                self.assertEqual(summary["failed"], 0)
                self.assertEqual([r["case_id"] for r in summary["results"]],
                                 [c["case_id"] for c in self.catalog["cases"]])
                self.assertEqual(json.loads(Path(summary["output"]).read_text()), summary)
                report = Path(summary["report"]).read_text(encoding="utf-8")
                for case, result in zip(self.catalog["cases"], summary["results"]):
                    assert_expected(self, json.loads(Path(result["output"]).read_text()), case["expected"])
                    self.assertTrue(Path(result["report"]).is_file())
                    self.assertIn(case["case_id"], report)
                    self.assertIn(Path(result["report"]).name, report)

    def test_batch_continues_after_failure_and_timeout(self) -> None:
        """Failures cannot hide later cases or link stale artifacts as successes."""
        outcomes = [ValueError("expectation mismatch"), subprocess.TimeoutExpired("case", 60),
                    {"ok": True, "case_id": "last", "output": "last.json", "report": "last.md"}]
        catalog = {"cases": [{"case_id": key} for key in ("first", "timeout", "last")]}
        with tempfile.TemporaryDirectory() as directory, \
                patch("src.scripts.run_ai_showcase.load_catalog", return_value=catalog), \
                patch("src.scripts.run_ai_showcase.run_case", side_effect=outcomes) as run, \
                contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main(["--json", "--output-dir", directory]), 1)
            summary = json.loads(stdout.getvalue())
            self.assertEqual(run.call_count, 3)
            self.assertEqual((summary["passed"], summary["failed"]), (1, 2))
            self.assertTrue(summary["results"][-1]["ok"])
            for result in summary["results"][:2]:
                self.assertNotIn("output", result)
                self.assertIn("error", result)
            report = Path(summary["report"]).read_text()
            self.assertIn("expectation mismatch", report)
            self.assertNotIn("first.md", report)
            self.assertNotIn("timeout.md", report)
            self.assertIn("last.md", report)

    def test_report_failure_does_not_claim_case_success(self) -> None:
        """Fail closed on unreadable report delivery, while continuing the batch."""
        case = copy.deepcopy(self.catalog["cases"][0])
        with tempfile.TemporaryDirectory() as directory, \
                patch("src.scripts.run_ai_showcase.load_catalog", return_value={"cases": [case]}), \
                patch("src.scripts.run_ai_showcase.render_case", side_effect=OSError("report write denied")), \
                contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main(["--json", "--output-dir", directory]), 1)
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["failed"], 1)
            self.assertNotIn("report", summary["results"][0])
            self.assertIn("report write denied", Path(summary["report"]).read_text())

    def test_report_uses_observed_evidence_and_preserves_query_gaps(self) -> None:
        """Expected answers and injected Markdown must never become report evidence."""
        case = {"case_id": "new-case", "skill": "alert-confirmation", "expected": {"secret": "EXPECTED_ONLY"}}
        evidence = {"_meta": {"expected": "META_ONLY"}, "primary_alerts": [{
            "alert_id": "a1", "timestamp": "t1", "payload": "<script>x</script>|[link](https://bad.invalid)\n# fake"
        }]}
        result = {"alert_id": "a1", "alert_verdict": "scanning_or_probe", "attack_outcome": "success_unknown",
                  "data_gaps_impact": ["host_exec timeout"], "fetch_summary": {
                      "total_events": 1, "total_fetch_queries": 2, "failed_fetch_queries": 1,
                      "query_integrity": {"status": "incomplete"}},
                  "analysis_constraints": {"recommended_confidence_ceiling": 0.65}}
        report = render_case(case, evidence, result, Path("input.json"), Path("result.json"))
        self.assertIn("success\\_unknown", report)
        self.assertIn("timeout", report)
        self.assertIn("incomplete", report)
        self.assertIn("0.65", report)
        self.assertNotIn("EXPECTED_ONLY", report)
        self.assertNotIn("META_ONLY", report)
        self.assertNotIn("<script>", report)
        self.assertNotIn("|[link]", report)
        self.assertNotIn("\n# fake", report)

    def test_unknown_case_and_conflicting_selection_do_not_run(self) -> None:
        for selection in (["missing-case"], ["--all", "reverse-shell-risk"]):
            with self.subTest(selection=selection), tempfile.TemporaryDirectory() as directory:
                process = subprocess.run(
                    [sys.executable, str(RUNNER), *selection, "--output-dir", directory],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
