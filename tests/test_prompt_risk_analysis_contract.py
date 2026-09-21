"""Regression tests for the prompt-only risk analysis contract and WAF golden fixture."""

from __future__ import annotations

import copy
import json
import re
import unittest
from datetime import datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, FormatChecker, ValidationError
except ImportError:  # Project dependencies may be absent in a bare source checkout.
    Draft202012Validator = None
    FormatChecker = None
    ValidationError = Exception

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = REPO_ROOT / "src" / "skills" / "prompt-risk-analysis"
EXAMPLE_DIR = REPO_ROOT / "examples" / "prompt-risk-analysis"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def evidence_ids(payload: dict) -> set[str]:
    return {
        event["evidence_id"]
        for events in payload["evidence_bundles"].values()
        for event in events
    }


class TestPromptRiskAnalysisContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load_json(SKILL_DIR / "output-schema.json")
        cls.fixture = load_json(EXAMPLE_DIR / "fetch-waf-bypass-mini.json")
        cls.report = load_json(EXAMPLE_DIR / "report-waf-bypass-mini.json")
        cls.validator = (
            Draft202012Validator(cls.schema, format_checker=FormatChecker())
            if Draft202012Validator is not None
            else None
        )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema dependency is not installed")
    def test_schema_and_golden_report_are_valid(self) -> None:
        Draft202012Validator.check_schema(self.schema)
        self.validator.validate(self.report)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema dependency is not installed")
    def test_s4_requires_waf_coverage(self) -> None:
        report = copy.deepcopy(self.report)
        del report["waf_coverage"]
        with self.assertRaises(ValidationError):
            self.validator.validate(report)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema dependency is not installed")
    def test_evidence_refs_require_id_and_redaction(self) -> None:
        for field in ("evidence_id", "redacted"):
            report = copy.deepcopy(self.report)
            del report["findings"][0]["evidence_refs"][0][field]
            with self.subTest(field=field), self.assertRaises(ValidationError):
                self.validator.validate(report)

    def test_retained_and_deduplicated_counts_are_consistent(self) -> None:
        summary = self.fixture["fetch_summary"]
        retained_by_type = {
            asset_type: len(events)
            for asset_type, events in self.fixture["evidence_bundles"].items()
        }
        self.assertEqual(retained_by_type, summary["by_asset_type"])
        self.assertEqual(sum(retained_by_type.values()), summary["total_events"])
        self.assertEqual(
            summary["total_fetched_events"],
            summary["total_events"] + summary["total_deduplicated_events"],
        )

        inventory = self.report["inventory"]
        self.assertEqual(inventory["counting"]["count_basis"], "retained_events")
        self.assertEqual(inventory["counting"]["raw_count"], summary["total_fetched_events"])
        self.assertEqual(inventory["counting"]["retained_count"], summary["total_events"])
        self.assertEqual(
            inventory["counting"]["deduplicated_count"],
            summary["total_deduplicated_events"],
        )

    def test_waf_coverage_matches_fixture_expectations(self) -> None:
        expected = self.fixture["fixture_expectations"]["waf_coverage"]
        coverage = self.report["waf_coverage"]
        for field, value in expected.items():
            self.assertEqual(coverage[field], value, field)

        self.assertLessEqual(
            coverage["confirmed_bypass_count"],
            coverage["suspicious_without_waf_count"],
        )
        self.assertLessEqual(coverage["blocked_count"], coverage["waf_alert_count"])
        self.assertEqual(coverage["count_basis"], "retained_events")

    def test_report_evidence_is_traceable_to_fixture(self) -> None:
        available = evidence_ids(self.fixture)
        cited = {
            ref["evidence_id"]
            for finding in self.report["findings"]
            for ref in finding["evidence_refs"]
        }
        timeline = {
            evidence_id
            for item in self.report["timeline"]
            for evidence_id in item["evidence_ids"]
        }
        self.assertTrue(cited)
        self.assertLessEqual(cited, available)
        self.assertLessEqual(timeline, available)

    def test_exec_syslog_fixture_keeps_context_within_declared_window(self) -> None:
        """A golden report must not rely on events outside its advertised fetch window."""
        fixture = load_json(EXAMPLE_DIR / "fetch-exec-syslog-mini.json")
        start = datetime.fromisoformat(fixture["params"]["time_start"])
        end = datetime.fromisoformat(fixture["params"]["time_end"])
        self.assertLess(start, end)
        for asset_type, events in fixture["evidence_bundles"].items():
            for event in events:
                with self.subTest(asset_type=asset_type, evidence_id=event["evidence_id"]):
                    self.assertLessEqual(start, datetime.fromisoformat(event["timestamp"]))
                    self.assertLessEqual(datetime.fromisoformat(event["timestamp"]), end)

    def test_exec_syslog_golden_report_does_not_infer_ssh_success(self) -> None:
        """A source-side SSH command alone cannot establish target-side compromise."""
        fixture = load_json(EXAMPLE_DIR / "fetch-exec-syslog-mini.json")
        self.assertNotIn("ssh_auth", fixture["evidence_bundles"])
        report = (EXAMPLE_DIR / "report-exec-syslog-mini.zh-CN.md").read_text(encoding="utf-8")
        self.assertIn("不能确认横向成功", report)
        self.assertNotIn("横向成功 T1021.004", report)
        self.assertNotIn("sshpass devops123", report)

    def test_golden_report_obeys_redaction_contract(self) -> None:
        self.assertTrue(self.report["redaction"]["applied"])
        self.assertFalse(self.report["redaction"]["contains_reusable_secrets"])
        for finding in self.report["findings"]:
            for ref in finding["evidence_refs"]:
                self.assertTrue(ref["redacted"])
                self.assertNotIn("raw_snippet", ref)

        serialized = json.dumps(self.report, ensure_ascii=False)
        forbidden_patterns = (
            r"sshpass\s+-p\s+(?!\[REDACTED\])\S+",
            r"password\s*[=:]\s*(?!\[REDACTED\])\S+",
            r"authorization\s*:\s*bearer\s+(?!\[REDACTED\])\S+",
            r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----",
        )
        for pattern in forbidden_patterns:
            self.assertIsNone(re.search(pattern, serialized, flags=re.IGNORECASE), pattern)


if __name__ == "__main__":
    unittest.main()
