"""Validate the unified Skill catalog and representative machine outputs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "src" / "skills" / "manifest.json"
COMMON_SCHEMA = ROOT / "src/skills/_shared/skill_runtime/schemas/skill-envelope.schema.json"
REPORTS = ROOT / "examples/reports"
EXAMPLES = ROOT / "examples"
SHOWCASE_CATALOG = EXAMPLES / "ai-showcase/cases.json"

sys.path.insert(0, str(ROOT / "src/skills/_shared"))
from skill_runtime.execution import SKILL_SCRIPTS  # noqa: E402

sys.path.insert(0, str(ROOT / "src/skills/log-format-discovery/scripts"))
from discover import detect_format, load_samples, preview_events  # noqa: E402


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def schema_registry() -> Registry:
    common = load_json(COMMON_SCHEMA)
    return Registry().with_resource(
        "https://secweaver.local/schemas/skill-envelope.json",
        Resource.from_contents(common),
    )


def validate_output(schema_path: Path, payload: dict) -> None:
    schema = load_json(schema_path)
    Draft202012Validator(
        schema, registry=schema_registry(), format_checker=FormatChecker()
    ).validate(payload)


class SkillCatalogAndOutputContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.skills = {entry["key"]: entry for entry in load_json(MANIFEST)["skills"]}
        catalog_cases = load_json(SHOWCASE_CATALOG)["cases"]
        skill_names = {
            "completeness": "data-source-completeness",
            "alert": "alert-confirmation",
            "traceability": "traceability-analysis",
            "risk": "risk-identification",
        }
        # The Showcase catalog owns the public assessment inventory. Keeping
        # exact path sets here prevents a fixture from silently escaping batch runs.
        cls.catalog_inputs = {
            key: {
                ROOT / case["input"]
                for case in catalog_cases
                if case["skill"] == skill_name
            }
            for key, skill_name in skill_names.items()
        }

    def assessment_paths(self, key: str, directory: str) -> list[Path]:
        """Return the exact catalog-backed fixture set for one assessment Skill."""
        paths = sorted((EXAMPLES / directory).glob("*.json"))
        self.assertEqual(set(paths), self.catalog_inputs[key])
        return paths

    def test_documented_case_counts_match_catalog(self) -> None:
        """Keep quickstarts and inventory summaries aligned with the case catalog."""
        counts = {key: len(paths) for key, paths in self.catalog_inputs.items()}
        total = sum(counts.values())
        expectations = {
            ROOT / "README.md": f"all {total} executable assessment cases",
            ROOT / "README.zh-CN.md": f"全部 {total} 个可执行评估案例",
            ROOT / "docs_user/00-security-operator-quickstart.md":
                f"all {total} executable assessment cases",
            ROOT / "docs_user/00-security-operator-quickstart.zh-CN.md":
                f"全部 {total} 个可执行评估案例",
            EXAMPLES / "README.md": f"**{total} distinct executable assessment inputs**",
            EXAMPLES / "README.zh-CN.md": f"**{total} 份不同的离线输入**",
            EXAMPLES / "CASE-CATALOG.md": f"**{total} distinct executable assessment inputs**",
            EXAMPLES / "CASE-CATALOG.zh-CN.md": f"**{total} 份不同的可执行评估输入**",
            EXAMPLES / "ai-showcase/README.md": (
                f"covers {total} assessment inputs ({counts['completeness']} completeness, "
                f"{counts['alert']} alert, {counts['traceability']} traceability, {counts['risk']} risk)"
            ),
            EXAMPLES / "ai-showcase/README.zh-CN.md": (
                f"覆盖 {total} 份评估输入（完整性 {counts['completeness']}、告警 {counts['alert']}、\n"
                f"溯源 {counts['traceability']}、风险 {counts['risk']}）"
            ),
        }
        for path, marker in expectations.items():
            with self.subTest(document=path.name):
                self.assertIn(marker, path.read_text(encoding="utf-8"))

    def run_offline_example(self, key: str, path: Path) -> tuple[dict, dict]:
        """Execute public samples in isolated processes so metadata cannot mask runtime drift."""
        entry = self.skills[key]
        args = [sys.executable, str(ROOT / entry["script"]), "-i", str(path)]
        if key == "traceability":
            # Offline regressions must not resolve IP intelligence or send webhook reports.
            args += ["--no-ip-intel", "--no-notify", "--no-markdown-report"]
        process = subprocess.run(
            args, cwd=ROOT, capture_output=True, text=True, timeout=30, check=False
        )
        self.assertEqual(process.returncode, 0, f"{path}: {process.stderr}")
        payload = json.loads(process.stdout)
        validate_output(ROOT / entry["output_schema"], payload)
        meta = load_json(path).get("_meta", {})
        self.assertTrue(meta.get("scenario_label"), str(path))
        return payload, meta

    def run_counterfactual(self, key: str, payload: dict) -> dict:
        """Exercise edited evidence through the same isolated CLI and Schema checks."""
        payload["_meta"] = {"scenario_label": "counterfactual evidence change"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "counterfactual.json"
            path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            result, _ = self.run_offline_example(key, path)
        return result

    def test_all_completeness_examples_match_expected_decisions(self) -> None:
        paths = self.assessment_paths("completeness", "data-source-completeness")
        for path in paths:
            with self.subTest(example=path.name):
                result, meta = self.run_offline_example("completeness", path)
                for field in ("overall_verdict", "next_skill_blocked", "next_skill", "can_confirm_breach"):
                    if f"expected_{field}" in meta:
                        self.assertEqual(result[field], meta[f"expected_{field}"])
                if "expected_block_reason_contains" in meta:
                    self.assertIn(meta["expected_block_reason_contains"], result["block_reason"])

    def test_all_alert_examples_match_expected_outcomes(self) -> None:
        paths = self.assessment_paths("alert", "alert-confirmation")
        for path in paths:
            with self.subTest(example=path.name):
                result, meta = self.run_offline_example("alert", path)
                if "expected_batch_summary" in meta:
                    self.assertEqual(len(result["results"]), meta["expected_result_count"])
                    for field, expected in meta["expected_batch_summary"].items():
                        self.assertEqual(result["batch_summary"][field], expected)
                    self.assertEqual(
                        result["fetch_summary"]["query_integrity"]["status"],
                        meta["expected_query_integrity_status"],
                    )
                else:
                    for field in ("alert_verdict", "attack_outcome", "attack_success", "next_skill"):
                        if f"expected_{field}" in meta:
                            self.assertEqual(result[field], meta[f"expected_{field}"])

    def test_webshell_success_degrades_without_host_evidence(self) -> None:
        """A matched WAF/Web request alone cannot establish command execution."""
        payload = load_json(EXAMPLES / "alert-confirmation/s4-webshell-attack-success.json")
        for source in ("host_exec", "host_connect", "host_file_op"):
            payload["correlated_evidence"][source] = []
        result = self.run_counterfactual("alert", payload)
        self.assertEqual(result["alert_verdict"], "confirmed_attack")
        self.assertEqual(result["attack_outcome"], "success_unknown")
        self.assertFalse(result["attack_success"])

    def test_all_traceability_examples_match_expected_joins(self) -> None:
        paths = self.assessment_paths("traceability", "traceability")
        for path in paths:
            with self.subTest(example=path.name):
                result, meta = self.run_offline_example("traceability", path)
                self.assertEqual(result["overall_verdict"], meta["expected_verdict"])
                matched = {edge["join_id"] for edge in result["join_edges"]}
                for join in meta.get("correlation_joins", []):
                    self.assertIn(join, matched)
                for join in meta.get("missing_joins", []):
                    self.assertEqual(result["join_coverage"]["per_join"][join], "no_match")

    def test_lateral_claim_degrades_when_ssh_success_is_removed_or_unrelated(self) -> None:
        """A Join edge or another host's success is not proof of this lateral path."""
        source = EXAMPLES / "traceability/s1-web-shell-to-ssh-lateral.json"
        for change in ("failed", "unrelated_source"):
            with self.subTest(change=change):
                payload = load_json(source)
                for event in payload["evidence_bundles"]["ssh_auth"]:
                    if event["result"] == "Accepted":
                        if change == "failed":
                            event["result"] = "Failed"
                        else:
                            event["src_ip"] = "10.0.9.9"
                result = self.run_counterfactual("traceability", payload)
                self.assertEqual(result["overall_verdict"], "initial_access_only")
                self.assertEqual(result["lateral_findings"]["confirmed"], [])

    def test_all_risk_examples_match_expected_rules(self) -> None:
        paths = self.assessment_paths("risk", "risk-identification")
        for path in paths:
            with self.subTest(example=path.name):
                result, meta = self.run_offline_example("risk", path)
                self.assertEqual(result["overall_verdict"], meta["expected_overall_verdict"])
                items = result["risk_items"]
                self.assertGreaterEqual(len(items), meta.get("expected_risk_items_min", meta.get("expected_risk_items_exact", 1)))
                if "expected_risk_items_exact" in meta:
                    self.assertEqual(len(items), meta["expected_risk_items_exact"])
                if "expected_highest_severity" in meta:
                    # Severity has priority order P0..P3; derive it from findings, not summary text.
                    self.assertEqual(
                        min((item["severity"] for item in items), key=lambda s: int(s[1:])),
                        meta["expected_highest_severity"],
                    )
                for module in meta.get("expected_risk_modules", []):
                    self.assertIn(module, result["risk_modules_run"])
                    if items:
                        self.assertIn(module, {item["risk_module"] for item in items})
                matched = {rule for item in items for rule in item.get("matched_rules", [])}
                for rule in meta.get("expected_matched_rules", []) + meta.get("expected_matched_rules_contains", []):
                    self.assertIn(rule, matched)
                for rule in meta.get("expected_unmatched_rules", []):
                    self.assertNotIn(rule, matched)
                if "expected_alert_required" in meta:
                    self.assertTrue(all(item["alert_required"] == meta["expected_alert_required"] for item in items))
                if "expected_whitelist_hit" in meta:
                    self.assertIn(meta["expected_whitelist_hit"], {hit["rule_id"] for hit in result["whitelist_hits"]})
                if "expected_ssh_brute_waves" in meta:
                    self.assertEqual(len(result["ssh_brute_waves"]), meta["expected_ssh_brute_waves"])
                if "expected_unproven_claim" in meta:
                    self.assertNotIn(meta["expected_unproven_claim"], result)

    def test_ssh_threshold_pair_differs_by_exactly_one_failure(self) -> None:
        """Keep the public 9-vs-10 comparison isolated to the threshold event."""
        directory = EXAMPLES / "risk-identification"
        below = load_json(directory / "s5-ssh-nine-failures-below-threshold.json")
        reached = load_json(directory / "s5-ssh-bruteforce-p0.json")
        self.assertEqual(below["params"], reached["params"])
        self.assertEqual(below["risk_modules"], reached["risk_modules"])
        self.assertEqual(below["evidence_bundles"]["ssh_auth"], reached["evidence_bundles"]["ssh_auth"][:9])
        self.assertEqual(len(reached["evidence_bundles"]["ssh_auth"]), 10)

    def test_s6_root_login_requires_high_risk_source_context(self) -> None:
        """A normal-risk login must not inherit the S6 candidate's P1 conclusion."""
        payload = load_json(EXAMPLES / "risk-identification/s6-root-ssh-login-p1.json")
        payload["evidence_bundles"]["syslog_risk_alert"][0]["risk_level"] = "low"
        result = self.run_counterfactual("risk", payload)
        self.assertEqual(result["overall_verdict"], "insufficient_data")
        self.assertEqual(result["risk_items"], [])

    def test_s7_connection_context_explains_p1_to_p0_elevation(self) -> None:
        """Removing the correlated connection must retain rules but lower severity."""
        payload = load_json(EXAMPLES / "risk-identification/s7-data-staging-and-scp-p0.json")
        payload["evidence_bundles"]["host_connect"] = []
        result = self.run_counterfactual("risk", payload)
        self.assertEqual(result["overall_verdict"], "high_risk_detected")
        self.assertEqual({item["severity"] for item in result["risk_items"]}, {"P1"})
        matched = {rule for item in result["risk_items"] for rule in item["matched_rules"]}
        self.assertTrue({"data_staging", "network_exfil_tools"}.issubset(matched))

    def test_all_format_discovery_samples_are_recognized(self) -> None:
        # Every public raw sample should remain parseable even when its vendor
        # fields cannot yet be mapped to a particular DataAsset's canonical spec.
        expected = {
            "host-exec-jsonl.sample": ("json_lines", "event_type"),
            "host-exec-webshell-no-tty.sample": ("json_lines", "has_tty"),
            "ssh-auth.log.sample": ("syslog_auth", "src_ip"),
            "vendor-cloud-audit.sample": ("json_lines", "timestamp"),
            "vendor-edr-identity.sample": ("json_lines", "timestamp"),
            "waf-jsonl.sample": ("json_lines", "client_ip"),
        }
        paths = sorted((EXAMPLES / "log-format-discovery").glob("*.sample"))
        self.assertEqual({path.name for path in paths}, set(expected))
        for path in paths:
            with self.subTest(sample=path.name):
                lines = load_samples(input_path=str(path), text=None)
                self.assertTrue(lines)
                fmt = detect_format(lines)
                self.assertEqual(fmt, expected[path.name][0])
                preview = preview_events(lines, fmt)
                self.assertEqual(len(preview), min(len(lines), 20))
                self.assertTrue(any(expected[path.name][1] in event for event in preview))

    def test_waf_raw_sample_maps_to_canonical_normalized_fields(self) -> None:
        """Check the public discovery asset and normalizer, not just JSONL syntax."""
        process = subprocess.run(
            [sys.executable, str(ROOT / "src/skills/log-format-discovery/scripts/discover.py"),
             "--asset-id", "asset-waf-api-prod", "-i", str(EXAMPLES / "log-format-discovery/waf-jsonl.sample"),
             "--preview-normalize"],
            cwd=ROOT, env={**os.environ, "DATAASSET_ROOT": str(ROOT / "dataasset")},
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["detected_format"], "json_lines")
        self.assertEqual(report["gap_analysis"]["missing_required"], [])
        first, second = report["normalized_preview"]
        self.assertEqual((first["src_ip"], first["url"], first["action"]),
                         ("203.0.113.10", "/api?id=1", "blocked"))
        self.assertEqual((second["src_ip"], second["host"]), ("198.51.100.2", "web-01"))
        self.assertEqual(first["timestamp"], "2026-06-21T08:15:01+08:00")
        self.assertEqual(second["timestamp"], "2026-06-21T08:15:02+08:00")

    def test_host_exec_raw_sample_maps_to_canonical_normalized_fields(self) -> None:
        """Exercise a second real discovery asset across aliasing and normalization."""
        process = subprocess.run(
            [sys.executable, str(ROOT / "src/skills/log-format-discovery/scripts/discover.py"),
             "--asset-id", "asset-sls-proxy-host-exec-demo", "-i",
             str(EXAMPLES / "log-format-discovery/host-exec-jsonl.sample"),
             "--preview-normalize"],
            cwd=ROOT, env={**os.environ, "DATAASSET_ROOT": str(ROOT / "dataasset")},
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["gap_analysis"]["missing_required"], [])
        first, second = report["normalized_preview"]
        self.assertEqual((first["host"], first["event_type"]), ("web-01", "exec"))
        self.assertEqual(first["timestamp"], "2026-06-21T09:15:22+08:00")
        self.assertEqual((second["host"], second["event_type"]), ("web-01", "active_connect"))
        self.assertTrue(first["evidence_id"].startswith("host-exec-v2-"))

    def test_catalog_covers_every_top_level_skill(self) -> None:
        manifest = load_json(MANIFEST)
        entries = manifest["skills"]
        self.assertEqual(manifest["version"], "1.1")
        expected = {
            path.name
            for path in (ROOT / "src/skills").iterdir()
            if path.is_dir() and (path / "SKILL.md").is_file()
        }
        self.assertEqual({entry["name"] for entry in entries}, expected)

        for entry in entries:
            with self.subTest(skill=entry["name"]):
                self.assertIn(entry["kind"], {"assessment", "fetch", "operation", "prompt", "router", "subskill"})
                docs = ROOT / entry["docs"]
                self.assertTrue(docs.is_file(), entry["docs"])
                if entry.get("cli_visible"):
                    self.assertTrue((ROOT / entry["script"]).is_file(), entry.get("script"))
                else:
                    self.assertNotIn("script", entry)
                if entry.get("output_schema"):
                    self.assertTrue((ROOT / entry["output_schema"]).is_file(), entry["output_schema"])

    def test_cli_lists_non_cli_workflows_and_rejects_running_them_as_scripts(self) -> None:
        listed = subprocess.run(
            [sys.executable, str(ROOT / "src/secweaver.py"), "list"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("prompt-risk-analysis", listed.stdout)
        rejected = subprocess.run(
            [sys.executable, str(ROOT / "src/secweaver.py"), "skill", "prompt-risk-analysis"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("non-CLI", rejected.stderr)

    def test_runtime_assessments_are_loaded_from_the_catalog(self) -> None:
        manifest = load_json(MANIFEST)
        expected = {
            entry["key"]: (ROOT / entry["script"]).resolve()
            for entry in manifest["skills"]
            if entry.get("kind") == "assessment"
        }
        self.assertEqual(SKILL_SCRIPTS, expected)

    def test_committed_demo_outputs_match_domain_schemas(self) -> None:
        manifest = load_json(MANIFEST)
        for key in ("completeness", "alert", "traceability", "risk"):
            entry = next(item for item in manifest["skills"] if item["key"] == key)
            payload = load_json(REPORTS / f"demo-{key if key != 'traceability' else 'traceability'}-output.json")
            validate_output(ROOT / entry["output_schema"], payload)

    def test_evidence_fetch_fixture_matches_domain_schema(self) -> None:
        manifest = load_json(MANIFEST)
        entry = next(item for item in manifest["skills"] if item["key"] == "evidence-fetch")
        for name in ("fetch-waf-bypass-mini.json", "fetch-exec-syslog-mini.json"):
            with self.subTest(fixture=name):
                payload = load_json(ROOT / "examples/prompt-risk-analysis" / name)
                validate_output(ROOT / entry["output_schema"], payload)

    def test_prompt_analysis_golden_report_matches_strict_schema(self) -> None:
        manifest = load_json(MANIFEST)
        entry = next(item for item in manifest["skills"] if item["key"] == "prompt-risk-analysis")
        report = load_json(ROOT / "examples/prompt-risk-analysis/report-waf-bypass-mini.json")
        validate_output(ROOT / entry["output_schema"], report)

    def test_offline_fetch_handoff_to_risk_without_precheck_matches_schema(self) -> None:
        """A direct evidence handoff may omit the optional completeness precheck."""
        process = subprocess.run(
            [
                sys.executable,
                str(ROOT / "src/skills/risk-identification/scripts/assess.py"),
                "-i",
                str(ROOT / "examples/prompt-risk-analysis/fetch-exec-syslog-mini.json"),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertIsNone(result["completeness_precheck"])
        self.assertEqual(result["skill"], "risk-identification")
        validate_output(ROOT / "src/skills/risk-identification/output-schema.json", result)


if __name__ == "__main__":
    unittest.main()
