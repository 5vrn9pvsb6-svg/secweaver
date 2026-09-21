"""Regression checks for layering and historical Skill CLI/import compatibility."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / "src/skills/_shared"
sys.path.insert(0, str(SHARED))
from skill_runtime import inputs  # noqa: E402
from skill_runtime.contracts import SkillContractError, ensure_skill_envelope  # noqa: E402
from skill_runtime.execution import assess_payload, load_skill_module  # noqa: E402
from skill_runtime import prepare  # noqa: E402
import skill_input  # noqa: E402


class SkillRuntimeTests(unittest.TestCase):
    def test_builders_stamp_versioned_skill_contract(self):
        payload = inputs.build_completeness_payload("bundle-incident-trace-default", {})
        self.assertEqual(payload["contract_version"], "1.0")
        self.assertEqual(payload["skill"], "data-source-completeness")

    def test_contract_rejects_version_skill_and_evidence_shape_conflicts(self):
        with self.assertRaisesRegex(SkillContractError, "contract_version"):
            ensure_skill_envelope({"contract_version": "2.0"}, "risk")
        with self.assertRaisesRegex(SkillContractError, "does not match"):
            ensure_skill_envelope({"skill": "alert-confirmation"}, "risk")
        with self.assertRaisesRegex(SkillContractError, "must contain JSON objects"):
            ensure_skill_envelope({"evidence_bundles": {"host_exec": ["bad"]}}, "risk")

    def test_evidence_fetch_preserves_partial_attempts_and_resets_context(self):
        def partial_fetch(*_args, **_kwargs):
            inputs.data_fetch._record_fetch_attempt({"asset_id": "synthetic", "connector_id": "es-test",
                                                     "status": "success", "partial": True,
                                                     "incomplete_reasons": ["timeout"]})
            return {}, {}

        with patch.object(inputs, "fetch_scenario_evidence", side_effect=partial_fetch):
            payload = inputs.build_evidence_fetch_payload({}, bundle_id="bundle-incident-trace-default")
        self.assertEqual(payload["data_access"]["fetch_attempts"][0]["incomplete_reasons"], ["timeout"])
        self.assertEqual(payload["fetch_summary"]["query_integrity"]["status"], "incomplete")
        self.assertIsNone(inputs.data_fetch.current_fetch_attempt_collection())
        with patch.object(inputs, "fetch_scenario_evidence", side_effect=RuntimeError("synthetic failure")):
            with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
                inputs.build_evidence_fetch_payload({}, bundle_id="bundle-incident-trace-default")
        self.assertIsNone(inputs.data_fetch.current_fetch_attempt_collection())

    def test_fetch_cache_retains_partial_metadata(self):
        from contextlib import ExitStack
        fetch = inputs.data_fetch
        asset = {"asset_id": "synthetic", "asset_type": "security_event", "status": "active"}
        connector = {"connector_id": "es-test", "connector_type": "es", "status": "active"}
        with ExitStack() as stack:
            for name, value in {"load_asset": asset, "get_connector_for_asset": connector,
                                "enrich_connector_params": {}, "load_templates": {},
                                "resolve_src_ip_web_access_template_id": "by-time", "render_template": {},
                                "credentials_ref_only": "vault://es/test", "resolve_credentials": {}}.items():
                stack.enter_context(patch.object(fetch, name, return_value=value))
            transport = stack.enter_context(patch.object(fetch, "fetch_connector", return_value=([], {"partial": True, "incomplete_reasons": ["failed_shards"]})))
            attempts, tokens = fetch.begin_fetch_attempt_collection()
            try:
                for _ in range(2):
                    fetch.fetch("synthetic", "by-time", {})
                self.assertEqual(transport.call_count, 1)
                self.assertEqual([a["status"] for a in attempts], ["success", "cache_hit"])
                self.assertTrue(all(a["partial"] and a["incomplete_reasons"] == ["failed_shards"] for a in attempts))
            finally:
                fetch.end_fetch_attempt_collection(tokens)

    def test_default_bundles_are_shipped(self):
        for bundle in set(inputs.DEFAULT_BUNDLE.values()):
            with self.subTest(bundle=bundle):
                self.assertTrue((ROOT / "dataasset/bundles" / f"{bundle}.json").is_file())

    def test_failed_module_load_restores_previous_registration(self):
        name = "secweaver_runtime_failure_test"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.py"
            path.write_text("raise RuntimeError('test failure')\n", encoding="utf-8")
            previous = types.ModuleType(name)
            try:
                with patch.dict(sys.modules, {name: previous}):
                    with self.assertRaisesRegex(RuntimeError, "test failure"):
                        load_skill_module(name, path)
                    self.assertIs(sys.modules[name], previous)
                with self.assertRaisesRegex(RuntimeError, "test failure"):
                    load_skill_module(name, path)
                self.assertNotIn(name, sys.modules)
            finally:
                if str(path.parent) in sys.path:
                    sys.path.remove(str(path.parent))

    def test_legacy_import_is_the_canonical_adapter_module(self):
        self.assertIs(skill_input, inputs)
        self.assertIs(skill_input.build_traceability_payload, inputs.build_traceability_payload)
        self.assertEqual(skill_input.fetch_scenario_evidence.__module__, "scenario_fetch")

    def test_lower_layer_cannot_import_skill_runtime_or_execute_skills(self):
        exceptions = {"skill_input.py", "prepare.py", "run_pipeline.py"}
        for path in (SHARED / "data-access").glob("*.py"):
            if path.name in exceptions:
                continue
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source)
                modules = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
                modules += [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
                self.assertFalse(any(name and (name.startswith("skill_runtime") or name == "skill_input") for name in modules))
                self.assertNotIn("spec_from_file_location", source)
                self.assertNotIn("traceability-analysis/scripts", source)

    def test_prepare_run_skill_assesses_all_four_modes(self):
        for skill in ("completeness", "traceability", "alert", "risk"):
            with self.subTest(skill=skill), patch.object(prepare, f"build_{skill}_payload", return_value={"params": {}}), \
                    patch.object(prepare, "assess_payload", return_value={"checked": skill}) as assess, \
                    patch.object(sys, "argv", ["prepare", "--bundle", "test", "--run-skill", skill]), \
                    patch("builtins.print") as output:
                self.assertEqual(prepare.main(), 0)
                assess.assert_called_once_with(skill, {"params": {}, "skill_result": {"checked": skill}})
                self.assertEqual(json.loads(output.call_args.args[0])["skill_result"], {"checked": skill})

    def test_prepare_default_is_metadata_only(self):
        with patch.object(prepare, "assess_payload") as assess, \
                patch.object(sys, "argv", ["prepare", "--bundle", "bundle-incident-trace-default"]), patch("builtins.print") as output:
            self.assertEqual(prepare.main(), 0)
            assess.assert_not_called()
            self.assertNotIn("skill_result", json.loads(output.call_args.args[0]))

    def test_canonical_assessment_matches_offline_cli(self):
        cases = {"completeness": "examples/data-source-completeness/s1-full-traceable.json",
                 "traceability": "examples/traceability/s1-web-shell-to-ssh-lateral.json",
                 "alert": "examples/alert-confirmation/s4-webshell-attack-success.json",
                 "risk": "examples/risk-identification/s5-curl-download-exec-p0.json"}
        for skill, relative in cases.items():
            with self.subTest(skill=skill):
                payload = json.loads((ROOT / relative).read_text(encoding="utf-8"))
                payload.setdefault("params", {})["resolve_attacker_ip_profile"] = False
                result = assess_payload(skill, payload)
                process = subprocess.run([sys.executable, str(ROOT / "src/secweaver.py"), "skill", skill,
                                          "-i", str(ROOT / relative)], capture_output=True, text=True, timeout=60, cwd=ROOT)
                self.assertEqual(process.returncode, 0, process.stderr)
                expected = json.loads(process.stdout)
                key = "alert_verdict" if skill == "alert" else "overall_verdict"
                self.assertEqual(result[key], expected[key])
                self.assertEqual(expected["contract_version"], "1.0")
                self.assertEqual(expected["skill"], result["skill"])

    def test_legacy_pipeline_and_prepare_commands_still_work(self):
        for script, args in (("run_pipeline.py", ["completeness"]),
                             ("prepare.py", ["--bundle", "bundle-incident-trace-default", "--run-skill", "completeness"])):
            with self.subTest(script=script):
                process = subprocess.run([sys.executable, str(SHARED / "data-access" / script), *args],
                                         capture_output=True, text=True, timeout=30, cwd=ROOT.parent)
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertIsInstance(json.loads(process.stdout), dict)


if __name__ == "__main__":
    unittest.main()
