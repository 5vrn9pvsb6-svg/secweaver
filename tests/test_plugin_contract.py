"""Contract parity at discovery, CLI validation and live plugin execution boundaries."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "src/skills/_shared/data-access"))

import secweaver  # noqa: E402
import plugin_executor_fetch as executor  # noqa: E402
from connector_registry import clear_connector_registry_cache, plugin_connector_specs  # noqa: E402
from dataasset.plugin_contract import (  # noqa: E402
    DEFAULT_TIMEOUT_SECONDS,
    EVENT_KEYS,
    PluginContractError,
    decode_response,
    normalize_manifest,
    resolve_entrypoint,
    resolve_python,
)


def plugin_manifest() -> dict:
    """A minimum documented version-1 plugin, with the optional timeout omitted."""
    return {"api_version": "1.0", "connector_type": "vendor_logs", "query_key": "vendor_query",
            "runtime": "plugin", "protocol": "stdio-json", "entrypoint": "fetch.py"}


class PluginContractTests(unittest.TestCase):
    def test_required_fields_are_not_synthesized(self):
        manifest = plugin_manifest()
        self.assertEqual(normalize_manifest(manifest)["timeout_sec"], DEFAULT_TIMEOUT_SECONDS)
        for key in manifest:
            with self.subTest(key=key), self.assertRaises(PluginContractError):
                normalize_manifest({field: value for field, value in manifest.items() if field != key})

    def test_cli_rejects_empty_and_non_object_manifests(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory)
            args = argparse.Namespace(target=directory, no_exec=True)
            for manifest in ({}, None, [], ["vendor_logs"], "vendor_logs"):
                with self.subTest(manifest=manifest):
                    (plugin / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
                    result = secweaver.validate_connector_plugins(args)
                    self.assertFalse(result["ok"])
                    self.assertGreater(result["summary"]["error_count"], 0)

    def test_timeout_rejects_lossy_values(self):
        for value in (True, False, 1.5, 0, -1, "1.5", None):
            with self.subTest(value=value), self.assertRaises(PluginContractError):
                normalize_manifest({**plugin_manifest(), "timeout_sec": value})
        self.assertEqual(normalize_manifest({**plugin_manifest(), "timeout_sec": "15"})["timeout_sec"], 15)

    def test_unreadable_utf8_manifest_is_reported_and_not_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "vendor_logs"
            plugin.mkdir()
            (plugin / "plugin.json").write_bytes(b"\xff")
            args = argparse.Namespace(target=str(plugin), no_exec=True)
            self.assertFalse(secweaver.validate_connector_plugins(args)["ok"])
            with patch("connector_registry.PLUGIN_ROOT", Path(directory)):
                clear_connector_registry_cache()
                try:
                    self.assertNotIn("vendor_logs", plugin_connector_specs())
                finally:
                    clear_connector_registry_cache()

    def test_event_aliases_and_optional_meta_remain_supported(self):
        for key in EVENT_KEYS:
            with self.subTest(key=key):
                self.assertEqual(decode_response(json.dumps({key: [{"message": "ok"}], "meta": None})),
                                 ([{"message": "ok"}], {}))
        self.assertEqual(decode_response('{"events": [], "data": [{"message": "ignored"}]}'), ([], {}))

    def test_invalid_response_does_not_fall_back_or_leak_stdout(self):
        for response in ({"events": ["secret-test-marker"], "data": [{}]},
                         {"events": [{}], "meta": "secret-test-marker"}, [], {}):
            with self.subTest(response=response), self.assertRaises(PluginContractError) as raised:
                decode_response(json.dumps(response))
            self.assertNotIn("secret-test-marker", str(raised.exception))
        with self.assertRaises(PluginContractError) as raised:
            decode_response("secret-test-marker")
        self.assertNotIn("secret-test-marker", str(raised.exception))

    def test_containment_resolves_symlinks_and_no_exec_checks_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin = root / "vendor_logs"
            plugin.mkdir()
            outside = root / "outside.py"
            outside.write_text("print('{}')\n", encoding="utf-8")
            manifest = {**plugin_manifest(), "entrypoint": "../outside.py"}
            (plugin / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(PluginContractError, "escapes"):
                resolve_entrypoint(plugin, manifest)
            result = subprocess.run([sys.executable, str(ROOT / "src/secweaver.py"), "connector", "plugin",
                                     "validate", str(plugin), "--no-exec", "--json"], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("escapes", result.stdout)
            (plugin / "fetch.py").symlink_to(outside)
            with self.assertRaisesRegex(PluginContractError, "escapes"):
                resolve_entrypoint(plugin, plugin_manifest())
            self.assertEqual(resolve_python(plugin, {"python": sys.executable}), str(Path(sys.executable).resolve()))

    def test_discovery_validates_raw_manifest_before_adding_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "vendor_logs"
            plugin.mkdir()
            manifest = plugin_manifest()
            del manifest["runtime"]
            (plugin / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            with patch("connector_registry.PLUGIN_ROOT", Path(directory)):
                clear_connector_registry_cache()
                try:
                    self.assertNotIn("vendor_logs", plugin_connector_specs())
                finally:
                    clear_connector_registry_cache()

    def test_cli_and_runtime_share_default_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory)
            (plugin / "fetch.py").write_text("print('{}')\n", encoding="utf-8")
            manifest = plugin_manifest()
            args = argparse.Namespace(sample_params="{}", sample_query=None, timeout_sec=None)
            output = subprocess.CompletedProcess([], 0, '{"events": []}', "")
            with patch("secweaver.subprocess.run", return_value=output) as run:
                self.assertEqual(secweaver.run_plugin_smoke(plugin, manifest, args), [])
                self.assertEqual(run.call_args.kwargs["timeout"], DEFAULT_TIMEOUT_SECONDS)
            with patch.object(executor, "_plugin_spec", return_value={**manifest, "plugin_dir": str(plugin)}), \
                    patch.object(executor.subprocess, "run", return_value=output) as run:
                self.assertEqual(executor.fetch({"connector_type": "vendor_logs"}, {}, "", {})[0], [])
                self.assertEqual(run.call_args.kwargs["timeout"], DEFAULT_TIMEOUT_SECONDS)
                executor.fetch({"connector_type": "vendor_logs", "constraints": {"request_timeout_sec": 9}}, {}, "", {})
                self.assertEqual(run.call_args.kwargs["timeout"], 9)

    def test_cli_and_runtime_reject_the_same_malformed_rows_and_meta(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory)
            (plugin / "fetch.py").write_text("print('{}')\n", encoding="utf-8")
            args = argparse.Namespace(sample_params="{}", sample_query=None, timeout_sec=None)
            for response, expected in (({"events": ["invalid"]}, "event array items must be JSON objects"),
                                       ({"events": [{}], "meta": []}, "meta must be a JSON object when provided")):
                output = subprocess.CompletedProcess([], 0, json.dumps(response), "")
                with self.subTest(response=response), patch("secweaver.subprocess.run", return_value=output):
                    issues = secweaver.run_plugin_smoke(plugin, plugin_manifest(), args)
                    self.assertEqual(issues[0]["message"], expected)
                    with patch.object(executor, "_plugin_spec", return_value={**plugin_manifest(), "plugin_dir": str(plugin)}):
                        with self.assertRaisesRegex(RuntimeError, expected):
                            executor.fetch({"connector_type": "vendor_logs"}, {}, "", {})

    def test_runtime_failure_omits_stdout_and_redacts_recursive_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory)
            (plugin / "fetch.py").write_text("print('{}')\n", encoding="utf-8")
            output = subprocess.CompletedProcess(
                [],
                7,
                "stdout-secret-marker",
                "request failed for access-secret-value with nested-token-value",
            )
            credentials = {
                "access_key_secret": "access-secret-value",
                "nested": {"token": "nested-token-value"},
            }
            with (
                patch.object(
                    executor,
                    "_plugin_spec",
                    return_value={**plugin_manifest(), "plugin_dir": str(plugin)},
                ),
                patch.object(executor.subprocess, "run", return_value=output),
                self.assertRaises(RuntimeError) as raised,
            ):
                executor.fetch({"connector_type": "vendor_logs"}, credentials, "", {})

            message = str(raised.exception)
            self.assertIn("request failed", message)
            self.assertIn("[REDACTED]", message)
            self.assertNotIn("stdout-secret-marker", message)
            self.assertNotIn("access-secret-value", message)
            self.assertNotIn("nested-token-value", message)

    def test_runtime_failure_omits_stderr_when_a_short_secret_cannot_be_safely_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory)
            (plugin / "fetch.py").write_text("print('{}')\n", encoding="utf-8")
            output = subprocess.CompletedProcess([], 9, "ignored", "diagnostic contains xy")
            with (
                patch.object(
                    executor,
                    "_plugin_spec",
                    return_value={**plugin_manifest(), "plugin_dir": str(plugin)},
                ),
                patch.object(executor.subprocess, "run", return_value=output),
                self.assertRaises(RuntimeError) as raised,
            ):
                executor.fetch({"connector_type": "vendor_logs"}, {"token": "xy"}, "", {})

            self.assertNotIn("diagnostic", str(raised.exception))
            self.assertNotIn("xy", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
