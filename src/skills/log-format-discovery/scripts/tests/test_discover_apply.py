"""Tests for discover_apply."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from discover_apply import apply_discovery_mapping, merge_aliases_into_spec  # noqa: E402
import discover as discovery  # noqa: E402


class TestDiscoverApply(unittest.TestCase):
    def test_existing_template_candidates_are_not_apply_payload(self) -> None:
        """A discovery candidate list must never cross the single-template apply boundary."""
        context = {
            "discovery_asset": {
                "asset_id": "asset-test-apply",
                "asset_type": "waf_alert",
                "connector_type": "http_api",
                "fields": ["src_ip", "timestamp", "url", "action"],
                "query_template_ids": ["waf-existing"],
            },
            "matching_templates": [{"template_id": "waf-existing"}],
        }
        spec = {
            "field_aliases": {},
            "by_asset_type": {
                "waf_alert": {"required": ["timestamp", "src_ip", "url", "action"]}
            },
        }
        with patch.object(discovery, "load_dataasset_context", return_value=context), \
                patch.object(discovery, "load_evidence_spec", return_value=spec):
            report = discovery.discover(
                asset_id="asset-test-apply",
                lines=['{"src_ip":"203.0.113.10","timestamp":"2026-01-01T00:00:00Z","url":"/","action":"blocked"}'],
            )
        self.assertIsNone(report["proposed_query_template"])
        self.assertEqual(
            report["proposed_template_hint"]["existing_templates_in_dataasset"],
            [{"template_id": "waf-existing"}],
        )
        from jsonschema import Draft202012Validator

        output_schema = json.loads((SCRIPTS.parent / "output-schema.json").read_text())
        Draft202012Validator(output_schema).validate(report)

    @staticmethod
    def _write_asset(root: Path, *, status: str = "discovery") -> Path:
        """Create the smallest valid discovery fixture used by apply tests."""
        path = root / "assets" / "asset-test-apply.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "asset_id": "asset-test-apply",
            "name": "test",
            "asset_type": "waf_alert",
            "domain": "D1",
            "status": status,
            "connector_id": "conn-x",
            "schema": {
                "fields": ["src_ip"],
                "time_field": "timestamp",
                "retention_days": 30,
            },
            "coverage": {"zones": [], "apps": [], "hosts": []},
        }), encoding="utf-8")
        return path

    def test_cli_rejects_active_asset_without_traceback_or_output(self) -> None:
        """Invalid discovery scope must fail before generating or applying files."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "assets").mkdir()
            asset = {"asset_id": "asset-active", "asset_type": "host_process", "status": "active"}
            asset_path = root / "assets" / "asset-active.json"
            asset_path.write_text(json.dumps(asset), encoding="utf-8")
            original = asset_path.read_bytes()
            output = root / "report.json"
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "discover.py"), "--asset-id", "asset-active",
                 "--text", '{"pid":1}', "-o", str(output)],
                env={**os.environ, "DATAASSET_ROOT": str(root)},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("discovery", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse(output.exists())
            self.assertEqual(asset_path.read_bytes(), original)

    def test_merge_aliases_skips_conflict(self) -> None:
        spec = {"field_aliases": {"ip": "src_ip"}}
        added, skipped = merge_aliases_into_spec(spec, {"ip": "dst_ip"}, force=False)
        self.assertEqual(skipped["ip"], "src_ip")
        self.assertNotIn("ip", added)

    def test_apply_per_asset_aliases_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataasset = root / "dataasset"
            path = self._write_asset(dataasset)

            import discover_apply as da

            old_dataasset = da.DATAASSET
            da.DATAASSET = dataasset
            try:
                with patch.object(da, "registry_write_lock", wraps=da.registry_write_lock) as lock:
                    result = apply_discovery_mapping(
                        {
                            "asset_id": "asset-test-apply",
                            "proposed_field_aliases": {"vendor_ip": "src_ip"},
                            "proposed_asset_schema": {
                                "fields": ["src_ip", "timestamp", "url"],
                                "query_template_ids": ["waf_by_src_ip_time"],
                            },
                            "detected_format": "json_lines",
                        },
                        dry_run=True,
                        promote_draft=True,
                    )
                    lock.assert_called_once_with(dataasset)
            finally:
                da.DATAASSET = old_dataasset

            self.assertEqual(result["status_promoted"], "discovery → draft")
            self.assertIn("vendor_ip", result["asset_field_aliases"])
            # dry run: file on disk unchanged
            on_disk = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(on_disk["status"], "discovery")

    def test_apply_rejects_cross_asset_mapping_without_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self._write_asset(root)
            original = path.read_bytes()
            import discover_apply as da

            old_dataasset = da.DATAASSET
            da.DATAASSET = root
            try:
                with self.assertRaisesRegex(ValueError, "does not match target asset"):
                    apply_discovery_mapping(
                        {"asset_id": "asset-other", "proposed_asset_schema": {}},
                        asset_id="asset-test-apply",
                    )
            finally:
                da.DATAASSET = old_dataasset
            self.assertEqual(path.read_bytes(), original)

    def test_apply_rejects_active_asset_without_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self._write_asset(root, status="active")
            original = path.read_bytes()
            import discover_apply as da

            old_dataasset = da.DATAASSET
            da.DATAASSET = root
            try:
                with self.assertRaisesRegex(ValueError, "only accepts status=discovery"):
                    apply_discovery_mapping({"asset_id": "asset-test-apply"})
            finally:
                da.DATAASSET = old_dataasset
            self.assertEqual(path.read_bytes(), original)

    def test_schema_failure_happens_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self._write_asset(root)
            schema_path = root / "schema" / "data-asset.schema.json"
            schema_path.parent.mkdir(parents=True)
            schema_path.write_text(json.dumps({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "schema": {
                        "type": "object",
                        "properties": {"retention_days": {"type": "integer"}},
                    }
                },
            }), encoding="utf-8")
            original = path.read_bytes()
            import discover_apply as da

            old_dataasset = da.DATAASSET
            da.DATAASSET = root
            try:
                with self.assertRaisesRegex(ValueError, "schema validation failed"):
                    apply_discovery_mapping({
                        "asset_id": "asset-test-apply",
                        "proposed_asset_schema": {"retention_days": "invalid"},
                    })
            finally:
                da.DATAASSET = old_dataasset
            self.assertEqual(path.read_bytes(), original)

    def test_relative_schema_reference_is_resolved_locally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self._write_asset(root)
            schema_dir = root / "schema"
            schema_dir.mkdir(parents=True)
            (schema_dir / "child.schema.json").write_text(json.dumps({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://example.invalid/schemas/child.json",
                "type": "object",
                "required": ["fields"],
                "properties": {"fields": {"type": "array"}},
            }), encoding="utf-8")
            (schema_dir / "data-asset.schema.json").write_text(json.dumps({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://example.invalid/schemas/data-asset.json",
                "type": "object",
                "properties": {"schema": {"$ref": "child.schema.json"}},
            }), encoding="utf-8")
            import discover_apply as da

            old_dataasset = da.DATAASSET
            da.DATAASSET = root
            try:
                result = apply_discovery_mapping(
                    {"asset_id": "asset-test-apply"},
                    dry_run=True,
                )
            finally:
                da.DATAASSET = old_dataasset
            self.assertEqual(result["asset_preview"]["status"], "draft")
            self.assertEqual(json.loads(path.read_text())["status"], "discovery")

    def test_multi_file_write_error_rolls_back_prior_replacements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset_path = self._write_asset(root)
            templates_path = root / "query-templates" / "templates.json"
            templates_path.parent.mkdir(parents=True)
            templates_path.write_text(json.dumps({"version": "1", "templates": {}}), encoding="utf-8")
            original_asset = json.loads(asset_path.read_text())
            original_templates = json.loads(templates_path.read_text())
            import discover_apply as da

            old_dataasset = da.DATAASSET
            da.DATAASSET = root
            original_write = da.write_json_atomic
            calls = 0

            def fail_second_write(path: Path, payload: dict) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("synthetic write failure")
                original_write(path, payload)

            try:
                with patch.object(da, "write_json_atomic", side_effect=fail_second_write):
                    with self.assertRaisesRegex(OSError, "synthetic write failure"):
                        apply_discovery_mapping({
                            "asset_id": "asset-test-apply",
                            "proposed_query_template": {
                                "template_id": "test-template",
                                "asset_types": ["waf_alert"],
                            },
                        })
            finally:
                da.DATAASSET = old_dataasset
            self.assertEqual(json.loads(asset_path.read_text()), original_asset)
            self.assertEqual(json.loads(templates_path.read_text()), original_templates)


if __name__ == "__main__":
    unittest.main()
