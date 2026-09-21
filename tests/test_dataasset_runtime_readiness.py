"""Static bundle runtime-readiness contract tests."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dataasset.validate_lib.runtime_readiness import assess_runtime_readiness  # noqa: E402
from dataasset.validate_lib.diagnostics import Issue  # noqa: E402
from dataasset.validate import Report, annotate_object_issues, check_connector  # noqa: E402


class RuntimeReadinessTests(unittest.TestCase):
    def test_active_local_file_graph_is_ready_without_a_credential(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = assess_runtime_readiness(
                root,
                {
                    "bundle-ready": (
                        root / "bundles/bundle-ready.json",
                        {"bundle_id": "bundle-ready", "status": "active", "asset_ids": ["asset-ready"]},
                    )
                },
                {
                    "asset-ready": (
                        root / "assets/asset-ready.json",
                        {"asset_id": "asset-ready", "status": "active", "connector_id": "conn-ready"},
                    )
                },
                {
                    "conn-ready": (
                        root / "connectors/conn-ready.json",
                        {
                            "connector_id": "conn-ready",
                            "connector_type": "local_file",
                            "status": "active",
                            "config": {"base_path": "/var/log"},
                        },
                    )
                },
                {},
            )

        self.assertEqual(result["ready_bundle_ids"], ["bundle-ready"])
        self.assertEqual(result["summary"]["not_ready_bundle_count"], 0)
        self.assertFalse(result["live_connectivity_checked"])

    def test_draft_placeholder_connector_and_missing_ciphertext_are_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = assess_runtime_readiness(
                root,
                {
                    "bundle-blocked": (
                        root / "bundles/bundle-blocked.json",
                        {"bundle_id": "bundle-blocked", "status": "active", "asset_ids": ["asset-blocked"]},
                    )
                },
                {
                    "asset-blocked": (
                        root / "assets/asset-blocked.json",
                        {"asset_id": "asset-blocked", "status": "active", "connector_id": "conn-blocked"},
                    )
                },
                {
                    "conn-blocked": (
                        root / "connectors/conn-blocked.json",
                        {
                            "connector_id": "conn-blocked",
                            "connector_type": "sls",
                            "status": "draft",
                            "credentials_ref": "vault://sls/readonly",
                            "config": {"project": "YOUR_SLS_PROJECT", "logstore": "security"},
                        },
                    )
                },
                {},
                bundle_ids=["bundle-blocked"],
            )

        codes = {item["code"] for item in result["bundles"][0]["blockers"]}
        self.assertEqual(
            codes,
            {"runtime-connector-inactive", "runtime-connector-placeholder", "runtime-credential-missing"},
        )
        self.assertEqual(result["not_ready_bundle_ids"], ["bundle-blocked"])

    def test_invalid_credential_reference_is_a_blocker_instead_of_an_exception(self) -> None:
        """Readiness must remain structured even when called without base validation."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = assess_runtime_readiness(
                root,
                {
                    "bundle-invalid-ref": (
                        root / "bundles/bundle-invalid-ref.json",
                        {"bundle_id": "bundle-invalid-ref", "status": "active", "asset_ids": ["asset-invalid-ref"]},
                    )
                },
                {
                    "asset-invalid-ref": (
                        root / "assets/asset-invalid-ref.json",
                        {"asset_id": "asset-invalid-ref", "status": "active", "connector_id": "conn-invalid-ref"},
                    )
                },
                {
                    "conn-invalid-ref": (
                        root / "connectors/conn-invalid-ref.json",
                        {
                            "connector_id": "conn-invalid-ref",
                            "connector_type": "es",
                            "status": "active",
                            "credentials_ref": "vault://es/../readonly",
                            "config": {"url": "https://es.example.com", "index": "security-*"},
                        },
                    )
                },
                {},
            )

        blockers = result["bundles"][0]["blockers"]
        self.assertIn("runtime-credential-ref", {item["code"] for item in blockers})
        self.assertEqual(result["not_ready_bundle_ids"], ["bundle-invalid-ref"])

    def test_active_external_executor_remote_http_is_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configure = root / "configure"
            configure.mkdir()
            (configure / "external-connectors.json").write_text(
                '{"connectors":{"vendor_logs":{"runtime":"local_or_external_executor"}}}',
                encoding="utf-8",
            )
            result = assess_runtime_readiness(
                root,
                {
                    "bundle-http": (
                        root / "bundles/bundle-http.json",
                        {"bundle_id": "bundle-http", "status": "active", "asset_ids": ["asset-http"]},
                    )
                },
                {
                    "asset-http": (
                        root / "assets/asset-http.json",
                        {"asset_id": "asset-http", "status": "active", "connector_id": "conn-http"},
                    )
                },
                {
                    "conn-http": (
                        root / "connectors/conn-http.json",
                        {
                            "connector_id": "conn-http",
                            "connector_type": "vendor_logs",
                            "status": "active",
                            "credentials_ref": "vault://vendor/readonly",
                            "config": {"endpoint": "http://vendor.example.com/fetch"},
                        },
                    )
                },
                {},
            )

        codes = {item["code"] for item in result["bundles"][0]["blockers"]}
        self.assertIn("runtime-connector-transport", codes)
        self.assertFalse(result["ready_for_execution"])

    def test_agent_stream_cycle_is_bounded_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = root / "credentials/secrets/agent/read.enc.yaml"
            secret.parent.mkdir(parents=True)
            secret.write_text("encrypted", encoding="utf-8")
            bundles = {
                "bundle-cycle": (
                    root / "bundles/bundle-cycle.json",
                    {"bundle_id": "bundle-cycle", "status": "active", "asset_ids": ["asset-cycle"]},
                )
            }
            assets = {
                "asset-cycle": (
                    root / "assets/asset-cycle.json",
                    {"asset_id": "asset-cycle", "status": "active", "connector_id": "conn-a"},
                )
            }
            connectors = {
                connector_id: (
                    root / f"connectors/{connector_id}.json",
                    {
                        "connector_id": connector_id,
                        "connector_type": "agent_stream",
                        "status": "active",
                        "credentials_ref": "vault://agent/read",
                        "config": {"sink_connector_id": sink_id},
                    },
                )
                for connector_id, sink_id in (("conn-a", "conn-b"), ("conn-b", "conn-a"))
            }

            result = assess_runtime_readiness(root, bundles, assets, connectors, {})

        codes = {item["code"] for item in result["bundles"][0]["blockers"]}
        self.assertIn("runtime-connector-cycle", codes)

    def test_related_base_validation_error_blocks_bundle_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schema_dir = root / "schema"
            schema_dir.mkdir()
            (schema_dir / "data-connector.schema.json").write_bytes(
                (ROOT / "dataasset/schema/data-connector.schema.json").read_bytes()
            )
            connector_path = root / "connectors/conn-invalid.json"
            connector = {
                "connector_id": "conn-invalid",
                "name": "Invalid local file",
                "connector_type": "local_file",
                "status": "active",
                "config": {},
            }
            report = Report()
            start = len(report.issues)
            check_connector(report, connector_path, connector, root=root)
            annotate_object_issues(
                report,
                start,
                object_type="connector",
                object_id="conn-invalid",
                path=connector_path,
            )
            result = assess_runtime_readiness(
                root,
                {
                    "bundle-invalid": (
                        root / "bundles/bundle-invalid.json",
                        {"bundle_id": "bundle-invalid", "status": "active", "asset_ids": ["asset-invalid"]},
                    )
                },
                {
                    "asset-invalid": (
                        root / "assets/asset-invalid.json",
                        {"asset_id": "asset-invalid", "status": "active", "connector_id": "conn-invalid"},
                    )
                },
                {
                    "conn-invalid": (
                        connector_path,
                        connector,
                    )
                },
                {},
                validation_issues=report.issues,
            )

        self.assertEqual(result["not_ready_bundle_ids"], ["bundle-invalid"])
        self.assertFalse(result["registry_valid"])
        self.assertFalse(result["ready_for_execution"])
        self.assertIn("runtime-object-validation", {item["code"] for item in result["bundles"][0]["blockers"]})

    def test_global_registry_error_is_reported_separately_from_bundle_graph(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = assess_runtime_readiness(
                root,
                {
                    "bundle-ready": (
                        root / "bundles/bundle-ready.json",
                        {"bundle_id": "bundle-ready", "status": "active", "asset_ids": ["asset-ready"]},
                    )
                },
                {
                    "asset-ready": (
                        root / "assets/asset-ready.json",
                        {"asset_id": "asset-ready", "status": "active", "connector_id": "conn-ready"},
                    )
                },
                {
                    "conn-ready": (
                        root / "connectors/conn-ready.json",
                        {"connector_id": "conn-ready", "connector_type": "local_file", "status": "active", "config": {"base_path": "/var/log"}},
                    )
                },
                {},
                validation_issues=[Issue(severity="error", message="global registry contract failed")],
            )

        self.assertEqual(result["ready_bundle_ids"], ["bundle-ready"])
        self.assertFalse(result["registry_valid"])
        self.assertFalse(result["ready_for_execution"])


if __name__ == "__main__":
    unittest.main()
