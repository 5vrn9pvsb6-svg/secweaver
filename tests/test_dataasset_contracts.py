"""Connector catalog migration, format, and multi-root drift contracts."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "src/skills/_shared/data-access"))

from dataasset.config_migration import FORMAT_VERSION, migrate_root  # noqa: E402
from dataasset.credential_contracts import validate_credentials_ref  # noqa: E402
from dataasset.validate_roots import (  # noqa: E402
    SHARED_CONTRACT_FILES,
    contract_drift,
    contract_policy_issues,
    discover_roots,
    shared_contract_paths,
)
from dataasset.sync_shared_contracts import sync_shared_contracts  # noqa: E402
from dataasset.validate_lib.connector_contracts import connector_manifest_errors  # noqa: E402
from connector_registry import _read_connector_catalog  # noqa: E402

try:
    from jsonschema import Draft202012Validator
except ImportError:  # The repository test runner installs this dependency.
    Draft202012Validator = None


class DataAssetContractTests(unittest.TestCase):
    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_top_level_schemas_reject_typos_and_allow_named_extensions(self) -> None:
        fixtures = {
            "data-asset.schema.json": {
                "asset_id": "asset-schema-test",
                "name": "Schema test",
                "asset_type": "host_exec",
                "domain": "D1",
                "status": "draft",
                "connector_id": "conn-schema-test",
                "schema": {"fields": [], "time_field": "timestamp", "retention_days": 1},
                "coverage": {},
            },
            "data-bundle.schema.json": {
                "bundle_id": "bundle-schema-test",
                "name": "Schema test",
                "asset_ids": ["asset-schema-test"],
                "status": "draft",
            },
            "data-host.schema.json": {
                "host_id": "host-schema-test",
                "name": "Schema test",
                "hostname": "schema-test",
                "host_type": "server",
                "status": "draft",
            },
            "data-network.schema.json": {
                "network_id": "net-schema-test",
                "name": "Schema test",
                "cidr": "192.0.2.0/24",
                "zone": "test",
                "status": "draft",
            },
        }
        for filename, document in fixtures.items():
            with self.subTest(schema=filename):
                schema = json.loads((ROOT / "dataasset/schema" / filename).read_text(encoding="utf-8"))
                validator = Draft202012Validator(schema)
                self.assertEqual(list(validator.iter_errors({**document, "extensions": {"vendor": True}})), [])
                self.assertTrue(list(validator.iter_errors({**document, "unexpected_filed": True})))

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_connector_schema_closes_builtin_fields_but_keeps_external_config_open(self) -> None:
        schema = json.loads((ROOT / "dataasset/schema/data-connector.schema.json").read_text())
        validator = Draft202012Validator(schema)
        base = {
            "connector_id": "conn-schema-test",
            "name": "Schema test",
            "status": "draft",
        }
        built_in = {
            **base,
            "connector_type": "sls",
            "config": {
                "endpoint": "cn-hangzhou.log.aliyuncs.com",
                "project": "demo",
                "logstore": "security",
                "porject": "typo",
            },
        }
        external = {
            **base,
            "connector_type": "vendor_logs",
            "config": {"vendor_specific_option": True},
        }
        self.assertTrue(list(validator.iter_errors(built_in)))
        self.assertEqual(list(validator.iter_errors(external)), [])

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_security_and_nested_inventory_schemas_reject_unsafe_or_misspelled_values(self) -> None:
        connector_schema = json.loads((ROOT / "dataasset/schema/data-connector.schema.json").read_text())
        connector = {
            "connector_id": "conn-es-test",
            "name": "ES test",
            "connector_type": "es",
            "status": "active",
            "credentials_ref": "vault://es/readonly",
            "config": {"url": "https://es.example.com", "index": "security-*", "tls_verify": False},
        }
        self.assertTrue(list(Draft202012Validator(connector_schema).iter_errors(connector)))

        host_schema = json.loads((ROOT / "dataasset/schema/data-host.schema.json").read_text())
        host = {
            "host_id": "host-schema-test",
            "name": "Schema test",
            "hostname": "schema-test",
            "host_type": "server",
            "status": "draft",
            "exposure": {"internet_expsed": True},
        }
        self.assertTrue(list(Draft202012Validator(host_schema).iter_errors(host)))

        status_schema = json.loads((ROOT / "dataasset/schema/credential-status.schema.json").read_text())
        self.assertTrue(
            list(
                Draft202012Validator(status_schema).iter_errors(
                    {"vault://es/readonly": "disabeld"}
                )
            )
        )

    def test_migration_previews_then_writes_inline_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configure = root / "configure"
            (root / "onboarding" / "sls").mkdir(parents=True)
            (root / "onboarding" / "external_generic").mkdir(parents=True)
            configure.mkdir()
            built_in = {
                "version": "1.0",
                "description": "legacy",
                "connectors": {"sls": {"query_key": "sls_query"}},
            }
            external = {
                "version": "1.0",
                "description": "legacy",
                "connectors": {"vendor_logs": {"query_key": "vendor_query"}},
            }
            profiles = {
                "version": "1.0",
                "profiles": {
                    "sls": {"label": "SLS"},
                    "external_generic": {"label": "External"},
                },
            }
            for name, value in (
                ("connector-catalog.json", built_in),
                ("external-connectors.json", external),
                ("onboarding-connector-profiles.json", profiles),
            ):
                (configure / name).write_text(json.dumps(value), encoding="utf-8")

            preview = migrate_root(root)
            self.assertTrue(preview["ok"])
            self.assertEqual(preview["written"], [])
            self.assertNotIn("format_version", json.loads((configure / "connector-catalog.json").read_text()))

            written = migrate_root(root, write=True)
            self.assertTrue(written["ok"])
            self.assertEqual(len(written["written"]), 2)
            migrated_builtin = json.loads((configure / "connector-catalog.json").read_text())
            migrated_external = json.loads((configure / "external-connectors.json").read_text())
            self.assertEqual(migrated_builtin["format_version"], FORMAT_VERSION)
            self.assertEqual(migrated_builtin["connectors"]["sls"]["onboarding_template"], "sls")
            self.assertEqual(
                migrated_external["connectors"]["vendor_logs"]["onboarding_template"],
                "external_generic",
            )
            self.assertTrue((configure / "onboarding-connector-profiles.json").is_file())

    def test_runtime_rejects_catalog_without_supported_format_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text('{"connectors": {}}', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "format_version=missing"):
                _read_connector_catalog(path)

    def test_shared_contract_drift_detects_missing_or_changed_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            public = base / "dataasset"
            overlay = base / "dataasset_overlay"
            for relative in SHARED_CONTRACT_FILES:
                for root in (public, overlay):
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(f"contract:{relative}\n", encoding="utf-8")

            self.assertEqual(contract_drift([public, overlay], public_root=public), [])
            changed = overlay / SHARED_CONTRACT_FILES[0]
            changed.write_text("changed\n", encoding="utf-8")
            drift = contract_drift([public, overlay], public_root=public)
            self.assertEqual(drift[0]["path"], SHARED_CONTRACT_FILES[0])
            self.assertEqual(drift[0]["reason"], "content differs")

    def test_repository_contract_policy_classifies_all_governed_files(self) -> None:
        roots = discover_roots(ROOT)
        self.assertEqual(contract_policy_issues(roots), [])
        shared = set(shared_contract_paths())
        self.assertIn("schema/data-asset.schema.json", shared)
        self.assertIn("onboarding/sls/asset.json", shared)
        self.assertNotIn("connectors/conn-sls-waf-prod.json", shared)

    def test_shared_contract_sync_previews_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            public = base / "dataasset"
            overlay = base / "dataasset_overlay"
            (public / "configure").mkdir(parents=True)
            (public / "schema").mkdir()
            (overlay / "schema").mkdir(parents=True)
            (public / "configure/shared-contracts.json").write_text(
                json.dumps({"shared": ["schema/example.json"]}),
                encoding="utf-8",
            )
            (public / "schema/example.json").write_text('{"version": 2}\n', encoding="utf-8")
            target = overlay / "schema/example.json"
            target.write_text('{"version": 1}\n', encoding="utf-8")

            preview = sync_shared_contracts([public, overlay], public_root=public)
            self.assertFalse(preview["ok"])
            self.assertEqual(preview["summary"]["change_count"], 1)
            self.assertEqual(target.read_text(encoding="utf-8"), '{"version": 1}\n')

            applied = sync_shared_contracts([public, overlay], public_root=public, write=True)
            self.assertTrue(applied["ok"])
            self.assertEqual(target.read_text(encoding="utf-8"), '{"version": 2}\n')

    def test_credential_reference_rejects_path_traversal(self) -> None:
        self.assertEqual(
            validate_credentials_ref("vault://ssh//readonly"),
            "vault://ssh/readonly",
        )
        for ref in ("vault://ssh/../readonly", "vault://ssh/./readonly"):
            with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "invalid credentials_ref"):
                validate_credentials_ref(ref)

    def test_onboarding_profile_must_expose_schema_required_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "configure").mkdir()
            (root / "schema").mkdir()
            template_dir = root / "onboarding" / "demo"
            template_dir.mkdir(parents=True)
            for name in ("connector.json", "asset.json", "template.snippet.json"):
                (template_dir / name).write_text("{}\n", encoding="utf-8")
            (root / "schema/data-connector.schema.json").write_text(
                json.dumps(
                    {
                        "allOf": [
                            {
                                "if": {"properties": {"connector_type": {"const": "demo"}}},
                                "then": {"properties": {"config": {"required": ["base_url", "index"]}}},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (root / "configure/connector-catalog.json").write_text(
                json.dumps(
                    {
                        "connectors": {
                            "demo": {
                                "onboarding_template": "demo",
                                "onboarding_profile": {
                                    "fields": ["base_url"],
                                    "required": ["base_url"],
                                    "defaults": {},
                                    "template_params": [],
                                    "template_defaults": {},
                                },
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            errors = connector_manifest_errors(root)

        self.assertTrue(any("fields" in error and "index" in error for error in errors))
        self.assertTrue(any("required" in error and "index" in error for error in errors))

    def test_public_onboarding_fields_are_accepted_by_connector_schema(self) -> None:
        """Every visible field must survive CLI/UI promotion into config."""
        self.assertEqual(connector_manifest_errors(ROOT / "dataasset"), [])


if __name__ == "__main__":
    unittest.main()
