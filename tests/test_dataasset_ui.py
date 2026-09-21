"""Regression tests for the local DataAsset UI server helpers."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER = REPO_ROOT / "dataasset-ui" / "server.py"


def load_server_module():
    spec = importlib.util.spec_from_file_location("dataasset_ui_server", SERVER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SERVER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestDataAssetUIOnboarding(unittest.TestCase):
    def setUp(self) -> None:
        self.server = load_server_module()

    def test_onboarding_meta_exposes_schema_sample_and_types(self) -> None:
        meta = self.server.load_onboarding_meta()
        self.assertIn("sls", meta["connector_types"])
        self.assertIn("sls_proxy", meta["connector_types"])
        self.assertIn("aws_cloudwatch", meta["connector_types"])
        self.assertIn("splunk", meta["connector_types"])
        self.assertIn("mongodb", meta["connector_types"])
        self.assertIn("redis", meta["connector_types"])
        self.assertIn("datadog_logs", meta["connector_types"])
        self.assertIn("okta_system_log", meta["connector_types"])
        self.assertIn("cloudflare_logs", meta["connector_types"])
        self.assertIn("crowdstrike_fdr", meta["connector_types"])
        self.assertIn("microsoft_entra_signin", meta["connector_types"])
        self.assertIn("google_workspace_audit", meta["connector_types"])
        self.assertIn("microsoft_defender_xdr", meta["connector_types"])
        self.assertIn("sentinelone_events", meta["connector_types"])
        self.assertIn("demo_plugin_logs", meta["connector_types"])
        self.assertIn("sls", meta["onboarding_connector_types"])
        self.assertIn("sls_proxy", meta["onboarding_connector_types"])
        self.assertIn("ssh_file", meta["onboarding_connector_types"])
        self.assertIn("mongodb", meta["onboarding_connector_types"])
        self.assertIn("redis", meta["onboarding_connector_types"])
        self.assertIn("datadog_logs", meta["onboarding_connector_types"])
        self.assertEqual(meta["connector_runtime_capabilities"]["sls"], "live_fetch")
        self.assertEqual(meta["connector_runtime_capabilities"]["sls_proxy"], "live_fetch")
        self.assertEqual(meta["connector_runtime_capabilities"]["aws_cloudwatch"], "live_or_external_executor")
        self.assertEqual(meta["connector_runtime_capabilities"]["agent_stream"], "local_or_external_executor")
        self.assertEqual(meta["connector_runtime_capabilities"]["object_storage"], "local_or_external_executor")
        self.assertEqual(meta["connector_runtime_capabilities"]["datadog_logs"], "local_or_external_executor")
        self.assertEqual(meta["connector_runtime_capabilities"]["microsoft_defender_xdr"], "local_or_external_executor")
        self.assertEqual(meta["connector_runtime_capabilities"]["sentinelone_events"], "local_or_external_executor")
        self.assertEqual(meta["connector_runtime_capabilities"]["demo_plugin_logs"], "plugin")
        self.assertEqual(meta["connector_query_keys"]["aws_cloudwatch"], "cloudwatch_query")
        self.assertEqual(meta["connector_query_keys"]["mongodb"], "mongo_query")
        self.assertEqual(meta["connector_query_keys"]["redis"], "redis_query")
        self.assertEqual(meta["connector_query_keys"]["datadog_logs"], "datadog_query")
        self.assertEqual(meta["connector_query_keys"]["okta_system_log"], "okta_query")
        self.assertEqual(meta["connector_query_keys"]["microsoft_entra_signin"], "entra_query")
        self.assertEqual(meta["connector_query_keys"]["google_workspace_audit"], "google_workspace_query")
        self.assertEqual(meta["connector_query_keys"]["microsoft_defender_xdr"], "defender_query")
        self.assertEqual(meta["connector_query_keys"]["sentinelone_events"], "sentinelone_query")
        self.assertEqual(meta["connector_query_keys"]["demo_plugin_logs"], "demo_plugin_query")
        catalog = {record["connector_type"]: record for record in meta["connector_catalog"]}
        self.assertEqual(catalog["sls_proxy"]["source"], "built_in")
        self.assertTrue(catalog["sls_proxy"]["onboarding_template"])
        self.assertEqual(catalog["aws_cloudwatch"]["source"], "built_in")
        self.assertIn("boto3", catalog["aws_cloudwatch"]["dependency_hint"])
        self.assertEqual(catalog["datadog_logs"]["source"], "external_config")
        self.assertEqual(catalog["demo_plugin_logs"]["source"], "plugin")
        self.assertEqual(meta["connector_profiles"]["mongodb"]["fields"], ["host", "port", "database", "collection", "auth_source"])
        self.assertEqual(
            meta["connector_profiles"]["sls_proxy"]["fields"],
            ["project", "logstore", "endpoint", "fallback_endpoint", "host_id"],
        )
        self.assertEqual(meta["connector_profiles"]["demo_plugin_logs"]["fields"], [])
        self.assertIn("default_query", meta["connector_profiles"]["okta_system_log"])
        self.assertIn("default_query", meta["connector_profiles"]["microsoft_defender_xdr"])
        self.assertTrue(any(item["file"].endswith("vendor-quickstart-cloud-vendors.json") for item in meta["onboarding_examples"]))
        self.assertTrue(any(item["file"].endswith("vendor-quickstart-cloud-audit-siem.json") for item in meta["onboarding_examples"]))
        self.assertTrue(any(item["file"].endswith("vendor-quickstart-edr-identity-vendors.json") for item in meta["onboarding_examples"]))
        self.assertTrue(any(item["file"].endswith("vendor-quickstart-document-cache.json") for item in meta["onboarding_examples"]))
        self.assertTrue(any(item["file"].endswith("vendor-quickstart-plugin-connector.json") for item in meta["onboarding_examples"]))
        self.assertTrue(any(item["file"].endswith("secweaver-saas-sls-proxy-assets.json") for item in meta["onboarding_examples"]))
        self.assertIn("waf_alert", meta["asset_types"])
        self.assertIn("json_lines", meta["text_parsers"])
        self.assertEqual(meta["agent_install"]["version"], "0.3.0")
        self.assertTrue(meta["agent_install"]["bootstrap_url"].startswith("https://"))
        self.assertIn("enrollment_id", meta["agent_install"])
        self.assertIn("aliyun_uid", meta["agent_install"])
        self.assertNotIn("release_base_url", meta["agent_install"])
        self.assertTrue(any(item["id"].startswith("vault://") for item in meta["credentials"]))
        self.assertGreaterEqual(len(meta["sample"].get("data_sources", [])), 1)

    def test_onboarding_preview_uses_asset_apply_without_writing(self) -> None:
        config = self.server.read_json(REPO_ROOT / "dataasset" / "onboarding" / "examples" / "data-sources.sample.json")
        result = self.server.run_onboarding_apply(config, dry_run=True)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["mode"], "dry-run")
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(len(result["data"]["sources"]), 3)
        self.assertEqual(result["data"]["sources"][0]["asset"]["data"]["coverage"]["apps"], ["demo-gateway"])

    def test_sls_proxy_onboarding_preserves_project_and_default_compatibility(self) -> None:
        for project in ("wis-log", ""):
            with self.subTest(project=project):
                result = self.server.run_onboarding_apply({"version": "1.0", "data_sources": [{"name": "Project query", "connector_type": "sls_proxy", "asset_type": "waf_alert", "project": project, "logstore": "gateway_plugin_log", "endpoint": "https://proxy.example:30443"}]}, dry_run=True)
                self.assertTrue(result["ok"], result)
                config = result["data"]["sources"][0]["connector"]["data"]["config"]
                self.assertEqual(config["project"], project)
                self.assertEqual(config["logstore"], "gateway_plugin_log")

    def test_onboarding_apply_failure_returns_config_diagnosis(self) -> None:
        result = self.server.run_onboarding_apply(
            {
                "version": "1.0",
                "data_sources": [
                    {
                        "name": "Broken source",
                        "asset_type": "waf_alert",
                    }
                ],
            },
            dry_run=True,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["advice"][0]["category"], "onboarding-required-field")
        self.assertIn("connector_type", result["error"])

    def test_refresh_connector_metadata_clears_caches(self) -> None:
        with patch.object(self.server, "clear_connector_registry_cache") as clear_registry, patch.object(
            self.server,
            "clear_connector_catalog_cache",
        ) as clear_catalog:
            self.server.refresh_connector_metadata()

        clear_registry.assert_called_once_with()
        clear_catalog.assert_called_once_with()

    def test_validation_ui_forwards_runtime_readiness_scope(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({"ok": True, "issues": [], "runtime_readiness": {"bundles": []}}),
            stderr="",
        )
        with patch("dataasset_ui_services.validation.validation_python", return_value="python-test"), patch(
            "dataasset_ui_services.validation.subprocess.run",
            return_value=completed,
        ) as run:
            result = self.server.run_validation(
                runtime_ready=True,
                bundle_ids=["bundle-incident-trace-default"],
            )

        self.assertTrue(result["ok"])
        command = run.call_args.args[0]
        self.assertIn("--runtime-ready", command)
        self.assertEqual(command[-2:], ["--bundle", "bundle-incident-trace-default"])

    def test_edit_rejects_object_id_changes(self) -> None:
        with self.assertRaisesRegex(ValueError, "asset_id .*\u7f16\u8f91"):
            self.server.save_object(
                "asset",
                {"asset_id": "asset-renamed"},
                original_id="asset-original",
            )

    def test_object_save_validates_schema_before_replacing_old_file(self) -> None:
        from dataasset_ui_services import objects

        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "schema").mkdir()
            (root / "networks").mkdir()
            shutil.copy2(REPO_ROOT / "dataasset/schema/data-network.schema.json", root / "schema")
            path = root / "networks/net-test.json"
            path.write_text('{"old": true}\n', encoding="utf-8")
            with patch.object(objects, "DATAASSET_DIR", root), patch.dict(
                objects.CRUD_OBJECTS, {"network": {**objects.CRUD_OBJECTS["network"], "directory": root / "networks"}},
            ):
                with self.assertRaisesRegex(ValueError, "network schema .*cidr"):
                    objects.save_object("network", {"network_id": "net-test", "name": "Test", "zone": "lab", "status": "draft"})
                self.assertEqual(path.read_text(encoding="utf-8"), '{"old": true}\n')
                objects.save_object("network", {"network_id": "net-test", "name": "Test", "cidr": "192.0.2.0/24", "zone": "lab", "status": "draft"})
                self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["cidr"], "192.0.2.0/24")

    def test_active_bundle_requires_existing_active_asset_before_save(self) -> None:
        from dataasset_ui_services import objects

        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "schema").mkdir()
            shutil.copy2(REPO_ROOT / "dataasset/schema/data-bundle.schema.json", root / "schema")
            bundle = {"bundle_id": "bundle-test", "name": "Test", "asset_ids": ["asset-missing"], "status": "active"}
            with patch.object(objects, "DATAASSET_DIR", root), patch.dict(
                objects.CRUD_OBJECTS, {"bundle": {**objects.CRUD_OBJECTS["bundle"], "directory": root / "bundles"}},
            ):
                with self.assertRaisesRegex(ValueError, "asset-missing.*不存在"):
                    objects.save_object("bundle", bundle)
                self.assertFalse((root / "bundles/bundle-test.json").exists())
                bundle["status"] = "draft"
                objects.save_object("bundle", bundle)
                self.assertTrue((root / "bundles/bundle-test.json").is_file())

    def test_asset_demotion_cannot_break_active_bundle(self) -> None:
        from dataasset_ui_services import objects

        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "schema").mkdir()
            (root / "bundles").mkdir()
            shutil.copy2(REPO_ROOT / "dataasset/schema/data-asset.schema.json", root / "schema")
            (root / "bundles/bundle-test.json").write_text(json.dumps({
                "bundle_id": "bundle-test", "name": "Test", "status": "active", "asset_ids": ["asset-test"],
            }), encoding="utf-8")
            asset = json.loads((REPO_ROOT / "dataasset/onboarding/sls/asset.json").read_text(encoding="utf-8"))
            asset.update(asset_id="asset-test", connector_id="conn-test", status="draft")
            with patch.object(objects, "DATAASSET_DIR", root), patch.dict(
                objects.CRUD_OBJECTS, {"asset": {**objects.CRUD_OBJECTS["asset"], "directory": root / "assets"}},
            ):
                with self.assertRaisesRegex(ValueError, "active 资产包引用了非 active 资产"):
                    objects.save_object("asset", asset)
                self.assertFalse((root / "assets/asset-test.json").exists())

    def test_connector_demotion_cannot_break_active_asset(self) -> None:
        from dataasset_ui_services import objects

        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "schema").mkdir()
            (root / "assets").mkdir()
            shutil.copy2(REPO_ROOT / "dataasset/schema/data-connector.schema.json", root / "schema")
            (root / "assets/asset-test.json").write_text(json.dumps({
                "asset_id": "asset-test", "status": "active", "connector_id": "conn-test",
            }), encoding="utf-8")
            connector = {"connector_id": "conn-test", "name": "Test", "connector_type": "sls",
                         "config": {"project": "test", "logstore": "test", "endpoint": "cn-hangzhou.log.aliyuncs.com"},
                         "status": "draft"}
            with patch.object(objects, "DATAASSET_DIR", root), patch.dict(
                objects.CRUD_OBJECTS, {"connector": {**objects.CRUD_OBJECTS["connector"], "directory": root / "connectors"}},
            ):
                with self.assertRaisesRegex(ValueError, "active 资产引用了非 active Connector"):
                    objects.save_object("connector", connector)
                self.assertFalse((root / "connectors/conn-test.json").exists())

    def test_active_connector_sink_must_be_registered_id(self) -> None:
        from dataasset_ui_services import objects

        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "schema").mkdir()
            shutil.copy2(REPO_ROOT / "dataasset/schema/data-connector.schema.json", root / "schema")
            connector = {"connector_id": "conn-test", "name": "Test", "connector_type": "agent_stream",
                         "status": "active", "credentials_ref": "vault://agent/test",
                         "config": {"sink_connector_id": "../outside"}}
            with patch.object(objects, "DATAASSET_DIR", root), patch.dict(
                objects.CRUD_OBJECTS, {"connector": {**objects.CRUD_OBJECTS["connector"], "directory": root / "connectors"}},
            ):
                with self.assertRaisesRegex(ValueError, "sink_connector_id 引用不存在"):
                    objects.save_object("connector", connector)
                self.assertFalse((root / "connectors/conn-test.json").exists())

    def test_atomic_save_failure_preserves_previous_json(self) -> None:
        from dataasset.registry_write import write_json_atomic

        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "item.json"
            path.write_text('{"old": true}\n', encoding="utf-8")
            with patch("dataasset.registry_write.os.replace", side_effect=OSError("interrupted")):
                with self.assertRaisesRegex(OSError, "interrupted"):
                    write_json_atomic(path, {"new": True})
            self.assertEqual(path.read_text(encoding="utf-8"), '{"old": true}\n')
            self.assertEqual(list(Path(temp_dir).glob(".item.json.*.tmp")), [])

    def test_studio_and_cli_share_bounded_registry_write_lock(self) -> None:
        from dataasset.registry_write import registry_write_lock

        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with registry_write_lock(root):
                with self.assertRaisesRegex(TimeoutError, "write lock busy"):
                    with registry_write_lock(root, timeout=0.05):
                        self.fail("second writer entered while lock was held")

    def test_credentials_support_resolved_external_root_paths(self) -> None:
        from dataasset_ui_services import credentials as credential_services

        with TemporaryDirectory(dir="/tmp") as temp_dir, patch.object(
            credential_services,
            "CREDENTIALS_DIR",
            Path(temp_dir),
        ):
            example = Path(temp_dir) / "examples" / "ui-e2e" / "test.yaml"
            example.parent.mkdir(parents=True)
            example.write_text("type: mysql\n", encoding="utf-8")

            self.assertEqual(credential_services.credential_ref_from_example(example), "vault://ui-e2e/test")
            self.assertEqual(credential_services.relative_to_credentials(example), "examples/ui-e2e/test.yaml")

    def test_credential_save_invokes_sops_and_requires_encrypted_output(self) -> None:
        from dataasset_ui_services import credentials as credential_services

        with TemporaryDirectory(dir="/tmp") as temp_dir, patch.object(
            credential_services,
            "CREDENTIALS_DIR",
            Path(temp_dir),
        ), patch.object(credential_services, "encrypt_credential") as encrypt:
            secret_path = Path(temp_dir) / "secrets" / "ui-e2e" / "test.enc.yaml"
            encrypt.side_effect = lambda _ref, _example: secret_path.write_text("sops: encrypted\n", encoding="utf-8")

            saved_path, saved_ref = credential_services.save_credential(
                {"credential_id": "vault://ui-e2e/test", "content": "type: mysql\npassword: secret\n"}
            )

            self.assertEqual(saved_ref, "vault://ui-e2e/test")
            self.assertEqual(saved_path.resolve(), secret_path.resolve())
            self.assertTrue((Path(temp_dir) / "examples" / "ui-e2e").is_dir())
            self.assertTrue((Path(temp_dir) / "secrets" / "ui-e2e").is_dir())
            encrypt.assert_called_once()
            encrypted_source = encrypt.call_args.args[1]
            self.assertFalse(encrypted_source.exists())
            example_path = Path(temp_dir) / "examples" / "ui-e2e" / "test.yaml"
            self.assertEqual(example_path.read_text(encoding="utf-8"), 'type: mysql\npassword: "REPLACE_ME"\n')

    def test_credential_save_rolls_back_example_when_sops_fails(self) -> None:
        from dataasset_ui_services import credentials as credential_services

        with TemporaryDirectory(dir="/tmp") as temp_dir, patch.object(
            credential_services,
            "CREDENTIALS_DIR",
            Path(temp_dir),
        ), patch.object(credential_services, "encrypt_credential", side_effect=RuntimeError("sops failed")):
            example_path = Path(temp_dir) / "examples" / "ui-e2e" / "test.yaml"
            example_path.parent.mkdir(parents=True)
            example_path.write_text("type: mysql\npassword: old\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "sops failed"):
                credential_services.save_credential(
                    {"credential_id": "vault://ui-e2e/test", "content": "type: mysql\npassword: new\n"}
                )

            self.assertEqual(example_path.read_text(encoding="utf-8"), "type: mysql\npassword: old\n")

    def test_credential_status_can_toggle_without_changing_files(self) -> None:
        from dataasset_ui_services import credentials as credential_services

        with TemporaryDirectory(dir="/tmp") as temp_dir, patch.object(
            credential_services,
            "CREDENTIALS_DIR",
            Path(temp_dir),
        ):
            example_path = Path(temp_dir) / "examples" / "ssh" / "readonly.yaml"
            secret_path = Path(temp_dir) / "secrets" / "ssh" / "readonly.enc.yaml"
            example_path.parent.mkdir(parents=True)
            secret_path.parent.mkdir(parents=True)
            example_path.write_text("type: ssh\npassword: REPLACE_ME\n", encoding="utf-8")
            secret_path.write_text("sops: encrypted\n", encoding="utf-8")
            example_before = example_path.read_bytes()
            secret_before = secret_path.read_bytes()

            self.assertEqual(credential_services.set_credential_status("vault://ssh/readonly", "disabled"), "disabled")
            self.assertEqual(credential_services.list_credential_objects()[0]["status"], "disabled")
            self.assertEqual(credential_services.set_credential_status("vault://ssh/readonly", "active"), "active")
            self.assertEqual(credential_services.list_credential_objects()[0]["status"], "active")
            self.assertEqual(example_path.read_bytes(), example_before)
            self.assertEqual(secret_path.read_bytes(), secret_before)

            status_path = Path(temp_dir) / "credential-status.json"
            status_path.write_text(
                json.dumps({"vault://ssh/readonly": "disabeld"}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unsupported status"):
                credential_services.load_credential_statuses()

    def test_shared_resolver_rejects_disabled_credentials(self) -> None:
        resolver_path = REPO_ROOT / "src" / "dataasset" / "credentials" / "resolve.py"
        spec = importlib.util.spec_from_file_location("credential_resolver", resolver_path)
        if spec is None or spec.loader is None:
            self.fail(f"cannot load {resolver_path}")
        resolver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(resolver)

        with TemporaryDirectory(dir="/tmp") as temp_dir:
            resolver.STATUS_FILE = str(Path(temp_dir) / "credential-status.json")
            credential_ref = "vault://ssh/readonly"
            resolver.ensure_credential_active(credential_ref)

            Path(resolver.STATUS_FILE).write_text(
                json.dumps({credential_ref: "disabled"}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "credential is disabled"):
                resolver.ensure_credential_active(credential_ref)

            Path(resolver.STATUS_FILE).write_text(
                json.dumps({credential_ref: "active"}),
                encoding="utf-8",
            )
            resolver.ensure_credential_active(credential_ref)


if __name__ == "__main__":
    unittest.main()
