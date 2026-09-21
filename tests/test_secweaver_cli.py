"""Regression tests for src/secweaver.py CLI and offline demos."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "src" / "secweaver.py"
DATA_ACCESS = REPO_ROOT / "src" / "skills" / "_shared" / "data-access"
sys.path.insert(0, str(DATA_ACCESS))
from connector_registry import connector_types, onboarding_profiles  # noqa: E402
from jsonschema import Draft202012Validator  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "demo_expectations.json"
DEMO_INPUTS = {
    "completeness": REPO_ROOT / "examples/data-source-completeness/s1-full-traceable.json",
    "alert": REPO_ROOT / "examples/alert-confirmation/s4-webshell-attack-success.json",
    "traceability": REPO_ROOT / "examples/traceability/s1-web-shell-to-ssh-lateral.json",
    "risk": REPO_ROOT / "examples/risk-identification/s5-curl-download-exec-p0.json",
}


def run_cli(*args: str, timeout: int = 120, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        cwd=REPO_ROOT,
        env=process_env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def load_demo_expectations() -> dict:
    return json.loads(FIXTURES.read_text(encoding="utf-8"))


def assert_demo_output(payload: dict, demo_name: str) -> None:
    expectations = load_demo_expectations()[demo_name]
    for key in expectations["required_keys"]:
        if key not in payload:
            raise AssertionError(f"{demo_name}: missing required key {key!r}")

    for key, expected in expectations["assertions"].items():
        actual = payload.get(key)
        if actual != expected:
            raise AssertionError(f"{demo_name}: {key} expected {expected!r}, got {actual!r}")

    summary_assertions = expectations.get("summary_assertions")
    if summary_assertions:
        summary = payload.get("summary")
        if not isinstance(summary, dict):
            raise AssertionError(f"{demo_name}: expected summary object")
        for key, expected in summary_assertions.items():
            actual = summary.get(key)
            if actual != expected:
                raise AssertionError(f"{demo_name}.summary.{key} expected {expected!r}, got {actual!r}")


class TestSecWeaverCLI(unittest.TestCase):
    def test_help_exits_zero(self) -> None:
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("secweaver", result.stdout)

    def test_list_includes_demos_skills_and_asset_ops(self) -> None:
        result = run_cli("list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Available demos:", result.stdout)
        self.assertIn("data-source-completeness", result.stdout)
        self.assertIn("src/skills/data-source-completeness/SKILL.md", result.stdout)
        self.assertIn("asset apply", result.stdout)
        self.assertIn("asset discover-format", result.stdout)
        self.assertIn("connector catalog", result.stdout)

    def test_cli_visible_skills_are_declared_in_manifest(self) -> None:
        manifest_path = REPO_ROOT / "src" / "skills" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = manifest.get("skills", [])
        self.assertGreaterEqual(len(entries), 4)
        names = {entry["name"] for entry in entries}
        self.assertIn("data-source-completeness", names)
        for entry in entries:
            self.assertTrue((REPO_ROOT / entry["docs"]).is_file(), entry["docs"])
            if entry.get("cli_visible"):
                self.assertTrue((REPO_ROOT / entry["script"]).is_file(), entry["script"])
            if entry.get("demo"):
                demo = entry["demo"]
                self.assertTrue((REPO_ROOT / demo["input"]).is_file(), demo.get("input"))

    def test_skill_wrapper_forwards_options_across_separator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output = Path(temporary_dir) / "traceability.json"
            result = run_cli(
                "skill",
                "traceability-analysis",
                "-i",
                "examples/traceability/s1-web-shell-to-ssh-lateral.json",
                "--",
                "--patterns",
                "dataasset/scenarios/anchor-patterns.json",
                "--no-notify",
                "--no-markdown-report",
                "-o",
                str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["skill"], "traceability-analysis")

    def test_validate_exits_zero(self) -> None:
        result = run_cli("validate")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 error(s)", result.stderr)

    def test_validate_json_reports_ok(self) -> None:
        result = run_cli("validate", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["summary"]["error_count"], 0)
        self.assertIn("diagnostics", payload)
        self.assertIn("categories", payload["diagnostics"])
        jsonschema_warnings = [
            issue
            for issue in payload["issues"]
            if issue.get("code") == "jsonschema-missing"
        ]
        self.assertLessEqual(len(jsonschema_warnings), 1)
        messages = [issue["message"] for issue in payload["issues"]]
        self.assertEqual(len(messages), len(set(messages)))

    def test_validate_only_active_argument_is_forwarded(self) -> None:
        result = run_cli("validate", "--json", "--only-active")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])

    def test_validate_runtime_ready_reports_static_bundle_blockers(self) -> None:
        result = run_cli(
            "validate",
            "--json",
            "--runtime-ready",
            "--bundle",
            "bundle-incident-trace-default",
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stdout)
        readiness = payload["runtime_readiness"]
        self.assertEqual(readiness["mode"], "static")
        self.assertFalse(readiness["live_connectivity_checked"])
        self.assertEqual(readiness["not_ready_bundle_ids"], ["bundle-incident-trace-default"])
        self.assertTrue(any(issue["code"].startswith("runtime-") for issue in payload["issues"]))

    def test_validate_diagnose_flag_is_forwarded(self) -> None:
        result = run_cli("validate", "--diagnose")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("validate[normal/all]", result.stderr)

    def test_unknown_command_fails(self) -> None:
        result = run_cli("not-a-command")
        self.assertNotEqual(result.returncode, 0)

    def test_asset_discover_format_with_offline_sample(self) -> None:
        sample = REPO_ROOT / "examples/log-format-discovery/waf-jsonl.sample"
        result = run_cli("asset", "discover-format", "asset-waf-api-prod", "-i", str(sample))
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["skill"], "log-format-discovery")
        self.assertEqual(payload["asset_id"], "asset-waf-api-prod")
        self.assertIn("asset_type", payload)

    def test_asset_discover_format_can_emit_parser_draft(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            parser_path = Path(tmpdir) / "vendor-kv-log.json"
            result = run_cli(
                "asset",
                "discover-format",
                "asset-waf-api-prod",
                "--text",
                "2026-07-07T00:00:00Z vendor=acme src_ip=203.0.113.10 action=blocked",
                "--parser-id",
                "vendor-kv-log",
                "--emit-parser",
                str(parser_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["proposed_text_parser"]["asset_text_parser"], "vendor-kv-log")
            self.assertTrue(parser_path.is_file())
            parser = json.loads(parser_path.read_text(encoding="utf-8"))
            self.assertEqual(parser["parser_id"], "vendor-kv-log")
            self.assertIn("line_regex", parser)

    def test_connector_catalog_json_exposes_dependency_strategy(self) -> None:
        result = run_cli("connector", "catalog", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        records = {record["connector_type"]: record for record in payload["connectors"]}
        self.assertEqual(records["aws_cloudwatch"]["source"], "built_in")
        self.assertEqual(records["sls"]["source_file"], "dataasset/configure/connector-catalog.json")
        self.assertIn("boto3", records["aws_cloudwatch"]["dependency_hint"])
        self.assertEqual(records["demo_plugin_logs"]["source"], "plugin")
        self.assertIn("plugin_stdio_json", records["demo_plugin_logs"]["execution_order"])

    def test_connector_plugin_init_scaffolds_temp_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_cli(
                "connector",
                "plugin",
                "init",
                "vendor_logs",
                "--query-key",
                "vendor_query",
                "--output-dir",
                tmpdir,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            plugin_dir = Path(tmpdir) / "vendor_logs"
            manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["api_version"], "1.0")
            self.assertEqual(manifest["connector_type"], "vendor_logs")
            self.assertEqual(manifest["query_key"], "vendor_query")
            self.assertEqual(manifest["onboarding_template"], "external_generic")
            self.assertEqual(manifest["onboarding_profile"]["default_asset_type"], "waf_alert")
            self.assertTrue((plugin_dir / "fetch.py").is_file())

    def test_connector_plugin_validate_demo_plugin(self) -> None:
        result = run_cli("connector", "plugin", "validate", "src/dataasset/plugins/connectors/demo_plugin_logs", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["summary"]["plugin_count"], 1)
        self.assertEqual(payload["plugins"][0]["connector_type"], "demo_plugin_logs")

    def test_asset_init_dry_run_renders_onboarding_bundle(self) -> None:
        result = run_cli(
            "asset",
            "init",
            "--connector-type",
            "sls",
            "--asset-type",
            "waf_alert",
            "--name",
            "demo-waf",
            "--project",
            "YOUR_SLS_PROJECT",
            "--logstore",
            "YOUR_LOGSTORE",
            "--dry-run",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["connector"]["data"]["connector_id"], "conn-demo-waf")
        self.assertEqual(payload["asset"]["data"]["asset_id"], "asset-demo-waf")
        self.assertEqual(payload["template"]["data"]["template_id"], "demo-waf-by-src-ip-time")

    def test_asset_init_writes_to_temp_dataasset_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "query-templates").mkdir(parents=True)
            (root / "query-templates" / "templates.json").write_text(
                json.dumps({"version": "1.0", "default_templates": {}, "templates": {}}, ensure_ascii=False),
                encoding="utf-8",
            )
            result = run_cli(
                "asset",
                "init",
                "--connector-type",
                "sls",
                "--asset-type",
                "waf_alert",
                "--name",
                "demo-waf",
                "--output-dir",
                str(root),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "connectors" / "conn-demo-waf.json").is_file())
            self.assertTrue((root / "assets" / "asset-demo-waf.json").is_file())
            templates = json.loads((root / "query-templates" / "templates.json").read_text(encoding="utf-8"))
            self.assertIn("demo-waf-by-src-ip-time", templates["templates"])

    def test_asset_apply_dry_run_renders_configured_sources(self) -> None:
        config_path = REPO_ROOT / "dataasset" / "onboarding" / "examples" / "data-sources.sample.json"
        result = run_cli("asset", "apply", "-f", str(config_path), "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["mode"], "dry-run")
        self.assertEqual(len(payload["sources"]), 3)
        first = payload["sources"][0]
        self.assertEqual(first["connector"]["data"]["connector_id"], "conn-demo-waf-sls")
        self.assertEqual(first["asset"]["data"]["asset_id"], "asset-demo-waf-sls")
        self.assertEqual(first["asset"]["data"]["owner_team"], "security-ops")
        self.assertEqual(first["asset"]["data"]["coverage"]["apps"], ["demo-gateway"])
        self.assertEqual(first["asset"]["data"]["schema"]["fields"], ["timestamp", "src_ip", "target_ip", "url", "action", "rule_id"])
        self.assertEqual(first["asset"]["data"]["field_aliases"]["upstream_addr"], "target_ip")
        self.assertEqual(first["template"]["data"]["defaults"]["limit"], 1000)
        self.assertIn("client_ip", first["template"]["data"]["sls_query"])

    def test_asset_apply_env_dataasset_root_overrides_config_output_dir(self) -> None:
        config_path = REPO_ROOT / "dataasset" / "onboarding" / "examples" / "data-sources.sample.json"
        with tempfile.TemporaryDirectory() as tmp:
            private_root = Path(tmp) / "dataasset_private"
            shutil.copytree(REPO_ROOT / "dataasset" / "onboarding", private_root / "onboarding")
            result = run_cli(
                "asset",
                "apply",
                "-f",
                str(config_path),
                "--dry-run",
                env={"DATAASSET_ROOT": private_root.as_posix()},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["output_dir"], private_root.as_posix())
            self.assertTrue(payload["sources"][0]["asset"]["path"].startswith(private_root.as_posix()))

    def test_vendor_quickstart_configs_render(self) -> None:
        examples = [
            "secweaver-saas-sls-proxy-assets.json",
            "vendor-quickstart-cloudwatch.json",
            "vendor-quickstart-cloud-vendors.json",
            "vendor-quickstart-siem-warehouse.json",
            "vendor-quickstart-external-connector.json",
            "vendor-quickstart-databases.json",
            "vendor-quickstart-document-cache.json",
            "vendor-quickstart-identity-edge-edr.json",
            "vendor-quickstart-plugin-connector.json",
        ]
        for filename in examples:
            with self.subTest(filename=filename):
                config_path = REPO_ROOT / "dataasset" / "onboarding" / "examples" / filename
                result = run_cli("asset", "apply", "-f", str(config_path), "--dry-run")
                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                self.assertTrue(payload["ok"])
                self.assertGreaterEqual(len(payload["sources"]), 1)
                for source in payload["sources"]:
                    self.assertTrue(source["connector"]["data"]["connector_type"])
                    self.assertTrue(source["asset"]["data"]["query_template_ids"])
                    self.assertIsNotNone(source["template"]["data"])

    def test_secweaver_saas_sls_proxy_quickstart_uses_public_resources(self) -> None:
        config_path = REPO_ROOT / "dataasset" / "onboarding" / "examples" / "secweaver-saas-sls-proxy-assets.json"
        result = run_cli("asset", "apply", "-f", str(config_path), "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        sources = json.loads(result.stdout)["sources"]
        self.assertEqual(len(sources), 13)
        connectors = [source["connector"]["data"] for source in sources]
        assets = [source["asset"]["data"] for source in sources]
        self.assertEqual(
            {connector["config"]["logstore"] for connector in connectors},
            {
                "dns",
                "host-exec",
                "host-persistence",
                "host-process",
                "host-state",
                "host-sys-messages",
                "wis-waf-access",
                "wis-waf-log",
            },
        )
        self.assertTrue(all(connector["connector_type"] == "sls_proxy" for connector in connectors))
        self.assertTrue(all(connector["config"]["project"] == "secweaver" for connector in connectors))
        self.assertTrue(all(connector["config"]["tls_verify"] is True for connector in connectors))
        self.assertTrue(all(connector["status"] == "draft" for connector in connectors))
        self.assertTrue(all(asset["status"] == "discovery" for asset in assets))
        self.assertTrue(all(asset["asset_id"].startswith("asset-secweaver-") for asset in assets))

    def test_asset_apply_supports_all_schema_connector_types(self) -> None:
        profiles = onboarding_profiles()
        for connector_type in connector_types():
            with self.subTest(connector_type=connector_type):
                profile = profiles.get(connector_type) or {}
                asset_type = profile.get("default_asset_type") or (
                    "ssh_auth" if connector_type in {"ssh_file", "ssh_command", "local_file", "syslog_ingest"} else "waf_alert"
                )
                source = {
                    "name": f"demo-{connector_type}",
                    "connector_type": connector_type,
                    "asset_type": asset_type,
                    "credentials_ref": "vault://test/readonly",
                    "status": "discovery",
                    **(profile.get("defaults") or {}),
                }
                with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as handle:
                    json.dump(
                        {
                            "version": "1.0",
                            "output_dir": "dataasset",
                            "data_sources": [source],
                        },
                        handle,
                    )
                    handle.flush()
                    result = run_cli("asset", "apply", "-f", handle.name, "--dry-run")
                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                generated = payload["sources"][0]
                self.assertEqual(generated["connector"]["data"]["connector_type"], connector_type)
                self.assertEqual(generated["asset"]["data"]["connector_id"], generated["connector"]["data"]["connector_id"])
                self.assertTrue(generated["asset"]["data"]["query_template_ids"])
                connector_schema = json.loads(
                    (REPO_ROOT / "dataasset/schema/data-connector.schema.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    list(Draft202012Validator(connector_schema).iter_errors(generated["connector"]["data"])),
                    [],
                )

    def test_asset_apply_supports_config_registered_external_connector_type(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as handle:
            json.dump(
                {
                    "version": "1.0",
                    "output_dir": "dataasset",
                    "data_sources": [
                        {
                            "name": "demo-datadog",
                            "connector_type": "datadog_logs",
                            "asset_type": "waf_alert",
                            "credentials_ref": "vault://http/api-readonly",
                            "status": "discovery",
                            "connector": {
                                "config": {
                                    "sample_file": "examples/log-format-discovery/waf-jsonl.sample"
                                }
                            },
                        }
                    ],
                },
                handle,
            )
            handle.flush()
            result = run_cli("asset", "apply", "-f", handle.name, "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        generated = payload["sources"][0]
        self.assertEqual(generated["connector"]["data"]["connector_type"], "datadog_logs")
        self.assertIn("datadog_query", generated["template"]["data"])

    def test_asset_apply_rejects_invalid_closed_connector_override(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as handle:
            json.dump(
                {
                    "data_sources": [
                        {
                            "name": "invalid-http-api",
                            "connector_type": "http_api",
                            "asset_type": "waf_alert",
                            "credentials_ref": "vault://http/readonly",
                            "status": "draft",
                            "base_url": "https://api.example.com",
                            "connector": {"config": {"misspelled_option": True}},
                        }
                    ]
                },
                handle,
            )
            handle.flush()
            result = run_cli("asset", "apply", "-f", handle.name, "--dry-run")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("generated connector violates data-connector.schema.json", result.stderr)

    def test_asset_apply_promotes_cloudwatch_executor_fields(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as handle:
            json.dump(
                {
                    "version": "1.0",
                    "output_dir": "dataasset",
                    "data_sources": [
                        {
                            "name": "demo-cloudwatch",
                            "connector_type": "aws_cloudwatch",
                            "asset_type": "waf_alert",
                            "credentials_ref": "vault://aws/security-readonly",
                            "status": "discovery",
                            "region": "ap-southeast-1",
                            "log_group": "/aws/cloudtrail/organization",
                            "log_stream_prefix": "2026/",
                            "executor_endpoint": "http://127.0.0.1:8788/fetch",
                            "sample_file": "examples/log-format-discovery/waf-jsonl.sample",
                        }
                    ],
                },
                handle,
            )
            handle.flush()
            result = run_cli("asset", "apply", "-f", handle.name, "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        generated = payload["sources"][0]
        config = generated["connector"]["data"]["config"]
        self.assertEqual(config["region"], "ap-southeast-1")
        self.assertEqual(config["log_group"], "/aws/cloudtrail/organization")
        self.assertEqual(config["log_stream_prefix"], "2026/")
        self.assertEqual(config["executor_endpoint"], "http://127.0.0.1:8788/fetch")
        self.assertEqual(config["sample_file"], "examples/log-format-discovery/waf-jsonl.sample")
        self.assertIn("cloudwatch_query", generated["template"]["data"])

    def test_asset_apply_promotes_common_database_fields(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as handle:
            json.dump(
                {
                    "version": "1.0",
                    "output_dir": "dataasset",
                    "data_sources": [
                        {
                            "name": "demo-sqlserver",
                            "connector_type": "database_ro",
                            "asset_type": "waf_alert",
                            "credentials_ref": "vault://sqlserver/security-readonly",
                            "status": "discovery",
                            "host": "sqlserver.internal",
                            "port": "1433",
                            "engine": "sqlserver",
                            "database": "security_logs",
                            "driver": "ODBC Driver 18 for SQL Server",
                            "connection_string": "Driver={ODBC Driver 18 for SQL Server};Server=sqlserver.internal;",
                        },
                        {
                            "name": "demo-sqlite",
                            "connector_type": "database_ro",
                            "asset_type": "waf_alert",
                            "status": "discovery",
                            "engine": "sqlite",
                            "path": "dataasset/samples/security.db",
                        },
                    ],
                },
                handle,
            )
            handle.flush()
            result = run_cli("asset", "apply", "-f", handle.name, "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        sqlserver_config = payload["sources"][0]["connector"]["data"]["config"]
        sqlite_config = payload["sources"][1]["connector"]["data"]["config"]
        self.assertEqual(sqlserver_config["engine"], "sqlserver")
        self.assertEqual(sqlserver_config["port"], 1433)
        self.assertEqual(sqlserver_config["driver"], "ODBC Driver 18 for SQL Server")
        self.assertIn("ODBC Driver 18", sqlserver_config["connection_string"])
        self.assertEqual(sqlite_config["engine"], "sqlite")
        self.assertEqual(sqlite_config["path"], "dataasset/samples/security.db")

    def test_asset_apply_promotes_document_and_cache_fields(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as handle:
            json.dump(
                {
                    "version": "1.0",
                    "output_dir": "dataasset",
                    "data_sources": [
                        {
                            "name": "demo-mongo",
                            "connector_type": "mongodb",
                            "asset_type": "web_access_log",
                            "credentials_ref": "vault://mongodb/security-readonly",
                            "status": "discovery",
                            "host": "mongodb.internal",
                            "port": 27017,
                            "database": "security_logs",
                            "collection": "events",
                            "auth_source": "admin",
                        },
                        {
                            "name": "demo-redis",
                            "connector_type": "redis",
                            "asset_type": "asset_inventory",
                            "credentials_ref": "vault://redis/security-readonly",
                            "status": "discovery",
                            "host": "redis.internal",
                            "port": 6379,
                            "db": 0,
                            "ssl": False,
                        },
                    ],
                },
                handle,
            )
            handle.flush()
            result = run_cli("asset", "apply", "-f", handle.name, "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        mongo_config = payload["sources"][0]["connector"]["data"]["config"]
        redis_config = payload["sources"][1]["connector"]["data"]["config"]
        self.assertEqual(mongo_config["database"], "security_logs")
        self.assertEqual(mongo_config["collection"], "events")
        self.assertEqual(mongo_config["auth_source"], "admin")
        self.assertEqual(redis_config["db"], 0)
        self.assertIs(redis_config["ssl"], False)

    def test_asset_apply_writes_multiple_sources_to_temp_dataasset_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "sources.json"
            config_path.write_text(
                json.dumps(
                    {
                        "output_dir": str(root),
                        "defaults": {"owner_team": "ops", "environment": "lab", "status": "discovery"},
                        "data_sources": [
                            {
                                "name": "ops-waf",
                                "connector_type": "sls",
                                "asset_type": "waf_alert",
                                "project": "YOUR_SLS_PROJECT",
                                "logstore": "YOUR_LOGSTORE",
                            },
                            {
                                "name": "ops-auth",
                                "connector_type": "ssh_file",
                                "asset_type": "ssh_auth",
                                "host": "YOUR_HOST",
                            },
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            result = run_cli("asset", "apply", "-f", str(config_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "connectors" / "conn-ops-waf.json").is_file())
            self.assertTrue((root / "assets" / "asset-ops-auth.json").is_file())
            templates = json.loads((root / "query-templates" / "templates.json").read_text(encoding="utf-8"))
            self.assertIn("ops-waf-by-src-ip-time", templates["templates"])
            auth_asset = json.loads((root / "assets" / "asset-ops-auth.json").read_text(encoding="utf-8"))
            self.assertEqual(auth_asset["query_template_ids"], ["ssh_auth_by_src_ip_time"])

    def test_asset_diff_and_rollback_preview_use_onboarding_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "sources.json"
            config_path.write_text(
                json.dumps(
                    {
                        "output_dir": str(root),
                        "data_sources": [
                            {
                                "name": "ops-waf",
                                "connector_type": "sls",
                                "asset_type": "waf_alert",
                                "project": "YOUR_SLS_PROJECT",
                                "logstore": "YOUR_LOGSTORE",
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            diff_before = run_cli("asset", "diff", "-f", str(config_path))
            self.assertEqual(diff_before.returncode, 0, diff_before.stderr)
            before_payload = json.loads(diff_before.stdout)
            self.assertEqual(before_payload["sources"][0]["connector"]["status"], "missing")

            apply_result = run_cli("asset", "apply", "-f", str(config_path))
            self.assertEqual(apply_result.returncode, 0, apply_result.stderr)

            diff_after = run_cli("asset", "diff", "-f", str(config_path))
            self.assertEqual(diff_after.returncode, 0, diff_after.stderr)
            after_payload = json.loads(diff_after.stdout)
            self.assertEqual(after_payload["summary"]["change_count"], 0)
            self.assertEqual(after_payload["sources"][0]["asset"]["status"], "unchanged")

            rollback = run_cli("asset", "rollback", "-f", str(config_path), "--dry-run")
            self.assertEqual(rollback.returncode, 0, rollback.stderr)
            rollback_payload = json.loads(rollback.stdout)
            self.assertTrue(rollback_payload["dry_run"])
            self.assertEqual(rollback_payload["sources"][0]["connector"]["status"], "would_delete")
            self.assertEqual(rollback_payload["sources"][0]["template"]["status"], "would_remove")

    def test_asset_apply_deep_overrides_connector_asset_and_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "sources.json"
            config_path.write_text(
                json.dumps(
                    {
                        "output_dir": str(root),
                        "defaults": {
                            "owner_team": "ops",
                            "environment": "lab",
                            "status": "discovery",
                            "asset": {
                                "coverage": {
                                    "zones": ["default-zone"],
                                    "apps": [],
                                    "hosts": [],
                                },
                                "schema": {
                                    "retention_days": 14,
                                },
                            },
                        },
                        "data_sources": [
                            {
                                "name": "ops-waf",
                                "connector_type": "sls",
                                "asset_type": "waf_alert",
                                "project": "YOUR_SLS_PROJECT",
                                "logstore": "YOUR_LOGSTORE",
                                "connector": {
                                    "config": {
                                        "logstore": "ops-log",
                                    },
                                    "constraints": {
                                        "max_rows": 123,
                                    },
                                },
                                "asset": {
                                    "text_parser": "nginx_access",
                                    "coverage": {
                                        "zones": ["dmz"],
                                        "apps": ["shop"],
                                        "hosts": ["host-web-01"],
                                    },
                                    "schema": {
                                        "fields": ["timestamp", "src_ip", "url"],
                                    },
                                    "field_aliases": {
                                        "remote_addr": "src_ip",
                                    },
                                },
                                "template": {
                                    "params": ["src_ip", "time_start", "time_end", "limit"],
                                    "defaults": {
                                        "limit": 500,
                                    },
                                    "description": "custom source query",
                                    "sls_query": "remote_addr: {src_ip} | select * limit {limit}",
                                },
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            result = run_cli("asset", "apply", "-f", str(config_path), "--dry-run")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            generated = payload["sources"][0]
            connector = generated["connector"]["data"]
            asset = generated["asset"]["data"]
            template = generated["template"]["data"]
            self.assertEqual(connector["config"]["project"], "YOUR_SLS_PROJECT")
            self.assertEqual(connector["config"]["logstore"], "ops-log")
            self.assertEqual(connector["constraints"]["max_rows"], 123)
            self.assertEqual(asset["text_parser"], "nginx_access")
            self.assertEqual(asset["coverage"]["zones"], ["dmz"])
            self.assertEqual(asset["coverage"]["apps"], ["shop"])
            self.assertEqual(asset["coverage"]["hosts"], ["host-web-01"])
            self.assertEqual(asset["schema"]["fields"], ["timestamp", "src_ip", "url"])
            self.assertEqual(asset["schema"]["retention_days"], 14)
            self.assertEqual(asset["field_aliases"]["remote_addr"], "src_ip")
            self.assertEqual(template["defaults"]["limit"], 500)
            self.assertEqual(template["description"], "custom source query")
            self.assertIn("remote_addr", template["sls_query"])

    def test_asset_apply_rejects_unknown_config_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "sources.json"
            config_path.write_text(
                json.dumps(
                    {
                        "data_sources": [
                            {
                                "name": "bad",
                                "connector_type": "sls",
                                "asset_type": "waf_alert",
                                "project": "YOUR_SLS_PROJECT",
                                "logstore": "YOUR_LOGSTORE",
                                "surprise": "typo",
                            }
                        ]
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            result = run_cli("asset", "apply", "-f", str(config_path), "--dry-run")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown field", result.stderr)


class TestSecWeaverDemoRegression(unittest.TestCase):
    def test_demo_outputs_match_expectations(self) -> None:
        for demo_name, input_path in DEMO_INPUTS.items():
            with self.subTest(demo=demo_name):
                with tempfile.TemporaryDirectory() as tmpdir:
                    output_path = Path(tmpdir) / f"demo-{demo_name}-output.json"
                    result = run_cli("demo", demo_name, "-o", str(output_path))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(output_path.is_file(), f"missing output for {demo_name}")
                    payload = json.loads(output_path.read_text(encoding="utf-8"))
                    assert_demo_output(payload, demo_name)

    def test_demo_all_generates_four_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_cli("demo", "all", "-o", tmpdir)
            self.assertEqual(result.returncode, 0, result.stderr)
            output_dir = Path(tmpdir)
            for demo_name in ("completeness", "alert", "traceability", "risk"):
                output_path = output_dir / f"demo-{demo_name}-output.json"
                with self.subTest(demo=demo_name):
                    self.assertTrue(output_path.is_file(), f"missing {output_path.name}")
                    payload = json.loads(output_path.read_text(encoding="utf-8"))
                    assert_demo_output(payload, demo_name)

    def test_demo_all_treats_dotted_output_names_as_directories(self) -> None:
        """A directory suffix must not cause the first demo to overwrite the directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for name, precreate in (("existing.v1", True), ("new.v1", False)):
                with self.subTest(name=name):
                    output_dir = Path(tmpdir) / name
                    if precreate:
                        output_dir.mkdir()
                    result = run_cli("demo", "all", "-o", str(output_dir))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    for demo_name in ("completeness", "alert", "traceability", "risk"):
                        path = output_dir / f"demo-{demo_name}-output.json"
                        self.assertTrue(path.is_file(), f"missing {path}")
                        assert_demo_output(json.loads(path.read_text(encoding="utf-8")), demo_name)

    def test_demo_single_supports_existing_dotted_directory_and_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir) / "reports.v1"
            directory.mkdir()
            for destination, expected in (
                (directory, directory / "demo-risk-output.json"),
                (Path(tmpdir) / "risk.json", Path(tmpdir) / "risk.json"),
            ):
                with self.subTest(destination=destination):
                    result = run_cli("demo", "risk", "-o", str(destination))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    assert_demo_output(json.loads(expected.read_text(encoding="utf-8")), "risk")

    def test_demo_all_rejects_existing_file_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "reports.v1"
            file_path.write_text("keep me", encoding="utf-8")
            result = run_cli("demo", "all", "-o", str(file_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expects -o/--output to be a directory", result.stderr)
            self.assertEqual(file_path.read_text(encoding="utf-8"), "keep me")

    def test_skill_alert_matches_demo_expectations(self) -> None:
        input_path = DEMO_INPUTS["alert"]
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "alert.json"
            result = run_cli("skill", "alert-confirmation", "-i", str(input_path), "-o", str(output_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            assert_demo_output(payload, "alert")


if __name__ == "__main__":
    unittest.main()
