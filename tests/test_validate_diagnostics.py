import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = ROOT / "src" / "dataasset"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import validate as validate_module  # noqa: E402
from validate import (  # noqa: E402
    check_config_only_layout,
    check_connector,
    public_credential_template_exists,
    sls_proxy_endpoint_is_secure,
)
from validate_lib.diagnostics import Issue, Report, diagnose_issue  # noqa: E402


class ValidateDiagnosticsTest(unittest.TestCase):
    def test_explicit_validation_root_does_not_mutate_global_root(self) -> None:
        original_root = validate_module.DATAASSET_ROOT
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            validate_module.validate(Path(temp_dir))
        self.assertEqual(validate_module.DATAASSET_ROOT, original_root)

    def test_sls_proxy_requires_https_except_for_loopback(self) -> None:
        self.assertTrue(sls_proxy_endpoint_is_secure("https://sls-proxy.id-net.cn"))
        self.assertTrue(sls_proxy_endpoint_is_secure("http://127.0.0.1:8787"))
        self.assertTrue(sls_proxy_endpoint_is_secure("http://localhost:8787"))
        self.assertTrue(sls_proxy_endpoint_is_secure("http://[::1]:8787"))
        self.assertFalse(sls_proxy_endpoint_is_secure("http://proxy.example.com"))
        self.assertFalse(sls_proxy_endpoint_is_secure("proxy.example.com"))

    def test_active_sls_placeholder_project_is_rejected(self) -> None:
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            root = Path(temp_dir)
            path = root / "connectors" / "conn-placeholder.json"
            path.parent.mkdir()
            connector = {
                "connector_id": "conn-placeholder",
                "name": "placeholder",
                "connector_type": "sls",
                "status": "active",
                "credentials_ref": "vault://sls/placeholder",
                "config": {
                    "endpoint": "cn-hangzhou.log.aliyuncs.com",
                    "project": "YOUR_SLS_PROJECT",
                    "logstore": "YOUR_LOGSTORE",
                },
            }
            report = Report()

            check_connector(report, path, connector, root=root)

            self.assertTrue(any("必须保持 draft" in message for message in report.errors))

    def test_active_credential_connectors_require_secure_endpoints(self) -> None:
        cases = (
            ("es", {"url": "http://es.example.com:9200", "index": "security-*", "tls_verify": True}),
            ("http_api", {"base_url": "http://api.example.com", "tls_verify": True}),
            ("splunk", {"base_url": "http://splunk.example.com:8089", "index": "security", "verify_tls": True}),
            (
                "agent_stream",
                {"endpoint": "http://executor.example.com/fetch", "sink_connector_id": "conn-sink"},
            ),
        )
        for connector_type, config in cases:
            with self.subTest(connector_type=connector_type):
                report = Report()
                check_connector(
                    report,
                    ROOT / "dataasset/connectors" / f"conn-{connector_type}-transport.json",
                    {
                        "connector_id": f"conn-{connector_type}-transport",
                        "name": "transport test",
                        "connector_type": connector_type,
                        "status": "active",
                        "credentials_ref": "vault://test/readonly",
                        "config": config,
                    },
                    root=ROOT / "dataasset",
                )
                self.assertIn("connector-transport-insecure", {issue.code for issue in report.issues})

    def test_invalid_credential_reference_is_reported_without_path_access(self) -> None:
        report = Report()
        check_connector(
            report,
            ROOT / "dataasset/connectors/conn-invalid-ref.json",
            {
                "connector_id": "conn-invalid-ref",
                "name": "invalid ref",
                "connector_type": "es",
                "status": "active",
                "credentials_ref": "vault://es/../readonly",
                "config": {"url": "https://es.example.com", "index": "security-*", "tls_verify": True},
            },
            root=ROOT / "dataasset",
        )
        self.assertIn("connector-credential-ref-invalid", {issue.code for issue in report.issues})

    def test_relative_ca_path_escape_is_reported(self) -> None:
        report = Report()
        check_connector(
            report,
            ROOT / "dataasset/connectors/conn-ca-escape.json",
            {
                "connector_id": "conn-ca-escape",
                "name": "CA escape",
                "connector_type": "es",
                "status": "draft",
                "credentials_ref": "vault://es/readonly",
                "config": {
                    "url": "https://es.example.com",
                    "index": "security-*",
                    "tls_verify": True,
                    "ca_file": "../outside.pem",
                },
            },
            root=ROOT / "dataasset",
        )
        self.assertIn("connector-ca-file-invalid", {issue.code for issue in report.issues})

    def test_asset_roots_do_not_contain_programs(self) -> None:
        for root_name in ("dataasset", "dataasset_my"):
            root = ROOT / root_name
            if not root.is_dir():
                continue
            with self.subTest(root=root_name):
                report = Report()
                check_config_only_layout(report, root)
                self.assertEqual(report.errors, [])

    def test_program_in_asset_root_is_rejected(self) -> None:
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            root = Path(temp_dir)
            (root / "fetch.py").write_text("print('not config')\n", encoding="utf-8")
            report = Report()

            check_config_only_layout(report, root)

            self.assertEqual(len(report.errors), 1)
            self.assertEqual(report.issues[0].code, "dataasset-program-file")

    def test_credential_issue_has_operator_diagnosis(self) -> None:
        issue = Issue(
            "error",
            "credentials_ref 缺失",
            code="connector-credential",
            object_type="connector",
        )

        payload = issue.to_dict()

        self.assertEqual(payload["priority"], "P0")
        self.assertEqual(payload["category"], "credential")
        self.assertEqual(payload["owner"], "运营")
        self.assertTrue(payload["fix_steps"])

    def test_public_credential_template_is_not_treated_as_missing_secret(self) -> None:
        self.assertTrue(public_credential_template_exists("vault://sls/sls-readonly"))
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            custom_root = Path(temp_dir)
            template = custom_root / "credentials" / "examples" / "sls" / "sls-readonly.yaml"
            template.parent.mkdir(parents=True)
            template.write_text("type: aliyun_ram\n", encoding="utf-8")
            self.assertFalse(
                public_credential_template_exists("vault://sls/sls-readonly", custom_root)
            )

    def test_report_deduplicates_issue_keys(self) -> None:
        report = Report()
        report.error("same", code="connector-config", object_type="connector", object_id="asset-a")
        report.error("same", code="connector-config", object_type="connector", object_id="asset-a")

        payload = report.as_json()

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["summary"]["error_count"], 1)
        self.assertEqual(len(payload["issues"]), 1)

    def test_strict_mode_counts_warnings_as_blocking(self) -> None:
        report = Report()
        report.warn("catalog.json stale", code="catalog", object_type="catalog")

        normal = report.as_json()
        strict = report.as_json(strict=True)

        self.assertTrue(normal["ok"])
        self.assertFalse(strict["ok"])
        self.assertEqual(normal["summary"]["blocking_count"], 0)
        self.assertEqual(strict["summary"]["blocking_count"], 1)

    def test_unknown_issue_falls_back_to_generic_config(self) -> None:
        diagnosis = diagnose_issue(Issue("warning", "custom message"))

        self.assertEqual(diagnosis["category"], "generic-config")
        self.assertEqual(diagnosis["priority"], "P1")


if __name__ == "__main__":
    unittest.main()
