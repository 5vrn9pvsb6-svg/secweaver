from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
CHECK_PATH = REPO_ROOT / "src/skills/dataasset-connectivity-check/scripts/check.py"
SPEC = importlib.util.spec_from_file_location("dataasset_connectivity_check", CHECK_PATH)
assert SPEC and SPEC.loader
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class AssetProbeParamsTest(unittest.TestCase):
    def test_uses_first_coverage_ip_when_cli_host_is_absent(self) -> None:
        params, source = check.build_asset_probe_params(
            {"coverage": {"hosts": ["192.0.2.200", "192.0.2.201"]}},
            {"time_start": "t0", "time_end": "t1", "limit": 1},
        )

        self.assertEqual(params["host"], "192.0.2.200")
        self.assertEqual(params["host_ip"], "192.0.2.200")
        self.assertNotIn("host_name", params)
        self.assertEqual(source, "asset.coverage.hosts")

    def test_uses_coverage_hostname_as_host_name(self) -> None:
        params, source = check.build_asset_probe_params(
            {"coverage": {"hosts": ["db-prod-01"]}},
            {"time_start": "t0", "time_end": "t1", "limit": 1},
        )

        self.assertEqual(params["host"], "db-prod-01")
        self.assertEqual(params["host_name"], "db-prod-01")
        self.assertEqual(source, "asset.coverage.hosts")

    def test_explicit_host_overrides_coverage(self) -> None:
        params, source = check.build_asset_probe_params(
            {"coverage": {"hosts": ["192.0.2.200"]}},
            {"host": "10.0.9.9", "time_start": "t0", "time_end": "t1", "limit": 1},
        )

        self.assertEqual(params["host_ip"], "10.0.9.9")
        self.assertEqual(source, "cli")

    def test_missing_coverage_does_not_inject_synthetic_host(self) -> None:
        params, source = check.build_asset_probe_params(
            {"coverage": {"hosts": []}},
            {"time_start": "t0", "time_end": "t1", "limit": 1},
        )

        self.assertNotIn("host", params)
        self.assertNotIn("host_ip", params)
        self.assertNotIn("host_name", params)
        self.assertIsNone(source)

    @mock.patch.object(check, "fetch", return_value={"events": [], "query_meta": {}})
    @mock.patch.object(check, "select_template_for_asset", return_value=("host_by_time", None))
    @mock.patch.object(
        check,
        "load_connector",
        return_value={
            "connector_id": "conn-local",
            "connector_type": "local_file",
            "status": "active",
            "config": {"path": "/tmp/example.log"},
        },
    )
    @mock.patch.object(check, "load_asset", return_value={"asset_id": "asset-host", "asset_type": "host_exec"})
    def test_no_data_result_is_scoped_to_probe_host(
        self,
        _load_asset: mock.Mock,
        _load_connector: mock.Mock,
        _select_template: mock.Mock,
        _fetch: mock.Mock,
    ) -> None:
        row = check.check_one(
            "asset-host",
            "conn-local",
            {"host": "192.0.2.200", "host_ip": "192.0.2.200"},
            {},
            include_draft_connectors=False,
            live=True,
            probe_host_source="asset.coverage.hosts",
        )

        self.assertEqual(row["status"], check.STATUS_OK_NO_DATA)
        self.assertEqual(row["data_presence_scope"], "probe_host")
        self.assertIn("192.0.2.200", row["reason"])
        self.assertTrue(row["connectable"])
        self.assertFalse(row["has_data"])
        self.assertFalse(row["usable_for_skill"])
        self.assertFalse(row["usable_for_requested_skill"])
        summary = check.summarize([row])
        self.assertEqual(summary["connected_assets_total"], 1)
        self.assertEqual(summary["assets_with_data_total"], 0)
        self.assertEqual(summary["failed_assets_total"], 0)
        self.assertEqual(summary["usable_assets_total"], 0)

    def test_dry_run_does_not_claim_connection_or_fail(self):
        with mock.patch.object(check, "load_asset", return_value={"asset_type": "host_exec"}), \
             mock.patch.object(check, "load_connector", return_value={"connector_type": "local_file", "status": "active", "config": {}}), \
             mock.patch.object(check, "select_template_for_asset", return_value=("host_by_time", None)), \
             mock.patch.object(check, "fetch") as fetch:
            row = check.check_one("asset", "conn", {}, {}, include_draft_connectors=False, live=False)
        fetch.assert_not_called()
        self.assertIsNone(row["connectable"])
        self.assertIsNone(row["has_data"])
        self.assertFalse(row["usable_for_skill"])
        self.assertEqual(check.summarize([row])["failed_assets_total"], 0)

    def test_disabled_connector_stops_before_credential_resolution(self):
        connector = {
            "connector_id": "conn-disabled",
            "connector_type": "sls",
            "status": "disabled",
            "credentials_ref": "vault://sls/disabled",
            "config": {"endpoint": "example.invalid", "project": "demo", "logstore": "security"},
        }
        with mock.patch.object(check, "load_asset", return_value={"asset_type": "waf_alert", "status": "active"}), \
             mock.patch.object(check, "load_connector", return_value=connector), \
             mock.patch.object(check, "resolve_credentials") as resolve_credentials, \
             mock.patch.object(check, "fetch") as fetch:
            row = check.check_one("asset", "conn-disabled", {}, {}, include_draft_connectors=True, live=True)
        resolve_credentials.assert_not_called()
        fetch.assert_not_called()
        self.assertEqual(row["status"], check.STATUS_SKIPPED_DISABLED)

    def test_nonempty_probe_does_not_prove_full_skill_coverage(self):
        with mock.patch.object(check, "load_asset", return_value={"asset_type": "host_process"}), \
             mock.patch.object(check, "load_connector", return_value={"connector_type": "local_file", "status": "active", "config": {}}), \
             mock.patch.object(check, "select_template_for_asset", return_value=("host_by_time", None)), \
             mock.patch.object(check, "fetch", return_value={"events": [{"pid": 123}], "query_meta": {"truncated": True}}):
            row = check.check_one("asset", "conn", {}, {}, include_draft_connectors=False, live=True)
        self.assertTrue(row["connectable"])
        self.assertTrue(row["has_data"])
        self.assertIsNone(row["usable_for_requested_skill"])
        self.assertEqual(check.summarize([row])["skill_readiness"], "not_evaluated")


if __name__ == "__main__":
    unittest.main()
