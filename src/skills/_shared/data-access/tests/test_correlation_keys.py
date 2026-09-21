"""Unit tests for matrix+fields correlation key derivation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from correlation_keys import derive_correlation_keys  # noqa: E402


WAF_ASSET = {
    "asset_id": "asset-waf-prod-01",
    "asset_type": "waf_alert",
    "schema": {
        "fields": [
            "src_ip",
            "timestamp",
            "url",
            "alert_id",
            "ip",
            "trace_id",
            "event",
            "plugin_name",
        ],
        "time_field": "timestamp",
    },
}

EXEC_ASSET = {
    "asset_id": "asset-secweaver-host-exec",
    "asset_type": "host_exec",
    "field_aliases": {"host_name": "host", "time": "timestamp"},
    "schema": {
        "fields": ["host_name", "time", "host_ip", "pid", "listener_pid", "listener_port", "command"],
        "time_field": "timestamp",
    },
}

SYSLOG_RISK_ASSET = {
    "asset_id": "asset-secweaver-sys-risk-alert",
    "asset_type": "syslog_risk_alert",
    "covers_asset_types": ["ssh_auth"],
    "field_aliases": {"__source__": "host_ip", "host_name": "host"},
    "schema": {
        "fields": ["timestamp", "host_name", "src_ip", "user", "event_type", "__source__"],
        "time_field": "timestamp",
    },
}


class TestCorrelationKeys(unittest.TestCase):
    def test_waf_derives_join_keys(self) -> None:
        keys = derive_correlation_keys(WAF_ASSET)
        self.assertIn("src_ip", keys)
        self.assertIn("timestamp", keys)
        self.assertIn("url", keys)
        self.assertNotIn("payload", keys)

    def test_exec_derives_host_via_alias(self) -> None:
        keys = derive_correlation_keys(EXEC_ASSET)
        self.assertIn("host", keys)
        self.assertIn("timestamp", keys)
        self.assertIn("host_ip", keys)
        self.assertNotIn("host_name", keys)

    def test_empty_fields_only_timestamp_if_time_present(self) -> None:
        keys = derive_correlation_keys(
            {
                "asset_type": "waf_alert",
                "schema": {"fields": ["time"], "time_field": "time"},
            }
        )
        self.assertEqual(keys, ["timestamp"])

    def test_covered_asset_type_contributes_join_keys(self) -> None:
        keys = derive_correlation_keys(SYSLOG_RISK_ASSET)
        self.assertIn("timestamp", keys)
        self.assertIn("src_ip", keys)
        self.assertIn("host", keys)
        self.assertIn("user", keys)


if __name__ == "__main__":
    unittest.main()
