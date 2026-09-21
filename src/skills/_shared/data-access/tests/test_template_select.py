"""Tests for query template selection."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from template_select import select_template_for_asset  # noqa: E402


class TestTemplateSelect(unittest.TestCase):
    def test_connector_default_template_used_when_asset_has_no_templates(self) -> None:
        asset = {
            "asset_id": "asset-waf-no-template",
            "asset_type": "waf_alert",
            "query_template_ids": [],
        }
        connector = {"connector_id": "conn-sls-waf", "connector_type": "sls"}
        templates = {
            "default_templates": {
                "sls": {"waf_alert": "waf_gateway_plugin_by_ip_time"}
            },
            "templates": {
                "waf_gateway_plugin_by_ip_time": {
                    "asset_types": ["waf_alert"],
                    "connector_types": ["sls"],
                    "params": ["src_ip", "time_start", "time_end", "limit"],
                    "defaults": {"limit": 2000},
                    "sls_query": "ip: {src_ip} | select * limit {limit}",
                }
            },
        }

        template_id, reason = select_template_for_asset(
            asset,
            connector,
            {
                "attacker_ip": "203.0.113.10",
                "time_start": "2026-06-21T08:00:00+08:00",
                "time_end": "2026-06-21T20:00:00+08:00",
            },
            templates,
        )

        self.assertEqual(template_id, "waf_gateway_plugin_by_ip_time")
        self.assertEqual(reason, "default_template_by_connector")

    def test_sls_proxy_reuses_sls_templates_and_defaults(self) -> None:
        asset = {
            "asset_id": "asset-proxy-waf",
            "asset_type": "waf_alert",
            "query_template_ids": [],
        }
        connector = {"connector_id": "conn-proxy-waf", "connector_type": "sls_proxy"}
        templates = {
            "default_templates": {"sls": {"waf_alert": "waf_by_ip"}},
            "templates": {
                "waf_by_ip": {
                    "asset_types": ["waf_alert"],
                    "connector_types": ["sls"],
                    "params": ["src_ip", "time_start", "time_end"],
                    "sls_query": "src_ip: {src_ip}",
                }
            },
        }

        template_id, reason = select_template_for_asset(
            asset,
            connector,
            {
                "src_ip": "203.0.113.10",
                "time_start": "2026-07-12T00:00:00+08:00",
                "time_end": "2026-07-12T00:01:00+08:00",
            },
            templates,
        )

        self.assertEqual(template_id, "waf_by_ip")
        self.assertEqual(reason, "default_template_by_connector")

    def test_asset_templates_still_preferred_over_default(self) -> None:
        asset = {
            "asset_id": "asset-waf-explicit",
            "asset_type": "waf_alert",
            "query_template_ids": ["waf_by_alert_id"],
        }
        connector = {"connector_id": "conn-http-waf", "connector_type": "http_api"}
        templates = {
            "default_templates": {"http_api": {"waf_alert": "waf_api_search"}},
            "templates": {
                "waf_by_alert_id": {
                    "asset_types": ["waf_alert"],
                    "connector_types": ["http_api"],
                    "params": ["alert_id"],
                    "http": {"method": "GET", "path": "/alerts/{alert_id}"},
                },
                "waf_api_search": {
                    "asset_types": ["waf_alert"],
                    "connector_types": ["http_api"],
                    "params": ["src_ip", "time_start", "time_end"],
                    "http": {"method": "POST", "path": "/alerts/search"},
                },
            },
        }

        template_id, reason = select_template_for_asset(
            asset,
            connector,
            {"alert_id": "WAF-001"},
            templates,
        )

        self.assertEqual(template_id, "waf_by_alert_id")
        self.assertIsNone(reason)

    def test_resolve_web_access_src_ip_prefers_ip_index_template(self) -> None:
        from template_select import resolve_src_ip_web_access_template_id

        asset = {
            "asset_id": "asset-secweaver-gateway-access",
            "asset_type": "web_access_log",
            "query_template_ids": [
                "web_access_by_remote_addr_time",
                "web_access_by_ip_time",
                "web_access_by_time",
            ],
        }
        connector = {"connector_id": "conn-sls-tsin", "connector_type": "sls"}
        templates = {
            "templates": {
                "web_access_by_remote_addr_time": {
                    "asset_types": ["web_access_log"],
                    "connector_types": ["sls"],
                    "params": ["src_ip", "time_start", "time_end", "limit"],
                    "sls_query": "remote_addr=\"{src_ip}\"",
                },
                "web_access_by_ip_time": {
                    "asset_types": ["web_access_log"],
                    "connector_types": ["sls"],
                    "params": ["src_ip", "time_start", "time_end", "limit"],
                    "defaults": {"limit": 2000},
                    "sls_query": "ip: {src_ip} | select * limit {limit}",
                },
                "web_access_by_src_ip_time": {
                    "asset_types": ["web_access_log"],
                    "connector_types": ["sls"],
                    "params": ["src_ip", "time_start", "time_end", "limit"],
                    "sls_query": "src_ip: {src_ip}",
                },
            }
        }
        params = {
            "src_ip": "77.90.185.230",
            "time_start": "2026-07-04T06:52:00+08:00",
            "time_end": "2026-07-04T07:32:00+08:00",
        }
        resolved = resolve_src_ip_web_access_template_id(
            asset,
            connector,
            params,
            templates,
            "web_access_by_src_ip_time",
        )
        self.assertEqual(resolved, "web_access_by_remote_addr_time")


if __name__ == "__main__":
    unittest.main()
