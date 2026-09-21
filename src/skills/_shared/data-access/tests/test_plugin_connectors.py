"""Tests for connector plugin discovery and execution."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from connector_registry import connector_registry, query_key_for_connector, runtime_capabilities  # noqa: E402
from extended_fetch import fetch_extended_connector  # noqa: E402
from template_select import connector_supports_template  # noqa: E402


class TestPluginConnectors(unittest.TestCase):
    def test_plugin_manifest_registers_connector_type(self) -> None:
        registry = connector_registry()
        self.assertIn("demo_plugin_logs", registry)
        self.assertEqual(query_key_for_connector("demo_plugin_logs"), "demo_plugin_query")
        self.assertEqual(runtime_capabilities()["demo_plugin_logs"], "plugin")
        self.assertTrue(registry["demo_plugin_logs"]["plugin_dir"].endswith("src/dataasset/plugins/connectors/demo_plugin_logs"))

    def test_plugin_fetch_executes_stdio_json_entrypoint(self) -> None:
        self.assertTrue(
            connector_supports_template(
                {
                    "connector_types": ["demo_plugin_logs"],
                    "demo_plugin_query": "demo plugin src_ip={src_ip} limit {limit}",
                },
                "demo_plugin_logs",
            )
        )

        events, meta = fetch_extended_connector(
            {
                "connector_id": "conn-demo-plugin",
                "connector_type": "demo_plugin_logs",
                "constraints": {
                    "max_records_per_request": 5,
                    "request_timeout_sec": 10,
                },
            },
            {},
            {
                "template_id": "demo-plugin-by-src-ip",
                "demo_plugin_query": "demo plugin src_ip=203.0.113.10 limit 2",
                "params": {
                    "src_ip": "203.0.113.10",
                    "limit": 2,
                },
            },
        )

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["src_ip"], "203.0.113.10")
        self.assertEqual(events[0]["action"], "plugin-demo")
        self.assertEqual(meta["mode"], "plugin")
        self.assertEqual(meta["backend"], "demo_plugin_logs")
        self.assertEqual(meta["rows_returned"], 2)

    def test_template_support_reads_the_current_registry_mapping(self) -> None:
        template = {
            "connector_types": ["dynamic_logs"],
            "first_query": "source=first",
        }
        with patch(
            "template_select.query_key_by_connector",
            side_effect=[{"dynamic_logs": "first_query"}, {"dynamic_logs": "second_query"}],
        ):
            self.assertTrue(connector_supports_template(template, "dynamic_logs"))
            self.assertFalse(connector_supports_template(template, "dynamic_logs"))


if __name__ == "__main__":
    unittest.main()
