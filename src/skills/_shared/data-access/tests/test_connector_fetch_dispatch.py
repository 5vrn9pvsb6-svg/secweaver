"""Tests for the unified connector fetch dispatcher."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from connector_fetch_dispatch import ConnectorFetchRequest, fetch_connector  # noqa: E402


def _request(connector_type: str, rendered: dict) -> ConnectorFetchRequest:
    return ConnectorFetchRequest(
        asset={"asset_id": "asset-demo", "asset_type": "waf_alert"},
        connector={"connector_id": f"conn-{connector_type}", "connector_type": connector_type},
        credentials={},
        rendered=rendered,
        requested_template_id="demo_template",
        effective_template_id="demo_template",
        load_connector=lambda connector_id: {"connector_id": connector_id},
        resolve_credentials=lambda ref: {},
    )


class TestConnectorFetchDispatch(unittest.TestCase):
    def test_builtin_connector_uses_registered_strategy(self) -> None:
        with patch(
            "connector_fetch_dispatch.fetch_sls",
            return_value=([{"message": "ok"}], {"backend": "sls"}),
        ) as mocked:
            events, meta = fetch_connector(
                _request("sls", {"sls_query": "* | limit 1", "params": {"limit": 1}})
            )

        self.assertEqual(events, [{"message": "ok"}])
        self.assertEqual(meta["backend"], "sls")
        mocked.assert_called_once()

    def test_sls_proxy_uses_dedicated_strategy(self) -> None:
        with patch(
            "connector_fetch_dispatch.fetch_sls_proxy",
            return_value=([{"message": "proxied"}], {"backend": "sls_proxy"}),
        ) as mocked:
            events, meta = fetch_connector(
                _request("sls_proxy", {"sls_query": "* | limit 1", "params": {"limit": 1}})
            )

        self.assertEqual(events, [{"message": "proxied"}])
        self.assertEqual(meta["backend"], "sls_proxy")
        mocked.assert_called_once()

    def test_extended_connector_uses_extended_dispatch(self) -> None:
        with patch("connector_fetch_dispatch.is_extended_connector", return_value=True), patch(
            "connector_fetch_dispatch.fetch_extended_connector",
            return_value=([], {"mode": "planned", "backend": "vendor_logs"}),
        ) as mocked:
            events, meta = fetch_connector(
                _request("vendor_logs", {"vendor_query": "src_ip=203.0.113.10", "params": {}})
            )

        self.assertEqual(events, [])
        self.assertEqual(meta["mode"], "planned")
        mocked.assert_called_once()

    def test_unknown_connector_type_is_explicit(self) -> None:
        with self.assertRaises(NotImplementedError):
            fetch_connector(_request("unknown_connector", {"params": {}}))


if __name__ == "__main__":
    unittest.main()
