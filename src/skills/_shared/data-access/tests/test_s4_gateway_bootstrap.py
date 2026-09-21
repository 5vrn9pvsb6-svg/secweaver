"""Tests for S4 gateway auto-append bootstrap."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

DATA_ACCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DATA_ACCESS))

from s4_gateway_bootstrap import (  # noqa: E402
    DEFAULT_S4_GATEWAY_ASSET_ID,
    LEGACY_S4_GATEWAY_ASSET_IDS,
    ensure_s4_alert_asset_ids,
    resolve_s4_gateway_asset_id,
    should_s4_gateway_append,
)


class S4GatewayBootstrapTests(unittest.TestCase):
    def test_should_append_when_waf_only(self) -> None:
        self.assertTrue(should_s4_gateway_append(["asset-waf-prod-01"]))

    def test_should_not_append_when_gateway_present(self) -> None:
        self.assertFalse(
            should_s4_gateway_append(["asset-waf-prod-01", "asset-secweaver-gateway-access"])
        )

    def test_ensure_appends_gateway_and_d2(self) -> None:
        merged = ensure_s4_alert_asset_ids(["asset-waf-prod-01"])
        self.assertIn(resolve_s4_gateway_asset_id(), merged)
        self.assertIn("asset-secweaver-host-exec", merged)
        self.assertIn("asset-secweaver-host-connect", merged)
        self.assertIn("asset-secweaver-host-file-op", merged)

    def test_ensure_skips_d2_when_disabled(self) -> None:
        merged = ensure_s4_alert_asset_ids(["asset-waf-prod-01"], include_exec=False)
        self.assertIn(resolve_s4_gateway_asset_id(), merged)
        self.assertNotIn("asset-secweaver-host-exec", merged)
        self.assertNotIn("asset-secweaver-host-connect", merged)
        self.assertNotIn("asset-secweaver-host-file-op", merged)

    @patch("s4_gateway_bootstrap.load_asset")
    def test_resolver_prefers_canonical_asset(self, mock_load_asset) -> None:
        def load(asset_id: str) -> dict[str, str]:
            if asset_id == DEFAULT_S4_GATEWAY_ASSET_ID:
                return {"asset_type": "web_access_log"}
            raise FileNotFoundError(asset_id)

        mock_load_asset.side_effect = load
        self.assertEqual(resolve_s4_gateway_asset_id(), DEFAULT_S4_GATEWAY_ASSET_ID)

    @patch("s4_gateway_bootstrap.load_asset")
    def test_resolver_falls_back_only_when_canonical_asset_is_missing(self, mock_load_asset) -> None:
        def load(asset_id: str) -> dict[str, str]:
            if asset_id == DEFAULT_S4_GATEWAY_ASSET_ID:
                raise FileNotFoundError(asset_id)
            if asset_id == LEGACY_S4_GATEWAY_ASSET_IDS[0]:
                return {"asset_type": "web_access_log"}
            raise FileNotFoundError(asset_id)

        mock_load_asset.side_effect = load
        self.assertEqual(
            resolve_s4_gateway_asset_id(),
            LEGACY_S4_GATEWAY_ASSET_IDS[0],
        )


if __name__ == "__main__":
    unittest.main()
