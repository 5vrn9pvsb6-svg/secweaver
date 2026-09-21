"""Runtime lifecycle enforcement for DataAsset evidence fetches."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/skills/_shared/data-access"))

import fetch as fetch_module  # noqa: E402


class DataAssetFetchLifecycleTests(unittest.TestCase):
    def test_skill_fetch_rejects_draft_before_query_planning(self) -> None:
        asset = {"asset_id": "asset-draft", "status": "draft"}
        connector = {"connector_id": "conn-active", "status": "active"}
        with (
            patch.object(fetch_module, "load_asset", return_value=asset),
            patch.object(fetch_module, "load_connector", return_value=connector),
            patch.object(fetch_module, "load_templates") as load_templates,
        ):
            with self.assertRaisesRegex(PermissionError, "asset-draft.*not active"):
                fetch_module.fetch("asset-draft", "template", {}, connector_id="conn-active")
            load_templates.assert_not_called()

    def test_onboarding_mode_allows_draft_and_discovery(self) -> None:
        for asset_status in ("draft", "discovery", "active"):
            with self.subTest(asset_status=asset_status):
                fetch_module._enforce_execution_status(
                    {"asset_id": "asset-test", "status": asset_status},
                    {"connector_id": "conn-test", "status": "draft"},
                    fetch_module.EXECUTION_MODE_ONBOARDING_TEST,
                )

    def test_disabled_is_blocked_in_every_mode(self) -> None:
        cases = (
            ({"asset_id": "asset-off", "status": "disabled"}, {"connector_id": "conn-on", "status": "active"}),
            ({"asset_id": "asset-on", "status": "active"}, {"connector_id": "conn-off", "status": "disabled"}),
        )
        for mode in (fetch_module.EXECUTION_MODE_SKILL, fetch_module.EXECUTION_MODE_ONBOARDING_TEST):
            for asset, connector in cases:
                with self.subTest(mode=mode, asset=asset["asset_id"], connector=connector["connector_id"]):
                    with self.assertRaisesRegex(PermissionError, "disabled"):
                        fetch_module._enforce_execution_status(asset, connector, mode)

    def test_unknown_lifecycle_state_is_not_treated_as_onboarding(self) -> None:
        with self.assertRaisesRegex(PermissionError, "unsupported status"):
            fetch_module._enforce_execution_status(
                {"asset_id": "asset-test", "status": "pending"},
                {"connector_id": "conn-test", "status": "active"},
                fetch_module.EXECUTION_MODE_ONBOARDING_TEST,
            )


if __name__ == "__main__":
    unittest.main()
