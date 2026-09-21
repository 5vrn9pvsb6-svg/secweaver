"""Compatibility tests for sanitized public DataAsset identifiers."""

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_ACCESS = REPO_ROOT / "src" / "skills" / "_shared" / "data-access"
sys.path.insert(0, str(DATA_ACCESS))

registry = importlib.import_module("registry")
trace_profile = importlib.import_module("trace_profile")


class DataAssetIdCompatibilityTests(unittest.TestCase):
    def test_new_asset_id_falls_back_to_legacy_private_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / "assets"
            assets.mkdir()
            legacy = assets / "asset-tigersec-host-exec.json"
            legacy.write_text(
                json.dumps({"asset_id": "asset-tigersec-host-exec", "asset_type": "host_exec"}),
                encoding="utf-8",
            )
            with patch.object(registry, "DATAASSET_ROOT", root):
                loaded = registry.load_asset("asset-secweaver-host-exec")
            self.assertEqual(loaded["asset_id"], "asset-tigersec-host-exec")

    def test_new_profile_id_falls_back_to_legacy_private_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profiles = Path(temporary)
            legacy = profiles / "tigersec-host-exec.json"
            legacy.write_text(json.dumps({"profile_id": "tigersec-host-exec"}), encoding="utf-8")
            trace_profile.load_trace_profile_template.cache_clear()
            with patch.object(trace_profile, "_TRACE_PROFILES_DIR", profiles):
                loaded = trace_profile.load_trace_profile_template("secweaver-host-exec")
            trace_profile.load_trace_profile_template.cache_clear()
            self.assertEqual(loaded["profile_id"], "tigersec-host-exec")


if __name__ == "__main__":
    unittest.main()
