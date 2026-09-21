"""Tests for correlation-matrix field resolution."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from field_resolver import (  # noqa: E402
    canonical_variants,
    match_join_key,
    resolve_field_value,
)

EXEC_ASSET = {
    "asset_id": "asset-secweaver-host-exec",
    "asset_type": "host_exec",
    "field_aliases": {"host_name": "host", "time": "timestamp"},
}


class TestFieldResolver(unittest.TestCase):
    def test_resolve_canonical_direct(self) -> None:
        event = {"host": "web-01", "timestamp": "2026-06-21T09:00:00+08:00"}
        self.assertEqual(resolve_field_value(event, "host"), "web-01")

    def test_resolve_raw_host_name(self) -> None:
        event = {"host_name": "web-01", "time": "2026-06-21T09:00:00+08:00"}
        self.assertEqual(
            resolve_field_value(event, "host", asset=EXEC_ASSET, asset_type="host_exec"),
            "web-01",
        )

    def test_resolve_waf_ip_to_src_ip(self) -> None:
        event = {"ip": "203.0.113.10", "trace_id": "abc"}
        waf_asset = {
            "asset_id": "asset-waf-prod-01",
            "asset_type": "waf_alert",
        }
        self.assertEqual(
            resolve_field_value(event, "src_ip", asset=waf_asset, asset_type="waf_alert"),
            "203.0.113.10",
        )
        self.assertEqual(
            resolve_field_value(event, "alert_id", asset=waf_asset, asset_type="waf_alert"),
            "abc",
        )

    def test_canonical_variants_include_asset_type(self) -> None:
        names = canonical_variants("host", asset_type="host_exec")
        self.assertIn("host", names)
        self.assertIn("host_name", names)

    def test_match_join_raw_to_canonical(self) -> None:
        left = {"host": "web-01"}
        right = {"host_name": "web-01"}
        join_key = {"left": "host", "right": "host", "match": "exact"}
        self.assertTrue(
            match_join_key(
                left,
                right,
                join_key,
                right_asset=EXEC_ASSET,
            )
        )

    def test_match_join_explicit_variants(self) -> None:
        left = {"ip": "203.0.113.10"}
        right = {"src_ip": "203.0.113.10"}
        join_key = {
            "left": "src_ip",
            "left_variants": ["ip"],
            "right": "src_ip",
            "match": "exact",
        }
        self.assertTrue(match_join_key(left, right, join_key))

    def test_match_join_normalizes_quoted_ip(self) -> None:
        left = {"src_ip": '"203.0.113.10'}
        right = {"src_ip": "203.0.113.10"}
        join_key = {"left": "src_ip", "right": "src_ip", "match": "exact"}
        self.assertTrue(match_join_key(left, right, join_key))


if __name__ == "__main__":
    unittest.main()
