"""Unit tests for evidence normalizer."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from normalizer import (  # noqa: E402
    apply_masking,
    apply_time_correction,
    get_time_correction,
    make_evidence_id,
    normalize_event,
    normalize_ip,
    normalize_timestamp,
)


ASSET = {
    "asset_id": "asset-waf-prod-01",
    "asset_type": "waf_alert",
    "masking": {"payload": "truncate_10"},
}


class TestNormalizer(unittest.TestCase):
    def test_declared_event_time_wins_and_invalid_time_falls_back(self):
        asset = {"asset_type": "host_exec", "schema": {"time_field": "time"}}
        row = {"time": "2026-09-17T01:02:03+08:00", "timestamp": "2026-09-18T00:00:00+08:00",
               "_sls_timestamp": "2026-09-18T00:00:01+08:00"}
        self.assertEqual(normalize_event(row, asset, 1)["timestamp"], row["time"])
        row.update(time="invalid", timestamp="invalid")
        self.assertEqual(normalize_event(row, asset, 1)["timestamp"], row["_sls_timestamp"])

    def test_native_event_identity_ignores_upload_but_keeps_distinct_sources(self):
        asset = {"asset_id": "exec", "asset_type": "host_exec", "schema": {"time_field": "time"}}
        row = {"audit_id": "10:20", "host_ip": "192.0.2.10", "pid": 2, "command": "id",
               "time": "2026-09-17T01:02:03+08:00", "__tag__:__pack_id__": "pack-a",
               "__tag__:__receive_time__": "1", "_sls_timestamp": "2026-09-18T00:00:00+08:00"}
        original = normalize_event(row, asset, 1)["evidence_id"]
        replay = {**row, "__tag__:__pack_id__": "pack-b", "__tag__:__receive_time__": "2",
                  "_sls_timestamp": "2026-09-18T01:00:00+08:00"}
        self.assertIn("-v3-", original)
        self.assertEqual(original, normalize_event(replay, asset, 99)["evidence_id"])
        for change in ({"host_ip": "192.0.2.11"}, {"time": "2026-09-17T02:02:03+08:00"},
                       {"file_paths": ["/a"]}, {"command": "whoami"}, {"_source_asset_id": "other"}):
            self.assertNotEqual(original, normalize_event({**row, **change}, asset, 1)["evidence_id"])
        self.assertEqual(normalize_event({**row, "evidence_id": "explicit"}, asset, 1)["evidence_id"], "explicit")

    def test_identity_is_order_independent_and_source_scoped(self) -> None:
        event = {"host": "test", "command": "id", "timestamp": "2026-09-16T00:00:00Z"}
        first = make_evidence_id(ASSET, event, 1)
        self.assertEqual(first, make_evidence_id(ASSET, dict(reversed(list(event.items()))), 99))
        self.assertNotEqual(first, make_evidence_id({**ASSET, "asset_id": "other"}, event, 1))
        self.assertNotEqual(first, make_evidence_id(ASSET, {**event, "_source_connector_id": "other"}, 1))
        self.assertNotEqual(first, make_evidence_id(ASSET, {**event, "pid": 123}, 1))

    def test_es_native_identity_includes_index_and_ignores_field_projection(self) -> None:
        event = {"_es_index": "logs-a", "_es_id": "1", "host": "test"}
        first = make_evidence_id(ASSET, event, 1)
        self.assertEqual(first, make_evidence_id(ASSET, {**event, "extra_field": "projection"}, 2))
        self.assertNotEqual(first, make_evidence_id(ASSET, {**event, "_es_index": "logs-b"}, 1))
        self.assertNotEqual(first, make_evidence_id(ASSET, {**event, "_es_id": "2"}, 1))

    def test_explicit_masking_covers_raw_alias_and_nested_header(self) -> None:
        event = {"command": "synthetic token", "raw_command": "synthetic token", "headers": {"Authorization": "Bearer synthetic"}}
        self.assertEqual(apply_masking(event, {}), event)
        masked = apply_masking(event, {"masking": {"command": "redact", "raw_command": "redact", "headers.Authorization": "redact"}})
        self.assertNotIn("synthetic", str(masked))
        self.assertIn("synthetic", str(event))

    def test_normalize_ip_removes_export_quotes_and_port(self) -> None:
        self.assertEqual(normalize_ip('"39.144.124.34'), "39.144.124.34")
        self.assertEqual(normalize_ip("'39.144.124.34:443'"), "39.144.124.34")
        self.assertIsNone(normalize_ip("-"))
        self.assertIsNone(normalize_ip("not-an-ip"))

    def test_timestamp_iso(self) -> None:
        self.assertEqual(
            normalize_timestamp("2026-06-21T08:15:01+08:00"),
            "2026-06-21T08:15:01+08:00",
        )

    def test_timestamp_alias(self) -> None:
        ev = normalize_event({"__time__": 1718933701, "client_ip": "1.2.3.4"}, ASSET, 1)
        self.assertIn("timestamp", ev)
        self.assertEqual(ev["src_ip"], "1.2.3.4")
        self.assertTrue(ev["evidence_id"].startswith("waf-alert-"))

    def test_normalize_event_canonicalizes_source_ip_aliases(self) -> None:
        asset = {**ASSET, "field_aliases": {"ip": "src_ip"}}
        ev = normalize_event(
            {"ip": '"39.144.124.34', "timestamp": "2026-06-21T08:00:00+08:00"},
            asset,
            1,
        )
        self.assertEqual(ev["src_ip"], "39.144.124.34")

    def test_evidence_id_stable_when_present(self) -> None:
        ev = normalize_event({"evidence_id": "custom-1", "timestamp": "2026-06-21T08:00:00+08:00"}, ASSET, 1)
        self.assertEqual(ev["evidence_id"], "custom-1")

    def test_masking_truncate(self) -> None:
        ev = apply_masking({"payload": "x" * 20}, ASSET)
        self.assertTrue(str(ev["payload"]).endswith("…"))
        self.assertLessEqual(len(str(ev["payload"])), 11)

    def test_per_asset_field_aliases_override(self) -> None:
        asset = {
            **ASSET,
            "field_aliases": {"ip": "dst_ip"},
        }
        ev = normalize_event({"ip": "203.0.113.10", "timestamp": "2026-06-21T08:00:00+08:00"}, asset, 1)
        self.assertEqual(ev["dst_ip"], "203.0.113.10")
        self.assertNotIn("src_ip", ev)

    def test_time_correction_offset_minutes(self) -> None:
        asset = {
            **ASSET,
            "schema": {
                "time_correction": {
                    "offset_minutes": 30,
                    "reason": "WAF 入库时钟慢 30 分钟",
                }
            },
        }
        ev = normalize_event({"timestamp": "2026-06-21T08:00:00+08:00"}, asset, 1)
        self.assertEqual(ev["timestamp"], "2026-06-21T08:30:00+08:00")

    def test_time_correction_assume_timezone(self) -> None:
        asset = {
            **ASSET,
            "schema": {
                "time_correction": {
                    "assume_timezone": "Asia/Shanghai",
                }
            },
        }
        ev = normalize_event({"timestamp": "2026-06-21T08:00:00"}, asset, 1)
        self.assertEqual(ev["timestamp"], "2026-06-21T08:00:00+08:00")

    def test_apply_time_correction_negative(self) -> None:
        self.assertEqual(
            apply_time_correction("2026-06-21T09:00:00+08:00", {"offset_minutes": -60}),
            "2026-06-21T08:00:00+08:00",
        )

    def test_get_time_correction_empty(self) -> None:
        self.assertEqual(get_time_correction(ASSET), {})
        self.assertEqual(
            get_time_correction({**ASSET, "schema": {"time_correction": {"offset_minutes": 5}}}),
            {"offset_minutes": 5},
        )


    def test_host_exec_canonicalizes_localhost_to_host_ip(self) -> None:
        asset = {
            "asset_id": "asset-secweaver-host-exec",
            "asset_type": "host_exec",
            "field_aliases": {
                "host_name": "host",
                "time": "timestamp",
                "__source__": "log_source",
                "log_source": "host_ip",
            },
        }
        ev = normalize_event(
            {
                "host_name": "localhost.localdomain",
                "host_ip": "192.0.2.91",
                "__source__": "192.0.2.91",
                "time": "2026-07-01T10:00:00+08:00",
                "event_type": "exec",
            },
            asset,
            1,
        )
        self.assertEqual(ev["host"], "192.0.2.91")
        self.assertEqual(ev["_victim_host"], "192.0.2.91")
        self.assertEqual(ev["timestamp"], "2026-07-01T10:00:00+08:00")

    def test_waf_upstream_addr_strips_port_to_target_ip(self) -> None:
        asset = {
            "asset_id": "asset-waf-prod-01",
            "asset_type": "waf_alert",
            "field_aliases": {
                "upstream_addr": "target_ip",
                "ip": "src_ip",
            },
        }
        ev = normalize_event(
            {
                "ip": "203.0.113.10",
                "upstream_addr": "10.0.1.5:8080",
                "timestamp": "2026-07-01T10:00:00+08:00",
            },
            asset,
            1,
        )
        self.assertEqual(ev["target_ip"], "10.0.1.5")
        self.assertEqual(ev["host"], "10.0.1.5")
        self.assertNotIn("host_ip", ev)

    def test_waf_http_host_from_gateway_plugin_url(self) -> None:
        asset = {
            "asset_id": "asset-waf-prod-01",
            "asset_type": "waf_alert",
            "field_aliases": {
                "upstream_addr": "target_ip",
                "ip": "src_ip",
            },
        }
        ev = normalize_event(
            {
                "ip": "38.148.253.160",
                "url": "https://test1.u.yinshendun.com:30443/sqli/search.php?q=1",
                "timestamp": "2026-07-04T22:25:23+08:00",
            },
            asset,
            1,
        )
        self.assertEqual(ev["http_host"], "test1.u.yinshendun.com:30443")
        self.assertEqual(ev["host"], "test1.u.yinshendun.com:30443")
        self.assertIsNone(ev.get("target_ip"))


if __name__ == "__main__":
    unittest.main()
