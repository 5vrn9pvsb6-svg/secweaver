"""Tests for WAF victim normalization and access backfill."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from normalizer import normalize_event  # noqa: E402
from waf_enrich import (  # noqa: E402
    canonicalize_waf_victim,
    enrich_waf_events_from_access,
    parse_http_host_from_url,
    parse_host_from_request_header,
)


WAF_ASSET = {
    "asset_id": "asset-waf-prod-01",
    "asset_type": "waf_alert",
    "field_aliases": {
        "upstream_addr": "target_ip",
        "ip": "src_ip",
        "trace_id": "alert_id",
    },
}


class TestWafEnrich(unittest.TestCase):
    def test_parse_http_host_from_url(self) -> None:
        self.assertEqual(
            parse_http_host_from_url("https://test1.u.yinshendun.com:30443/sqli/search.php?q=1"),
            "test1.u.yinshendun.com:30443",
        )

    def test_parse_host_from_request_header(self) -> None:
        header = "Host: test1.u.yinshendun.com:30443\r\nUser-Agent: curl/8.2.1"
        self.assertEqual(parse_host_from_request_header(header), "test1.u.yinshendun.com:30443")

    def test_canonicalize_waf_victim_from_url(self) -> None:
        ev = canonicalize_waf_victim(
            {
                "url": "https://test1.u.yinshendun.com:30443/sqli/page.php?tpl=/etc/passwd",
                "ip": "38.148.253.160",
            }
        )
        self.assertEqual(ev["http_host"], "test1.u.yinshendun.com:30443")
        self.assertEqual(ev["victim_host"], "test1.u.yinshendun.com:30443")
        self.assertNotIn("target_ip", ev)

    def test_normalize_event_sets_http_host_and_host(self) -> None:
        ev = normalize_event(
            {
                "ip": "38.148.253.160",
                "url": "https://test1.u.yinshendun.com:30443/.env",
                "timestamp": "2026-07-04T22:24:52+08:00",
            },
            WAF_ASSET,
            1,
        )
        self.assertEqual(ev["http_host"], "test1.u.yinshendun.com:30443")
        self.assertEqual(ev["host"], "test1.u.yinshendun.com:30443")

    def test_enrich_waf_target_from_access(self) -> None:
        waf = [
            {
                "src_ip": "38.148.253.160",
                "timestamp": "2026-07-04T22:45:26+08:00",
                "url": "https://test1.u.yinshendun.com:30443/sqli/search.php?q=x",
            }
        ]
        web = [
            {
                "remote_addr": "38.148.253.160",
                "timestamp": "2026-07-04T22:45:26+08:00",
                "request_uri": "/sqli/search.php?q=x",
                "upstream_addr": "192.0.2.91:80",
                "status": "200",
            }
        ]
        enriched, stats = enrich_waf_events_from_access(waf, web)
        self.assertEqual(stats["enriched"], 1)
        self.assertEqual(enriched[0]["target_ip"], "192.0.2.91")
        self.assertEqual(enriched[0]["target_ip_source"], "web_access_upstream_addr")

    def test_enrich_skips_when_target_ip_present(self) -> None:
        waf = [{"src_ip": "1.2.3.4", "target_ip": "10.0.0.1", "timestamp": "2026-07-04T22:00:00+08:00"}]
        web = [{"remote_addr": "1.2.3.4", "upstream_addr": "10.0.0.2", "timestamp": "2026-07-04T22:00:00+08:00"}]
        enriched, stats = enrich_waf_events_from_access(waf, web)
        self.assertEqual(enriched[0]["target_ip"], "10.0.0.1")
        self.assertEqual(stats["already_had_target_ip"], 1)


if __name__ == "__main__":
    unittest.main()
