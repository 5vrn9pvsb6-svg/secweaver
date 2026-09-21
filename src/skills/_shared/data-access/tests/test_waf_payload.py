"""Tests for WAF payload base64 decode."""

from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skill_input import waf_events_to_primary_alerts  # noqa: E402
from waf_payload import extract_waf_request_method, resolve_waf_payload, try_decode_base64_text  # noqa: E402


class TestWafPayload(unittest.TestCase):
    def test_plain_json_unchanged(self) -> None:
        raw = '{"user":"admin"}'
        decoded, hint = try_decode_base64_text(raw)
        self.assertIsNone(decoded)
        self.assertEqual(hint, "plain")

    def test_standard_base64(self) -> None:
        plain = "id=1' OR 1=1--"
        raw = base64.b64encode(plain.encode()).decode()
        decoded, hint = try_decode_base64_text(raw)
        self.assertEqual(decoded, plain)
        self.assertEqual(hint, "base64")

    def test_urlsafe_base64(self) -> None:
        plain = '{"action":"login"}'
        raw = base64.urlsafe_b64encode(plain.encode()).decode()
        decoded, hint = try_decode_base64_text(raw)
        self.assertEqual(decoded, plain)
        self.assertIn("base64", hint)

    def test_data_uri(self) -> None:
        plain = "username=test&password=secret"
        raw = "data:application/x-www-form-urlencoded;base64," + base64.b64encode(plain.encode()).decode()
        decoded, hint = try_decode_base64_text(raw)
        self.assertEqual(decoded, plain)
        self.assertEqual(hint, "data_uri_base64")

    def test_resolve_prefers_body_and_decodes(self) -> None:
        plain = "UNION SELECT 1,2,3"
        ev = {"request.body": base64.b64encode(plain.encode()).decode(), "url": "/api"}
        payload, meta = resolve_waf_payload(ev)
        self.assertEqual(payload, plain)
        self.assertTrue(meta["payload_decoded"])
        self.assertEqual(meta["payload_source"], "request.body")

    def test_resolve_falls_back_to_url(self) -> None:
        payload, meta = resolve_waf_payload({"url": "/health", "request.body": "null"})
        self.assertEqual(payload, "/health")
        self.assertEqual(meta, {})

    def test_resolve_from_request_json(self) -> None:
        plain = '<% out.println("x"); %>'
        inner = base64.b64encode(
            f'--b\r\nContent-Disposition: form-data; filename="x.jsp"\r\n\r\n{plain}\r\n--b--'.encode()
        ).decode()
        ev = {
            "request": json.dumps({"body": inner}),
            "request.body": "null",
            "url": "/upload.jsp",
        }
        payload, meta = resolve_waf_payload(ev)
        self.assertIn("out.println", payload)
        self.assertTrue(meta["payload_decoded"])
        self.assertEqual(meta["payload_source"], "request.json.body")

    def test_extract_method_from_request_json(self) -> None:
        ev = {"request": json.dumps({"method": "POST", "body": "ignored"})}
        self.assertEqual(extract_waf_request_method(ev), "POST")

    def test_waf_events_to_primary_alerts_preserves_request_json_method(self) -> None:
        ev = {
            "alert_id": "waf-upload",
            "timestamp": "2026-07-11T12:34:47+08:00",
            "src_ip": "218.74.11.194",
            "url": "https://test1.u.yinshendun.com:30443/webshell/upload.php",
            "request": json.dumps({"method": "POST", "body": "ignored"}),
            "rule_name": "POST危险文件上传",
            "action": "block",
        }

        alerts = waf_events_to_primary_alerts([ev])

        self.assertEqual(alerts[0]["method"], "POST")


if __name__ == "__main__":
    unittest.main()
