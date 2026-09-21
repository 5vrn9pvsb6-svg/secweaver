"""Unit tests for Elasticsearch fetch (no live ES required)."""

from __future__ import annotations

import json
import ssl
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from es_fetch import _ssl_context, fetch_es, render_es_query  # noqa: E402

CONNECTOR = {
    "connector_id": "conn-es-waf-prod",
    "connector_type": "es",
    "config": {
        "url": "https://es.example.com:9200",
        "index": "logs-waf-*",
        "time_field": "@timestamp",
    },
    "constraints": {"max_records_per_request": 100},
}

CREDENTIALS = {"type": "es", "username": "reader", "password": "secret"}


class TestRenderEsQuery(unittest.TestCase):
    def test_deep_format(self) -> None:
        q = {"query": {"term": {"src_ip": "{src_ip}"}}, "size": "{limit}"}
        out = render_es_query(q, {"src_ip": "203.0.113.10", "limit": "100"})
        self.assertEqual(out["query"]["term"]["src_ip"], "203.0.113.10")
        self.assertEqual(out["size"], "100")


class TestFetchEs(unittest.TestCase):
    def test_hits_to_events(self) -> None:
        payload = {
            "hits": {
                "hits": [
                    {
                        "_index": "logs-waf-2026",
                        "_id": "1",
                        "_source": {
                            "src_ip": "203.0.113.10",
                            "@timestamp": "2026-06-21T08:00:00+08:00",
                        },
                    }
                ]
            }
        }
        body = json.dumps(payload).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        with patch("es_fetch._open_request", return_value=mock_resp):
            events, meta = fetch_es(
                CONNECTOR,
                CREDENTIALS,
                {"query": {"match_all": {}}, "size": 10},
                {},
            )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["src_ip"], "203.0.113.10")
        self.assertEqual(meta["index"], "logs-waf-*")

    def test_https_uses_configured_ca_file(self) -> None:
        connector = json.loads(json.dumps(CONNECTOR))
        with tempfile.TemporaryDirectory() as temp_dir:
            ca_file = Path(temp_dir) / "ca.crt"
            ca_file.write_text("test ca", encoding="utf-8")
            connector["config"]["ca_file"] = str(ca_file)
            connector["config"]["tls_verify"] = True
            context = MagicMock(spec=ssl.SSLContext)
            with patch("ssl.create_default_context", return_value=context) as create_context, patch(
                "es_fetch._open_request", side_effect=RuntimeError("stop after request")
            ) as urlopen:
                with self.assertRaisesRegex(RuntimeError, "stop after request"):
                    fetch_es(connector, CREDENTIALS, {"query": {"match_all": {}}}, {})
            create_context.assert_called_once_with(cafile=str(ca_file))
            self.assertIs(urlopen.call_args.kwargs["context"], context)

    def test_https_rejects_disabled_certificate_verification(self) -> None:
        connector = json.loads(json.dumps(CONNECTOR))
        connector["config"]["tls_verify"] = False
        with self.assertRaisesRegex(ValueError, "not allowed"):
            _ssl_context(connector["config"], connector["config"]["url"])

    def test_https_defaults_to_certificate_verification_enabled(self) -> None:
        context = _ssl_context(CONNECTOR["config"], CONNECTOR["config"]["url"])
        self.assertIsNotNone(context)
        assert context is not None
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_malformed_tls_policy_never_reaches_transport(self) -> None:
        for value in (None, 0, 1, "", "false", "true"):
            connector = {**CONNECTOR, "config": {**CONNECTOR["config"], "tls_verify": value}}
            with self.subTest(value=value), patch("es_fetch._open_request") as transport:
                with self.assertRaisesRegex(ValueError, "boolean"):
                    fetch_es(connector, CREDENTIALS, {"size": 10}, {})
                transport.assert_not_called()

    def test_partial_results_and_complete_control(self) -> None:
        cases = [
            ({"timed_out": True}, 2, 2, True, False, "timeout"),
            ({"terminated_early": True}, 2, 2, True, False, "terminated_early"),
            ({"_shards": {"failed": 1}}, 2, 2, True, False, "failed_shards"),
            ({}, 1000, 2, True, True, "total_hits_exceed_returned_or_lower_bound"),
            ({}, 3, 3, True, True, "local_limit"),
            ({}, {"value": 2, "relation": "gte"}, 2, True, True, "total_hits_exceed_returned_or_lower_bound"),
            ({}, None, 2, True, True, "page_limit_without_total"),
            ({}, 2, 2, False, False, None),
        ]
        for extra, total, count, partial, truncated, reason in cases:
            with self.subTest(extra=extra, total=total, count=count):
                payload = {**extra, "hits": {"total": total, "hits": [{"_id": str(i), "_source": {"host": "test"}} for i in range(count)]}}
                response = MagicMock()
                response.__enter__.return_value = response
                response.status = 200
                response.read.return_value = json.dumps(payload).encode()
                connector = {**CONNECTOR, "constraints": {"max_records_per_request": 2}}
                with patch("es_fetch._open_request", return_value=response):
                    rows, meta = fetch_es(connector, CREDENTIALS, {"size": 2}, {})
                self.assertEqual(len(rows), 2)
                self.assertEqual(meta["partial"], partial)
                self.assertEqual(meta["truncated"], truncated)
                self.assertTrue(meta["tls_verified"])
                if reason:
                    self.assertIn(reason, meta["incomplete_reasons"])

    def test_live_fetch_never_reaches_transport_when_verification_is_disabled(self) -> None:
        connector = json.loads(json.dumps(CONNECTOR))
        connector["config"]["tls_verify"] = False
        with patch("es_fetch._open_request") as transport:
            with self.assertRaisesRegex(ValueError, "not allowed"):
                fetch_es(connector, CREDENTIALS, {"query": {"match_all": {}}}, {})
            transport.assert_not_called()


if __name__ == "__main__":
    unittest.main()
