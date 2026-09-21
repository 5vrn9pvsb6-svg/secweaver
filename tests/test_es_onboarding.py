from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "dataasset"))

from es_onboarding import (  # noqa: E402
    ElasticsearchOnboardingError,
    ElasticsearchDiscoveryClient,
    build_es_onboarding_config,
    discover_elasticsearch,
)


class ElasticsearchOnboardingTests(unittest.TestCase):
    def test_discovery_finds_indices_fields_and_redacts_samples(self) -> None:
        def fake_request(client, method, path, body=None):  # noqa: ANN001, ARG001
            if path == "/":
                return {"cluster_name": "customer-sec", "version": {"number": "8.14.0"}}
            if path == "/_cluster/health":
                return {"status": "green"}
            if "_resolve" in path:
                return {"indices": [{"name": "logs-security-2026.07"}], "data_streams": []}
            if "_field_caps" in path:
                return {"fields": {"@timestamp": {"date": {}}, "source.ip": {"ip": {}}, "api_token": {"keyword": {}}}}
            return {"hits": {"hits": [{"_source": {"@timestamp": "2026-07-17T00:00:00Z", "source": {"ip": "192.0.2.1"}, "api_token": "secret"}}]}}

        with patch.object(ElasticsearchDiscoveryClient, "request", fake_request):
            result = discover_elasticsearch("http://127.0.0.1:9200", {"username": "reader", "password": "pw"}, index="logs-security-*")
        self.assertEqual(result["cluster"]["name"], "customer-sec")
        self.assertEqual(result["suggested_time_field"], "@timestamp")
        self.assertIn("source.ip", result["sample_fields"])
        self.assertEqual(result["sample_documents"][0]["api_token"], "[REDACTED]")

    def test_remote_plain_http_is_rejected(self) -> None:
        with self.assertRaisesRegex(ElasticsearchOnboardingError, "HTTPS"):
            discover_elasticsearch("http://es.example.com:9200")

    def test_generated_template_is_time_only(self) -> None:
        payload = {"name": "Customer ES", "endpoint": "https://es.example.com", "index": "logs-*"}
        probe = {"endpoint": payload["endpoint"], "selected_index": "logs-*", "suggested_time_field": "@timestamp", "sample_fields": ["@timestamp", "source.ip"]}
        config = build_es_onboarding_config(payload, probe, "vault://es/customer")
        source = config["data_sources"][0]
        self.assertEqual(source["template_id"], "customer-es-by-time")
        self.assertTrue(source["connector"]["config"]["tls_verify"])
        self.assertEqual(source["template"]["params"], ["time_start", "time_end", "limit"])
        self.assertEqual(source["template"]["es_query"]["query"]["bool"]["must"], [])

    def test_malformed_tls_flag_rejected_by_client_and_builder(self) -> None:
        for flag in (None, 0, 1, "false", "true", ""):
            with self.subTest(flag=flag):
                with self.assertRaisesRegex(ElasticsearchOnboardingError, "boolean"):
                    ElasticsearchDiscoveryClient("https://es.example.com", tls_verify=flag)
                with self.assertRaisesRegex(ElasticsearchOnboardingError, "boolean"):
                    build_es_onboarding_config(
                        {"endpoint": "https://es.example.com", "index": "logs-*", "tls_verify": flag},
                        {"suggested_time_field": "@timestamp"}, "vault://es/test")

    def test_builder_rejects_diagnostic_tls_opt_out_for_active_connector(self) -> None:
        with self.assertRaisesRegex(ElasticsearchOnboardingError, "require tls_verify=true"):
            build_es_onboarding_config(
                {"endpoint": "https://es.example.com", "index": "logs-*", "tls_verify": False},
                {"suggested_time_field": "@timestamp"},
                "vault://es/test",
            )


if __name__ == "__main__":
    unittest.main()
