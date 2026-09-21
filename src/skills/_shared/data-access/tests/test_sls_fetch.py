"""Tests for SLS structured and raw-payload parsing boundaries."""

from __future__ import annotations

import sys
import json
import ssl
from urllib.error import URLError
import types
import unittest
from pathlib import Path
from unittest.mock import patch

DATA_ACCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DATA_ACCESS))

from sls_fetch import _configure_sdk_endpoint, _postprocess_events, _project_proxy_client, fetch  # noqa: E402
from sls_proxy_config import proxy_project  # noqa: E402
import sls_proxy_fetch  # noqa: E402
from sls_proxy_fetch import fetch as fetch_proxy  # noqa: E402


class SlsPostprocessTests(unittest.TestCase):
    def test_local_ip_endpoint_uses_sdk_path_routing(self) -> None:
        client = types.SimpleNamespace(_isRowIp=False)

        _configure_sdk_endpoint(client, "http://127.0.0.1:8787")

        self.assertTrue(client._isRowIp)

    def test_https_dns_endpoint_keeps_sdk_routing_default(self) -> None:
        client = types.SimpleNamespace(_isRowIp=False)

        _configure_sdk_endpoint(client, "https://sls-proxy.id-net.cn")

        self.assertFalse(client._isRowIp)

    def test_proxy_endpoint_forces_direct_host_routing(self) -> None:
        client = types.SimpleNamespace(_isRowIp=False, _logHost="sls-proxy.id-net.cn")

        _configure_sdk_endpoint(
            client,
            "https://sls-proxy.id-net.cn",
            force_direct_host=True,
        )

        self.assertTrue(client._isRowIp)

    def test_proxy_non_default_port_is_preserved_in_sdk_host(self) -> None:
        client = types.SimpleNamespace(_isRowIp=False, _logHost="sls-proxy.id-net.cn")

        _configure_sdk_endpoint(
            client,
            "https://sls-proxy.id-net.cn:30443",
            force_direct_host=True,
        )

        self.assertTrue(client._isRowIp)
        self.assertEqual(client._logHost, "sls-proxy.id-net.cn:30443")

    def test_structured_sls_row_does_not_run_text_parser(self) -> None:
        asset = {
            "asset_type": "host_exec",
            "text_parser": "json_lines",
            "schema": {"fields": ["event_type", "command", "host_ip"]},
        }
        row = {
            "event_type": "exec",
            "command": "id",
            "host_ip": "192.0.2.10",
            "message": '{"event_type":"wrong"}',
        }
        self.assertEqual(_postprocess_events([row], asset), [row])

    def test_raw_json_payload_is_parsed_when_structured_fields_are_absent(self) -> None:
        asset = {
            "asset_type": "host_exec",
            "text_parser": "json_lines",
            "schema": {"fields": ["event_type", "command", "host_ip"]},
        }
        result = _postprocess_events(
            [{"__source__": "192.0.2.10", "content": '{"event_type":"exec","command":"id"}'}],
            asset,
        )
        self.assertEqual(result[0]["event_type"], "exec")
        self.assertEqual(result[0]["command"], "id")

    def test_raw_nginx_payload_uses_declared_parser(self) -> None:
        asset = {
            "asset_type": "web_access_log",
            "text_parser": "nginx_combined",
            "schema": {"fields": ["remote_addr", "request_uri"]},
        }
        line = '203.0.113.9 - - [12/Jul/2026:10:00:00 +0800] "GET /health HTTP/1.1" 200 12 "-" "curl/8"'
        result = _postprocess_events([{"__line__": line}], asset)
        self.assertEqual(result[0]["src_ip"], "203.0.113.9")
        self.assertEqual(result[0]["url"], "/health")

    def test_proxy_connector_uses_internal_logical_project(self) -> None:
        captured: dict[str, object] = {}

        class FakeRequest:
            def __init__(self, *args: object, **kwargs: object) -> None:
                captured["request_args"] = args
                captured["request_kwargs"] = kwargs

        class FakeResponse:
            @staticmethod
            def get_logs() -> list[object]:
                return [
                    types.SimpleNamespace(
                        contents={"message": "ok"},
                        source="",
                        topic="",
                        timestamp=1783785600,
                    )
                ]

        class FakeClient:
            def __init__(self, *args: object) -> None:
                captured["client_args"] = args
                self._session = types.SimpleNamespace(verify=True)

            def get_logs(self, request: object) -> FakeResponse:
                captured["request"] = request
                captured["tls_verify"] = self._session.verify
                return FakeResponse()

        fake_module = types.ModuleType("aliyun.log")
        fake_module.GetLogsRequest = FakeRequest
        fake_module.LogClient = FakeClient
        with patch.dict(sys.modules, {"aliyun.log": fake_module}):
            events, meta = fetch_proxy(
                {},
                {
                    "connector_type": "sls_proxy",
                    "config": {
                        "endpoint": "https://sls-proxy.id-net.cn",
                        "logstore": "host-events",
                    }
                },
                {
                    "type": "aliyun_ram",
                    "access_key_id": "SWAK_TEST",
                    "access_key_secret": "proxy-secret",
                },
                "level:error",
                {
                    "time_start": "2026-07-12T00:00:00+08:00",
                    "time_end": "2026-07-12T00:01:00+08:00",
                    "limit": 1,
                },
            )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["message"], "ok")
        self.assertNotIn("timestamp", events[0])
        self.assertTrue(events[0]["_sls_timestamp"].endswith("+00:00"))
        self.assertEqual(meta["rows_returned"], 1)
        self.assertTrue(meta["truncated"])
        self.assertEqual(
            captured["client_args"],
            ("https://sls-proxy.id-net.cn", "SWAK_TEST", "proxy-secret", None),
        )
        self.assertTrue(captured["tls_verify"])
        self.assertEqual(captured["request_args"][:2], ("", "host-events"))

    def test_proxy_connector_can_require_tls_verification(self) -> None:
        captured: dict[str, object] = {}

        class FakeRequest:
            def __init__(self, *args: object, **kwargs: object) -> None:
                captured["request_args"] = args

        class FakeResponse:
            @staticmethod
            def get_logs() -> list[object]:
                return []

        class FakeClient:
            def __init__(self, *args: object) -> None:
                self._session = types.SimpleNamespace(verify=False)

            def get_logs(self, request: object) -> FakeResponse:
                captured["tls_verify"] = self._session.verify
                return FakeResponse()

        fake_module = types.ModuleType("aliyun.log")
        fake_module.GetLogsRequest = FakeRequest
        fake_module.LogClient = FakeClient
        with patch.dict(sys.modules, {"aliyun.log": fake_module}):
            fetch_proxy(
                {},
                {
                    "connector_type": "sls_proxy",
                    "config": {
                        "endpoint": "https://sls-proxy.id-net.cn",
                        "logstore": "host-events",
                        "tls_verify": True,
                    },
                },
                {
                    "type": "aliyun_ram",
                    "access_key_id": "SWAK_TEST",
                    "access_key_secret": "proxy-secret",
                },
                "*",
                {
                    "time_start": "2026-07-12T00:00:00+08:00",
                    "time_end": "2026-07-12T00:01:00+08:00",
                    "limit": 1,
                },
            )
        self.assertTrue(captured["tls_verify"])

    def test_proxy_connector_uses_fallback_when_primary_probe_fails(self) -> None:
        connector = {
            "connector_type": "sls_proxy",
            "config": {
                "endpoint": "https://sls-proxy.id-net.cn",
                "fallback_endpoint": "https://sls-proxy.id-net.cn:30443",
                "logstore": "host-events",
            },
        }
        calls: list[str] = []

        def fake_fetch(
            asset: dict[str, object],
            selected: dict[str, object],
            credentials: dict[str, object],
            query: str,
            params: dict[str, object],
        ) -> tuple[list[dict[str, object]], dict[str, object]]:
            endpoint = str(selected["config"]["endpoint"])
            calls.append(endpoint)
            return [{"message": "ok"}], {"rows_returned": 1}

        with (
            patch.object(
                sls_proxy_fetch,
                "_endpoint_available",
                side_effect=lambda endpoint, **_: endpoint.endswith(":30443"),
            ),
            patch.object(sls_proxy_fetch, "fetch_sls", side_effect=fake_fetch),
        ):
            events, meta = fetch_proxy({}, connector, {}, "*", {})

        self.assertEqual(events, [{"message": "ok"}])
        self.assertEqual(calls, ["https://sls-proxy.id-net.cn:30443"])
        self.assertEqual(meta["endpoint_used"], "https://sls-proxy.id-net.cn:30443")
        self.assertTrue(meta["fallback_used"])

    def test_proxy_connector_does_not_fallback_on_authentication_error(self) -> None:
        connector = {
            "connector_type": "sls_proxy",
            "config": {
                "endpoint": "https://sls-proxy.id-net.cn",
                "fallback_endpoint": "https://sls-proxy.id-net.cn:30443",
                "logstore": "host-events",
            },
        }
        with (
            patch.object(sls_proxy_fetch, "_endpoint_available", return_value=True),
            patch.object(sls_proxy_fetch, "fetch_sls", side_effect=RuntimeError("401 Unauthorized")) as mocked,
            self.assertRaisesRegex(RuntimeError, "401 Unauthorized"),
        ):
            fetch_proxy({}, connector, {}, "*", {})

        self.assertEqual(mocked.call_count, 1)

    def test_proxy_connector_falls_back_on_route_not_found(self) -> None:
        connector = {
            "connector_type": "sls_proxy",
            "config": {
                "endpoint": "https://sls-proxy.id-net.cn",
                "fallback_endpoint": "https://sls-proxy.id-net.cn:30443",
                "logstore": "host-events",
            },
        }
        with (
            patch.object(sls_proxy_fetch, "_endpoint_available", return_value=True),
            patch.object(
                sls_proxy_fetch,
                "fetch_sls",
                side_effect=[RuntimeError("404 Route Not Found"), ([{"message": "ok"}], {})],
            ) as mocked,
        ):
            events, meta = fetch_proxy({}, connector, {}, "*", {})

        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(events, [{"message": "ok"}])
        self.assertTrue(meta["fallback_used"])

    def test_proxy_connector_rejects_server_managed_fields(self) -> None:
        for field in ("region", "enterprise_id"):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "server-managed"):
                fetch_proxy(
                    {},
                    {
                        "connector_type": "sls_proxy",
                        "config": {
                            "endpoint": "https://sls-proxy.id-net.cn",
                            "logstore": "host-events",
                            field: "must-not-be-client-controlled",
                        },
                    },
                    {
                        "type": "aliyun_ram",
                        "access_key_id": "SWAK_TEST",
                        "access_key_secret": "proxy-secret",
                    },
                    "*",
                    {},
                )

    def test_public_schema_matches_project_runtime_contract(self) -> None:
        from jsonschema import Draft202012Validator
        root = DATA_ACCESS.parents[3]
        schema = json.loads((root / "dataasset/schema/data-connector.schema.json").read_text())
        sample = json.loads((root / "dataasset/connectors/conn-sls-proxy-demo.json").read_text())
        validator = Draft202012Validator(schema)
        for value in ("", "wis-log", "tigersec-uni-log", "A_1", "a" * 128):
            with self.subTest(value=value):
                sample["config"]["project"] = value
                self.assertEqual(list(validator.iter_errors(sample)), [])
                self.assertEqual(proxy_project(sample["config"]), value)
        for value in (None, 0, "../other", "x/y", "a\n", "a" * 129):
            with self.subTest(value=value):
                sample["config"]["project"] = value
                self.assertTrue(list(validator.iter_errors(sample)))

    def test_proxy_bad_tls_flag_fails_before_network(self) -> None:
        for value in (None, 0, 1, "false", "true", "", []):
            with self.subTest(value=value), patch.object(sls_proxy_fetch, "fetch_sls") as query:
                with self.assertRaisesRegex(ValueError, "boolean"):
                    fetch_proxy({}, {"config": {"endpoint": "https://proxy.example", "tls_verify": value}}, {}, "*", {})
                query.assert_not_called()

    def test_proxy_certificate_failure_never_falls_back(self) -> None:
        connector = {"connector_type": "sls_proxy", "config": {
            "endpoint": "https://primary.example", "fallback_endpoint": "https://backup.example", "logstore": "events"}}
        with patch.object(sls_proxy_fetch, "urlopen", side_effect=URLError(ssl.SSLCertVerificationError("bad certificate"))), patch.object(sls_proxy_fetch, "fetch_sls") as query:
            with self.assertRaises(URLError):
                fetch_proxy({}, connector, {}, "*", {})
            query.assert_not_called()
        with patch.object(sls_proxy_fetch, "_endpoint_available", return_value=True), patch.object(sls_proxy_fetch, "fetch_sls", side_effect=RuntimeError("Max retries exceeded SSLError CERTIFICATE_VERIFY_FAILED")) as query:
            with self.assertRaises(RuntimeError):
                fetch_proxy({}, connector, {}, "*", {})
            self.assertEqual(query.call_count, 1)

    def test_proxy_project_validation_and_forwarding(self) -> None:
        for value in (None, 12, [], "../other", "x/y", " a", "a\n", "a" * 129, "https://evil"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                proxy_project({"project": value})
        self.assertEqual(proxy_project({}), "")
        connector = {"connector_type": "sls_proxy", "config": {"endpoint": "https://proxy.example:30443", "project": "wis-log", "logstore": "gateway_plugin_log"}}
        with patch.object(sls_proxy_fetch, "fetch_sls", return_value=([], {})) as mock:
            _, meta = fetch_proxy({}, connector, {}, "*", {})
        self.assertEqual(mock.call_args.args[1]["config"]["project"], "wis-log")
        self.assertEqual(meta["project"], "wis-log")
        self.assertEqual(meta["logstore"], "gateway_plugin_log")

    def test_project_is_added_before_sdk_signing_without_host_rewrite(self) -> None:
        # Exercise the real SDK signing boundary without network access. Two
        # per-instance selectors must not mutate caller params or each other.
        from aliyun.log import LogClient
        captures = []
        def capture(self, method, url, params, body, headers, *args, **kwargs):
            captures.append((url, dict(params), dict(headers)))
            return {}, {}
        original = {"from": "1", "to": "2", "type": "log"}
        with patch.object(LogClient, "_sendRequest", capture):
            for project in ("tigersec-uni-log", "wis-log"):
                client = _project_proxy_client(LogClient, project)("https://proxy.example:30443", "SWAKTEST", "synthetic-secret")
                _configure_sdk_endpoint(client, "https://proxy.example:30443", force_direct_host=True)
                client._send("GET", "", None, "/logstores/events", original, {})
        self.assertNotIn("project", original)
        for captured, project in zip(captures, ("tigersec-uni-log", "wis-log")):
            self.assertEqual(captured[0], "https://proxy.example:30443/logstores/events")
            self.assertEqual(captured[1]["project"], project)
            self.assertEqual(captured[2]["Host"], "proxy.example:30443")
        self.assertNotEqual(captures[0][2]["Authorization"], captures[1][2]["Authorization"])


if __name__ == "__main__":
    unittest.main()
