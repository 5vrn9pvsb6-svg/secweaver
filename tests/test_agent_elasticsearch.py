"""Public self-managed ES integration contracts, without a private ES Operator."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = ROOT / "src/tools/secweaver-agent/elasticsearch"
spec = importlib.util.spec_from_file_location("public_agent_es", INTEGRATION / "init_es.py")
es = importlib.util.module_from_spec(spec)
spec.loader.exec_module(es)


class AgentElasticsearchTests(unittest.TestCase):
    def test_preview_is_offline(self):
        with patch.object(es, "Client") as client, patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(es.main([]), 0)
            body = json.loads(output.getvalue())
        client.assert_not_called()
        self.assertEqual(body["index_patterns"], [es.INDEX_PATTERN])
        self.assertEqual(body["template"]["settings"]["number_of_replicas"], 1)

    def test_create_only_template(self):
        client = Mock()
        client.request.side_effect = [{"version": {"number": "8.19.4"}}, None, {"acknowledged": True}]
        es.install(client, es.template(0))
        self.assertEqual(client.request.call_args.args[:2],
                         ("PUT", "/_index_template/secweaver-public-agent-v1?create=true"))
        self.assertEqual(client.request.call_count, 3)

    def test_idempotency_accepts_es_settings_serialization(self):
        body = es.template(1)
        current = copy.deepcopy(body)
        current["composed_of"] = []
        current["template"]["settings"] = {"index": {
            "number_of_shards": "1", "number_of_replicas": "1", "refresh_interval": "10s",
        }}
        client = Mock()
        client.request.side_effect = [
            {"version": {"number": "8.19.4"}}, {"index_templates": [{"index_template": current}]},
        ]
        self.assertIn("no write", es.install(client, body))
        self.assertEqual(client.request.call_count, 2)

    def test_drift_is_not_overwritten(self):
        client = Mock()
        client.request.side_effect = [
            {"version": {"number": "8.19.4"}},
            {"index_templates": [{"index_template": es.template(0)}]},
        ]
        with self.assertRaisesRegex(es.SetupError, "nothing overwritten"):
            es.install(client, es.template(1))
        self.assertEqual(client.request.call_count, 2)

    def test_other_engines_are_not_modified(self):
        for version in ({"number": "9.0.0"}, {"number": "2.17.0", "distribution": "opensearch"}, {}):
            with self.subTest(version=version):
                client = Mock()
                client.request.return_value = {"version": version}
                with self.assertRaises(es.SetupError):
                    es.install(client, es.template(1))
                self.assertEqual(client.request.call_count, 1)

    def test_recent_data_check_does_not_fetch_raw_logs(self):
        client = Mock()
        client.request.return_value = {"aggregations": {"datasets": {"buckets": [
            {"key": "host-process-snapshot", "doc_count": 5},
        ]}}}
        self.assertIn("host-process-snapshot", es.check(client))
        method, path, query = client.request.call_args.args
        self.assertEqual(method, "POST")
        self.assertEqual(path, "/secweaver-public-agent-*/_search")
        self.assertEqual(query["size"], 0)
        self.assertIn("@timestamp", query["query"]["range"])

    def test_empty_or_partial_data_fails(self):
        for result in ({}, {"timed_out": True}, {"_shards": {"failed": 1}}):
            with self.subTest(result=result), self.assertRaises(es.SetupError):
                client = Mock()
                client.request.return_value = result
                es.check(client)

    def test_reject_unsafe_endpoints(self):
        for endpoint in ("http://es.example.com", "https://user:pass@es.example.com",
                         "https://es.example.com/path", "https://es.example.com?token=x",
                         "https://es.example.com#fragment", "https://[broken",
                         "https://es.example.com:bad", "https://es.example.com:0"):
            with self.subTest(endpoint=endpoint), self.assertRaises(es.SetupError):
                es.Client(endpoint, "writer", "secret")

    def test_redirect_refused(self):
        with self.assertRaisesRegex(es.SetupError, "Redirect refused"):
            es.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example.com")

    def test_tls_and_bounded_response(self):
        with patch.object(es.ssl, "create_default_context") as context:
            client = es.Client("https://es.example.com", "user", "secret", "/example/ca.pem")
        context.assert_called_once_with(cafile="/example/ca.pem")
        response = Mock()
        response.read.return_value = b"x" * (es.MAX_RESPONSE + 1)
        client.opener = Mock()
        client.opener.open.return_value.__enter__ = Mock(return_value=response)
        client.opener.open.return_value.__exit__ = Mock(return_value=False)
        with self.assertRaisesRegex(es.SetupError, "exceeds"):
            client.request("GET", "/")
        response.read.assert_called_once_with(es.MAX_RESPONSE + 1)

    def test_http_failure_is_sanitized_and_not_retried(self):
        client = es.Client("https://es.example.com", "user", "secret")
        client.opener = Mock()
        client.opener.open.side_effect = urllib.error.HTTPError(
            "https://es.example.com", 403, "do-not-echo-secret", {}, None,
        )
        with self.assertRaises(es.SetupError) as error:
            client.request("PUT", "/_index_template/test", {})
        self.assertNotIn("do-not-echo-secret", str(error.exception))
        self.assertIn("403", str(error.exception))
        client.opener.open.assert_called_once()

    def test_filebeat_config_matches_public_agent_outputs(self):
        # JSON is a YAML subset; parse without adding a runtime YAML dependency.
        config = json.loads((INTEGRATION / "filebeat.yml").read_text())
        inputs = config["filebeat.inputs"]
        self.assertEqual(len(inputs), 7)
        self.assertEqual(len({entry["id"] for entry in inputs}), 7)
        sources = ROOT / "src/tools/secweaver-agent"
        agent = json.loads((sources / "config.example.json").read_text())
        expected = {agent["operations_report"]["output"], "/opt/secweaver-agent/logs/behavior-learning.log"}
        for module in ("syslog-risk-json", "host-process-snapshot", "host-state-snapshot"):
            args = agent["modules"][module]["args"]
            expected.add(args[args.index("-output") + 1])
        for module in ("audit-port-execmon", "host-persistence"):
            expected.add(json.loads((sources / f"{module}.example.json").read_text())["output_log"])
        self.assertEqual({item["paths"][0] for item in inputs}, expected)
        for item in inputs:
            self.assertIn(item["paths"][0] + ".*", item["paths"])
            self.assertNotIn("ignore_inactive", item)
        self.assertFalse(config["setup.ilm.enabled"])
        self.assertFalse(config["setup.template.enabled"])
        output = config["output.elasticsearch"]
        self.assertEqual(output["ssl.verification_mode"], "full")
        self.assertEqual(output["password"], "${SECWEAVER_ES_WRITER_PASSWORD}")
        for route in output["indices"]:
            self.assertTrue(route["index"].startswith("secweaver-public-agent-"))
        self.assertIn("host", config["processors"][0]["drop_fields"]["fields"])
        self.assertTrue(config["processors"][1]["decode_json_fields"]["overwrite_keys"])
        self.assertEqual(es.template(1)["template"]["mappings"]["properties"]["host"]["type"], "keyword")

    def test_behavior_summary_mappings_are_typed(self):
        # Aggregates must remain separate from raw process evidence and support
        # numeric count queries rather than dynamically mapped text fields.
        fields = es.template(1)["template"]["mappings"]["properties"]
        for name in ("baseline_id", "behavior_fingerprint", "summary_id", "source_event_type"):
            self.assertEqual(fields[name]["type"], "keyword")
        for name in ("observed_count", "suppressed_count", "original_emitted_count"):
            self.assertEqual(fields[name]["type"], "long")
        for name in ("counter_complete", "source_healthy", "filtering_active", "shadow"):
            self.assertEqual(fields[name]["type"], "boolean")

    def test_installer_shell_syntax(self):
        subprocess.run(["bash", "-n", str(INTEGRATION / "install-agent.sh")], check=True)

    def test_documented_asset_types_exist(self):
        evidence = json.loads((ROOT / "dataasset/configure/evidence-minimum-fields.json").read_text())
        for language in ("README.md", "README.zh-CN.md"):
            text = (INTEGRATION / language).read_text()
            for line in text.splitlines():
                cell = line.split("|")[2].strip() if line.startswith("| `secweaver-public-agent-") else ""
                if cell.startswith("`") and cell.endswith("`"):
                    asset_type = cell.strip("`")
                    self.assertIn(asset_type, evidence["by_asset_type"])

    def test_public_export_boundary(self):
        if not (ROOT / ".git").exists():
            self.skipTest("No Git metadata in a clean Community archive")
        paths = [str(path.relative_to(ROOT)) for path in INTEGRATION.iterdir() if path.is_file()]
        result = subprocess.run(["git", "check-attr", "export-ignore", "--", *paths],
                                cwd=ROOT, text=True, capture_output=True, check=True)
        self.assertTrue(all(line.endswith(": unspecified") for line in result.stdout.splitlines()))
        private = subprocess.run(["git", "check-attr", "export-ignore", "--",
                                  "src/es-operator/operator-release/README.zh-CN.md"],
                                 cwd=ROOT, text=True, capture_output=True, check=True)
        self.assertTrue(private.stdout.strip().endswith(": set"))


if __name__ == "__main__":
    unittest.main()
