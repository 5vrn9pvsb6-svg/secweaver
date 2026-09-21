"""Unit tests for built-in cloud vendor connector fetchers."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import aws_common_fetch  # noqa: E402
import aws_cloudwatch_fetch  # noqa: E402
import aws_s3_logs_fetch  # noqa: E402
import azure_monitor_fetch  # noqa: E402
import extended_fetch  # noqa: E402
import gcp_logging_fetch  # noqa: E402
import huawei_lts_fetch  # noqa: E402
import tencent_cls_fetch  # noqa: E402


class TestCloudVendorFetchers(unittest.TestCase):
    def test_aws_cloudwatch_uses_live_api_when_credentials_exist(self) -> None:
        calls: list[str] = []
        original = aws_common_fetch.aws_json_request
        original_boto3 = aws_cloudwatch_fetch._load_boto3

        def fake_aws_json_request(*args, **kwargs):
            calls.append(kwargs["target"])
            if kwargs["target"].endswith("StartQuery"):
                self.assertEqual(kwargs["payload"]["logGroupName"], "/aws/cloudtrail")
                self.assertEqual(kwargs["payload"]["queryString"], "fields @timestamp, @message | limit 10")
                return {"queryId": "query-1"}
            return {
                "status": "Complete",
                "results": [
                    [
                        {"field": "@timestamp", "value": "2026-06-21T00:00:00Z"},
                        {"field": "@message", "value": json.dumps({"src_ip": "203.0.113.10", "eventName": "ConsoleLogin"})},
                    ]
                ],
            }

        aws_common_fetch.aws_json_request = fake_aws_json_request
        aws_cloudwatch_fetch._load_boto3 = lambda: None
        try:
            events, meta = extended_fetch.fetch_extended_connector(
                {
                    "connector_id": "conn-aws-cloudwatch",
                    "connector_type": "aws_cloudwatch",
                    "config": {"region": "ap-southeast-1", "log_group": "/aws/cloudtrail"},
                },
                {"access_key_id": "AKIA_TEST", "secret_access_key": "secret"},
                {
                    "template_id": "cloudwatch-test",
                    "cloudwatch_query": "fields @timestamp, @message | limit 10",
                    "params": {"limit": 10, "time_start": "2026-06-21T00:00:00Z", "time_end": "2026-06-21T01:00:00Z"},
                },
            )
        finally:
            aws_common_fetch.aws_json_request = original
            aws_cloudwatch_fetch._load_boto3 = original_boto3

        self.assertEqual(calls, ["Logs_20140328.StartQuery", "Logs_20140328.GetQueryResults"])
        self.assertEqual(meta["mode"], "live")
        self.assertEqual(meta["backend"], "aws_cloudwatch")
        self.assertEqual(meta["sdk"], "rest_sigv4")
        self.assertEqual(events[0]["src_ip"], "203.0.113.10")

    def test_aws_cloudwatch_prefers_boto3_when_available(self) -> None:
        original_boto3 = aws_cloudwatch_fetch._load_boto3

        class FakeLogsClient:
            def __init__(self) -> None:
                self.start_payload = None

            def start_query(self, **payload):
                self.start_payload = payload
                return {"queryId": "query-sdk"}

            def get_query_results(self, **_payload):
                return {
                    "status": "Complete",
                    "results": [
                        [
                            {"field": "@timestamp", "value": "2026-06-21T00:00:00Z"},
                            {"field": "@message", "value": json.dumps({"src_ip": "203.0.113.10", "eventName": "ConsoleLogin"})},
                        ]
                    ],
                }

        fake_client = FakeLogsClient()

        class FakeBoto3:
            @staticmethod
            def client(service, **kwargs):
                self.assertEqual(service, "logs")
                self.assertEqual(kwargs["region_name"], "ap-southeast-1")
                self.assertEqual(kwargs["aws_access_key_id"], "AKIA_TEST")
                return fake_client

        aws_cloudwatch_fetch._load_boto3 = lambda: FakeBoto3
        try:
            events, meta = extended_fetch.fetch_extended_connector(
                {
                    "connector_id": "conn-aws-cloudwatch",
                    "connector_type": "aws_cloudwatch",
                    "config": {"region": "ap-southeast-1", "log_group": "/aws/cloudtrail"},
                },
                {"access_key_id": "AKIA_TEST", "secret_access_key": "secret"},
                {
                    "template_id": "cloudwatch-test",
                    "cloudwatch_query": "fields @timestamp, @message | limit 10",
                    "params": {"limit": 10, "time_start": "2026-06-21T00:00:00Z", "time_end": "2026-06-21T01:00:00Z"},
                },
            )
        finally:
            aws_cloudwatch_fetch._load_boto3 = original_boto3

        self.assertEqual(fake_client.start_payload["logGroupName"], "/aws/cloudtrail")
        self.assertEqual(meta["sdk"], "boto3")
        self.assertEqual(meta["query_id"], "query-sdk")
        self.assertEqual(events[0]["src_ip"], "203.0.113.10")

    def test_aws_s3_logs_lists_and_reads_objects(self) -> None:
        original = aws_common_fetch.aws_raw_request
        original_boto3 = aws_s3_logs_fetch._load_boto3

        def fake_aws_raw_request(url, **_kwargs):
            if "list-type=2" in url:
                return 200, b"""<ListBucketResult><Contents><Key>AWSLogs/app.jsonl</Key></Contents></ListBucketResult>"""
            return 200, (json.dumps({"src_ip": "203.0.113.10", "action": "allow"}) + "\n").encode("utf-8")

        aws_common_fetch.aws_raw_request = fake_aws_raw_request
        aws_s3_logs_fetch._load_boto3 = lambda: None
        try:
            events, meta = extended_fetch.fetch_extended_connector(
                {
                    "connector_id": "conn-aws-s3",
                    "connector_type": "aws_s3_logs",
                    "config": {"bucket": "security-logs", "prefix": "AWSLogs/", "region": "ap-southeast-1"},
                },
                {"access_key_id": "AKIA_TEST", "secret_access_key": "secret"},
                {
                    "template_id": "s3-test",
                    "object_query": "src_ip=203.0.113.10",
                    "params": {"src_ip": "203.0.113.10", "limit": 10},
                },
            )
        finally:
            aws_common_fetch.aws_raw_request = original
            aws_s3_logs_fetch._load_boto3 = original_boto3

        self.assertEqual(meta["mode"], "live")
        self.assertEqual(meta["backend"], "aws_s3_logs")
        self.assertEqual(meta["sdk"], "rest_sigv4")
        self.assertEqual(meta["objects_scanned"], 1)
        self.assertEqual(events[0]["_s3_key"], "AWSLogs/app.jsonl")

    def test_aws_s3_logs_prefers_boto3_when_available(self) -> None:
        original_boto3 = aws_s3_logs_fetch._load_boto3

        class FakeBody:
            def read(self):
                return (json.dumps({"src_ip": "203.0.113.10", "action": "allow"}) + "\n").encode("utf-8")

        class FakeS3Client:
            def list_objects_v2(self, **payload):
                self.list_payload = payload
                return {"Contents": [{"Key": "AWSLogs/app.jsonl"}]}

            def get_object(self, **payload):
                self.get_payload = payload
                return {"Body": FakeBody()}

        fake_client = FakeS3Client()

        class FakeBoto3:
            @staticmethod
            def client(service, **kwargs):
                self.assertEqual(service, "s3")
                self.assertEqual(kwargs["region_name"], "ap-southeast-1")
                return fake_client

        aws_s3_logs_fetch._load_boto3 = lambda: FakeBoto3
        try:
            events, meta = extended_fetch.fetch_extended_connector(
                {
                    "connector_id": "conn-aws-s3",
                    "connector_type": "aws_s3_logs",
                    "config": {"bucket": "security-logs", "prefix": "AWSLogs/", "region": "ap-southeast-1"},
                },
                {"access_key_id": "AKIA_TEST", "secret_access_key": "secret"},
                {
                    "template_id": "s3-test",
                    "object_query": "src_ip=203.0.113.10",
                    "params": {"src_ip": "203.0.113.10", "limit": 10},
                },
            )
        finally:
            aws_s3_logs_fetch._load_boto3 = original_boto3

        self.assertEqual(fake_client.list_payload["Bucket"], "security-logs")
        self.assertEqual(fake_client.get_payload["Key"], "AWSLogs/app.jsonl")
        self.assertEqual(meta["sdk"], "boto3")
        self.assertEqual(events[0]["_s3_key"], "AWSLogs/app.jsonl")

    def test_azure_monitor_parses_log_analytics_tables(self) -> None:
        original_token = azure_monitor_fetch.azure_access_token
        original_http = azure_monitor_fetch.http_json_request
        captured: dict[str, object] = {}

        def fake_token(_config, _credentials, _timeout):
            return "azure-token"

        def fake_http(url, payload=None, **kwargs):
            captured["url"] = url
            captured["payload"] = payload
            captured["headers"] = kwargs["headers"]
            return {
                "tables": [
                    {
                        "columns": [{"name": "TimeGenerated"}, {"name": "SrcIpAddr"}],
                        "rows": [["2026-06-21T00:00:00Z", "203.0.113.10"]],
                    }
                ]
            }, 200

        azure_monitor_fetch.azure_access_token = fake_token
        azure_monitor_fetch.http_json_request = fake_http
        try:
            events, meta = extended_fetch.fetch_extended_connector(
                {
                    "connector_id": "conn-azure",
                    "connector_type": "azure_monitor",
                    "config": {"workspace_id": "workspace-1"},
                },
                {"client_id": "client", "client_secret": "secret", "tenant_id": "tenant"},
                {
                    "template_id": "azure-test",
                    "kql": "SigninLogs | take 10",
                    "params": {"limit": 10},
                },
            )
        finally:
            azure_monitor_fetch.azure_access_token = original_token
            azure_monitor_fetch.http_json_request = original_http

        self.assertIn("workspace-1", str(captured["url"]))
        self.assertEqual(captured["headers"], {"Authorization": "Bearer azure-token"})
        self.assertEqual(meta["mode"], "live")
        self.assertEqual(events[0]["SrcIpAddr"], "203.0.113.10")

    def test_gcp_logging_parses_entries(self) -> None:
        original_token = gcp_logging_fetch.gcp_access_token
        original_http = gcp_logging_fetch.http_json_request

        def fake_token(_config, _credentials):
            return "gcp-token"

        def fake_http(_url, payload=None, **_kwargs):
            self.assertEqual(payload["resourceNames"], ["projects/demo-project"])
            return {
                "entries": [
                    {
                        "timestamp": "2026-06-21T00:00:00Z",
                        "severity": "NOTICE",
                        "jsonPayload": {"src_ip": "203.0.113.10", "action": "allow"},
                    }
                ]
            }, 200

        gcp_logging_fetch.gcp_access_token = fake_token
        gcp_logging_fetch.http_json_request = fake_http
        try:
            events, meta = extended_fetch.fetch_extended_connector(
                {
                    "connector_id": "conn-gcp",
                    "connector_type": "gcp_logging",
                    "config": {"project_id": "demo-project"},
                },
                {"access_token": "token"},
                {
                    "template_id": "gcp-test",
                    "gcp_logging_filter": 'jsonPayload.src_ip="203.0.113.10"',
                    "params": {"limit": 10},
                },
            )
        finally:
            gcp_logging_fetch.gcp_access_token = original_token
            gcp_logging_fetch.http_json_request = original_http

        self.assertEqual(meta["mode"], "live")
        self.assertEqual(events[0]["src_ip"], "203.0.113.10")
        self.assertEqual(events[0]["severity"], "NOTICE")

    def test_tencent_cls_posts_signed_live_request(self) -> None:
        original_http = tencent_cls_fetch.http_request
        captured: dict[str, object] = {}

        def fake_http(url, **kwargs):
            captured["url"] = url
            captured["headers"] = kwargs["headers"]
            captured["body"] = json.loads(kwargs["body"].decode("utf-8"))
            return 200, json.dumps(
                {
                    "Response": {
                        "RequestId": "req-1",
                        "Results": [{"LogJson": json.dumps({"src_ip": "203.0.113.10", "action": "block"})}],
                    }
                }
            ).encode("utf-8")

        tencent_cls_fetch.http_request = fake_http
        try:
            events, meta = extended_fetch.fetch_extended_connector(
                {
                    "connector_id": "conn-tencent",
                    "connector_type": "tencent_cls",
                    "config": {"endpoint": "cls.tencentcloudapi.com", "region": "ap-guangzhou", "topic_id": "topic-1"},
                },
                {"secret_id": "id", "secret_key": "key"},
                {
                    "template_id": "tencent-test",
                    "cls_query": "src_ip:203.0.113.10",
                    "params": {"limit": 10},
                },
            )
        finally:
            tencent_cls_fetch.http_request = original_http

        self.assertEqual(captured["url"], "https://cls.tencentcloudapi.com/")
        self.assertIn("Authorization", captured["headers"])
        self.assertEqual(captured["body"]["TopicId"], "topic-1")
        self.assertEqual(meta["request_id"], "req-1")
        self.assertEqual(events[0]["src_ip"], "203.0.113.10")

    def test_huawei_lts_posts_live_request_with_token(self) -> None:
        original_http = huawei_lts_fetch.http_request
        captured: dict[str, object] = {}

        def fake_http(url, **kwargs):
            captured["url"] = url
            captured["headers"] = kwargs["headers"]
            captured["body"] = json.loads(kwargs["body"].decode("utf-8"))
            return 200, json.dumps({"logs": [{"content": json.dumps({"src_ip": "203.0.113.10", "event": "deny"})}]}).encode("utf-8")

        huawei_lts_fetch.http_request = fake_http
        try:
            events, meta = extended_fetch.fetch_extended_connector(
                {
                    "connector_id": "conn-huawei",
                    "connector_type": "huawei_lts",
                    "config": {
                        "endpoint": "https://lts.cn-north-4.myhuaweicloud.com",
                        "project_id": "project-1",
                        "log_group_id": "group-1",
                        "log_stream_id": "stream-1",
                    },
                },
                {"token": "huawei-token"},
                {
                    "template_id": "huawei-test",
                    "lts_query": "src_ip:203.0.113.10",
                    "params": {"limit": 10},
                },
            )
        finally:
            huawei_lts_fetch.http_request = original_http

        self.assertIn("/project-1/", captured["url"])
        self.assertEqual(captured["headers"]["X-Auth-Token"], "huawei-token")
        self.assertEqual(captured["body"]["keywords"], "src_ip:203.0.113.10")
        self.assertEqual(meta["mode"], "live")
        self.assertEqual(events[0]["src_ip"], "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
