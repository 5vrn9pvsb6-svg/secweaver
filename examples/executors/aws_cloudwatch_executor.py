#!/usr/bin/env python3
"""Optional AWS CloudWatch Logs executor for SecWeaver external connectors.

This file is intentionally outside the core runtime path. Install boto3 only in
the environment that runs this executor:

    python3 -m pip install boto3
    python3 examples/executors/aws_cloudwatch_executor.py --port 8788

Then set connector.config.endpoint to http://127.0.0.1:8788/fetch.
AWS credentials are resolved by boto3 from the usual environment, shared config,
or instance/task role chain; SecWeaver does not pass secrets in the POST body.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


def load_boto3():
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("aws_cloudwatch_executor requires optional dependency: pip install boto3") from exc
    return boto3


def parse_limit(params: dict[str, Any], config: dict[str, Any]) -> int:
    raw = params.get("limit") or config.get("limit") or 100
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        limit = 100
    return max(1, min(limit, int(config.get("max_limit") or 1000)))


def normalize_log_event(event: dict[str, Any]) -> dict[str, Any]:
    row = {
        "@timestamp": event.get("timestamp"),
        "@message": event.get("message"),
        "_event_id": event.get("eventId"),
        "_ingestion_time": event.get("ingestionTime"),
        "_log_stream": event.get("logStreamName"),
    }
    message = event.get("message")
    if isinstance(message, str):
        try:
            parsed = json.loads(message)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            row.update(parsed)
    return {key: value for key, value in row.items() if value is not None}


def normalize_insights_row(row: list[dict[str, Any]]) -> dict[str, Any]:
    event: dict[str, Any] = {}
    for item in row:
        field = item.get("field")
        if field:
            event[str(field)] = item.get("value")
    message = event.get("@message")
    if isinstance(message, str):
        try:
            parsed = json.loads(message)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            event.update(parsed)
    return event


def fetch_cloudwatch_logs(payload: dict[str, Any]) -> dict[str, Any]:
    boto3 = load_boto3()
    query = str(payload.get("query") or "").strip()
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    config = payload.get("config") if isinstance(payload.get("config"), dict) else {}
    region = str(config.get("region") or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "").strip()
    log_group = str(config.get("log_group") or "").strip()
    if not region:
        raise ValueError("config.region or AWS_REGION is required")
    if not log_group:
        raise ValueError("config.log_group is required")
    if not query:
        raise ValueError("payload.query is required")

    session_kwargs: dict[str, Any] = {"region_name": region}
    if config.get("profile"):
        session_kwargs["profile_name"] = str(config["profile"])
    logs = boto3.Session(**session_kwargs).client("logs")

    now = int(time.time())
    request: dict[str, Any] = {
        "logGroupName": log_group,
        "queryString": query,
        "startTime": int(_parse_epoch_seconds(params.get("time_start") or now - 3600)),
        "endTime": int(_parse_epoch_seconds(params.get("time_end") or now)),
        "limit": parse_limit(params, config),
    }

    query_id = logs.start_query(**request)["queryId"]
    deadline = time.monotonic() + int(config.get("query_timeout_sec") or 30)
    response: dict[str, Any] = {"status": "Scheduled", "results": []}
    while time.monotonic() < deadline:
        response = logs.get_query_results(queryId=query_id)
        if response.get("status") in {"Complete", "Failed", "Cancelled", "Timeout"}:
            break
        time.sleep(float(config.get("poll_interval_sec") or 1.0))
    if response.get("status") != "Complete":
        raise RuntimeError(f"CloudWatch Logs Insights query did not complete: {response.get('status')}")

    events = [normalize_insights_row(row) for row in response.get("results", [])]
    return {
        "events": events,
        "meta": {
            "backend": "aws_cloudwatch",
            "region": region,
            "log_group": log_group,
            "query_id": query_id,
            "status": response.get("status"),
            "rows_returned": len(events),
        },
    }


def _parse_epoch_seconds(value: Any) -> int:
    from datetime import datetime

    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    normalized = text.replace("Z", "+00:00")
    return int(datetime.fromisoformat(normalized).timestamp())


class ExecutorHandler(BaseHTTPRequestHandler):
    server_version = "SecWeaverCloudWatchExecutor/1.0"

    def do_POST(self) -> None:
        if self.path not in {"/fetch", "/"}:
            self._write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            result = fetch_cloudwatch_logs(payload)
        except Exception as exc:  # noqa: BLE001 - return a clear executor error to SecWeaver.
            self._write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self._write_json(result, HTTPStatus.OK)

    def log_message(self, fmt: str, *args: Any) -> None:
        if not getattr(self.server, "quiet", False):
            super().log_message(fmt, *args)

    def _write_json(self, payload: dict[str, Any], status: HTTPStatus) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the optional SecWeaver AWS CloudWatch Logs executor.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8788)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer((args.host, args.port), ExecutorHandler)
    server.quiet = args.quiet  # type: ignore[attr-defined]
    print(f"aws_cloudwatch executor listening on http://{args.host}:{args.port}/fetch")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
