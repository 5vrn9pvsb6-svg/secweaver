"""Dispatcher for non-core connector fetchers.

Core fetchers such as SLS, SSH, DB, HTTP, ES, and local_file live in their
own modules. Extension-style connector types are routed here, but each
connector implementation remains in a dedicated `*_fetch.py` file.
"""

from __future__ import annotations

from typing import Any, Callable

import aws_cloudwatch_fetch
import aws_s3_logs_fetch
import agent_stream_fetch
import azure_monitor_fetch
import clickhouse_fetch
import gcp_logging_fetch
import hive_fetch
import huawei_lts_fetch
import mongodb_fetch
import object_storage_fetch
import planned_executor_fetch
import plugin_executor_fetch
import redis_fetch
import splunk_fetch
import syslog_ingest_fetch
import tencent_cls_fetch
from connector_registry import is_external_runtime, is_plugin_runtime, query_key_by_connector, query_key_for_connector

FetchFn = Callable[[dict[str, Any], dict[str, Any], str, dict[str, Any]], tuple[list[dict[str, Any]], dict[str, Any]]]
CORE_CONNECTOR_TYPES = frozenset({"sls", "sls_proxy", "ssh_file", "ssh_command", "database_ro", "http_api", "es", "local_file"})

PLANNED_EXECUTOR_CONNECTORS = frozenset({"agent_stream", "syslog_ingest", "object_storage"})
CLOUD_LOG_CONNECTORS = frozenset(
    {
        "aws_cloudwatch",
        "aws_s3_logs",
        "azure_monitor",
        "gcp_logging",
        "tencent_cls",
        "huawei_lts",
    }
)
WAREHOUSE_CONNECTORS = frozenset({"clickhouse", "hive"})


def extended_connector_types() -> set[str]:
    return {
        connector_type
        for connector_type, query_key in query_key_by_connector().items()
        if connector_type not in CORE_CONNECTOR_TYPES and query_key
    }


def is_extended_connector(connector_type: str) -> bool:
    return connector_type in extended_connector_types()


CONNECTOR_FETCHERS: dict[str, FetchFn] = {
    "agent_stream": agent_stream_fetch.fetch,
    "aws_cloudwatch": aws_cloudwatch_fetch.fetch,
    "aws_s3_logs": aws_s3_logs_fetch.fetch,
    "azure_monitor": azure_monitor_fetch.fetch,
    "gcp_logging": gcp_logging_fetch.fetch,
    "tencent_cls": tencent_cls_fetch.fetch,
    "huawei_lts": huawei_lts_fetch.fetch,
    "object_storage": object_storage_fetch.fetch,
    "splunk": splunk_fetch.fetch,
    "syslog_ingest": syslog_ingest_fetch.fetch,
    "clickhouse": clickhouse_fetch.fetch,
    "hive": hive_fetch.fetch,
    "mongodb": mongodb_fetch.fetch,
    "redis": redis_fetch.fetch,
}


def fetch_extended_connector(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    rendered: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    connector_type = connector.get("connector_type", "")
    params = rendered.get("params") or {}
    query_key = query_key_for_connector(connector_type)
    if not query_key:
        raise NotImplementedError(f"unsupported extended connector_type={connector_type}")
    query = rendered.get(query_key)
    if not query:
        raise ValueError(f"template {rendered.get('template_id')} has no {query_key} for {connector_type}")

    fetcher = CONNECTOR_FETCHERS.get(connector_type)
    if fetcher:
        return fetcher(connector, credentials, str(query), params)
    if is_plugin_runtime(connector_type):
        return plugin_executor_fetch.fetch(connector, credentials, str(query), params)
    if connector_type in PLANNED_EXECUTOR_CONNECTORS or is_external_runtime(connector_type):
        return planned_executor_fetch.fetch(connector, credentials, str(query), params)
    raise NotImplementedError(f"live fetch not implemented for connector_type={connector_type}")
