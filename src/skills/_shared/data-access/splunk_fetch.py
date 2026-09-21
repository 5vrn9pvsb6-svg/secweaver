"""Splunk connector fetcher."""

from __future__ import annotations

from typing import Any

from connector_fetch_common import post_json, request_timeout


def fetch(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    search: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    config = connector.get("config") or {}
    base_url = str(config.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("splunk connector config requires base_url")
    timeout = request_timeout(connector)
    index = config.get("index")
    query = search if search.lstrip().startswith("search ") else f"search {search}"
    if index and "index=" not in query:
        query = f"search index={index} {query.removeprefix('search ').strip()}"
    payload = {
        "search": query,
        "exec_mode": "oneshot",
        "output_mode": "json",
        "earliest_time": params.get("time_start"),
        "latest_time": params.get("time_end"),
    }
    events, meta = post_json(
        f"{base_url}/services/search/jobs/export",
        payload,
        credentials,
        timeout=timeout,
        transport_config=config,
        label="splunk base_url",
    )
    return events, {**meta, "backend": "splunk", "search": query}
