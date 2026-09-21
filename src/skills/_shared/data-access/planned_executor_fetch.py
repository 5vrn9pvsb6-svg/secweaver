"""Local-sample or external-executor connector fetcher."""

from __future__ import annotations

from typing import Any

from connector_fetch_common import fetch_local_samples, post_json


def fetch(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    query: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    connector_type = connector.get("connector_type", "")
    config = connector.get("config") or {}
    endpoint = str(config.get("endpoint") or config.get("base_url") or "").rstrip("/")
    local_result = fetch_local_samples(connector, query, params)
    if local_result is not None:
        return local_result
    if not endpoint:
        return [], {
            "mode": "planned",
            "backend": connector_type,
            "query": query,
            "params": {k: params.get(k) for k in ("time_start", "time_end", "limit")},
            "note": "connector endpoint not configured; query rendered for external executor",
        }
    timeout = int((connector.get("constraints") or {}).get("request_timeout_sec") or 60)
    payload = {"query": query, "params": params, "config": {k: v for k, v in config.items() if "secret" not in k.lower()}}
    events, meta = post_json(
        endpoint,
        payload,
        credentials,
        timeout=timeout,
        transport_config=config,
    )
    return events, {**meta, "backend": connector_type, "query": query}
