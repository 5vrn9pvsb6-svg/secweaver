"""Redis connector fetcher."""

from __future__ import annotations

import json
from typing import Any

from connector_fetch_common import max_rows, request_timeout

READ_ONLY_COMMANDS = frozenset({"GET", "MGET", "HGETALL", "LRANGE", "ZRANGE", "SCAN"})


def _load_redis():
    try:
        import redis
    except ImportError as exc:
        raise RuntimeError("live Redis fetch requires: pip install redis") from exc
    return redis


def _parse_query(query: str) -> dict[str, Any]:
    try:
        payload = json.loads(query)
    except json.JSONDecodeError as exc:
        raise ValueError("redis redis_query must be a JSON object") from exc
    if not isinstance(payload, dict):
        raise ValueError("redis redis_query must be a JSON object")
    command = str(payload.get("command") or "").upper()
    if command not in READ_ONLY_COMMANDS:
        raise ValueError(f"redis command must be read-only, got {command!r}")
    payload["command"] = command
    return payload


def _client(config: dict[str, Any], credentials: dict[str, Any], timeout: int, redis_module: Any) -> Any:
    password = credentials.get("password") or credentials.get("token") or None
    username = credentials.get("username") or credentials.get("user") or None
    return redis_module.Redis(
        host=config.get("host") or "127.0.0.1",
        port=int(config.get("port") or 6379),
        db=int(config.get("db") or config.get("database") or 0),
        username=username,
        password=password,
        ssl=bool(config.get("ssl")),
        socket_timeout=timeout,
        decode_responses=True,
    )


def _row(key: str, value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {"key": key, **value}
    return {"key": key, "value": value}


def fetch(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    query: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    redis_module = _load_redis()
    config = connector.get("config") or {}
    spec = _parse_query(query)
    timeout = request_timeout(connector)
    limit = min(int(spec.get("limit") or max_rows(connector, params)), max_rows(connector, params))
    client = _client(config, credentials, timeout, redis_module)
    command = spec["command"]
    events: list[dict[str, Any]]
    if command == "GET":
        key = str(spec["key"])
        events = [_row(key, client.get(key))]
    elif command == "MGET":
        keys = [str(item) for item in spec.get("keys") or []][:limit]
        events = [_row(key, value) for key, value in zip(keys, client.mget(keys), strict=False)]
    elif command == "HGETALL":
        key = str(spec["key"])
        events = [_row(key, client.hgetall(key))]
    elif command == "LRANGE":
        key = str(spec["key"])
        start = int(spec.get("start") or 0)
        end = int(spec.get("end") if spec.get("end") is not None else limit - 1)
        events = [{"key": key, "index": start + idx, "value": value} for idx, value in enumerate(client.lrange(key, start, end)[:limit])]
    elif command == "ZRANGE":
        key = str(spec["key"])
        start = int(spec.get("start") or 0)
        end = int(spec.get("end") if spec.get("end") is not None else limit - 1)
        withscores = bool(spec.get("withscores"))
        values = client.zrange(key, start, end, withscores=withscores)
        events = [
            {"key": key, "member": item[0], "score": item[1]} if withscores else {"key": key, "member": item}
            for item in values[:limit]
        ]
    else:
        pattern = str(spec.get("match") or "*")
        count = int(spec.get("count") or min(limit, 100))
        events = []
        for key in client.scan_iter(match=pattern, count=count):
            events.append({"key": key})
            if len(events) >= limit:
                break
    return events, {
        "mode": "live",
        "backend": "redis",
        "command": command,
        "rows_returned": len(events),
    }
