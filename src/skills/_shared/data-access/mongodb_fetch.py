"""MongoDB connector fetcher."""

from __future__ import annotations

import datetime as dt
import json
from urllib.parse import quote_plus
from typing import Any

from connector_fetch_common import max_rows, request_timeout


def _load_pymongo():
    try:
        import pymongo
    except ImportError as exc:
        raise RuntimeError("live MongoDB fetch requires: pip install pymongo") from exc
    return pymongo


def _parse_query(query: str) -> dict[str, Any]:
    try:
        payload = json.loads(query)
    except json.JSONDecodeError as exc:
        raise ValueError("mongodb mongo_query must be a JSON object") from exc
    if not isinstance(payload, dict):
        raise ValueError("mongodb mongo_query must be a JSON object")
    return payload


def _mongo_uri(config: dict[str, Any], credentials: dict[str, Any]) -> str:
    if config.get("uri"):
        return str(config["uri"])
    host = str(config.get("host") or "127.0.0.1")
    port = int(config.get("port") or 27017)
    username = credentials.get("username") or credentials.get("user")
    password = credentials.get("password")
    auth_source = str(config.get("auth_source") or config.get("database") or "admin")
    if username and password:
        return f"mongodb://{quote_plus(str(username))}:{quote_plus(str(password))}@{host}:{port}/?authSource={quote_plus(auth_source)}"
    return f"mongodb://{host}:{port}/"


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if not isinstance(value, (str, int, float, bool, type(None))):
        return str(value)
    return value


def fetch(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    query: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    pymongo = _load_pymongo()
    config = connector.get("config") or {}
    spec = _parse_query(query)
    database = str(spec.get("database") or config.get("database") or "")
    collection_name = str(spec.get("collection") or config.get("collection") or "")
    if not database or not collection_name:
        raise ValueError("mongodb connector requires database and collection in config or mongo_query")
    find_filter = spec.get("filter") or {}
    projection = spec.get("projection")
    if not isinstance(find_filter, dict):
        raise ValueError("mongodb mongo_query.filter must be an object")
    limit = min(int(spec.get("limit") or max_rows(connector, params)), max_rows(connector, params))
    client = pymongo.MongoClient(_mongo_uri(config, credentials), serverSelectionTimeoutMS=request_timeout(connector) * 1000)
    try:
        collection = client[database][collection_name]
        cursor = collection.find(find_filter, projection)
        sort = spec.get("sort")
        if isinstance(sort, list) and sort:
            cursor = cursor.sort([(str(item[0]), int(item[1])) for item in sort if isinstance(item, (list, tuple)) and len(item) == 2])
        cursor = cursor.limit(limit)
        events = [_json_safe(dict(row)) for row in cursor]
    finally:
        client.close()
    return events, {
        "mode": "live",
        "backend": "mongodb",
        "database": database,
        "collection": collection_name,
        "rows_returned": len(events),
    }
