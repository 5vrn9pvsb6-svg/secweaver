"""ClickHouse connector fetcher."""

from __future__ import annotations

from typing import Any

from db_fetch import assert_select_only, filter_rows, sql_named_to_positional


def _load_clickhouse_driver():
    try:
        import clickhouse_connect
    except ImportError as exc:
        raise RuntimeError("live ClickHouse fetch requires: pip install clickhouse-connect") from exc
    return clickhouse_connect


def fetch(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    sql: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    clickhouse_connect = _load_clickhouse_driver()
    config = connector.get("config") or {}
    query, values = sql_named_to_positional(sql, params)
    assert_select_only(query)
    client = clickhouse_connect.get_client(
        host=config["host"],
        port=int(config.get("port") or (8443 if config.get("secure") else 8123)),
        username=credentials.get("username") or credentials.get("user") or "default",
        password=credentials.get("password") or "",
        database=config.get("database") or "default",
        secure=bool(config.get("secure")),
    )
    result = client.query(query, parameters=values)
    rows = [dict(zip(result.column_names, row, strict=False)) for row in result.result_rows]
    denylist = {c.lower() for c in (config.get("column_denylist") or [])}
    events = filter_rows(rows, denylist)
    return events, {"backend": "clickhouse", "database": config.get("database"), "rows_returned": len(events)}
