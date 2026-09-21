"""Hive connector fetcher."""

from __future__ import annotations

from typing import Any

from db_fetch import assert_select_only, filter_rows, sql_named_to_positional


def _load_pyhive():
    try:
        from pyhive import hive
    except ImportError as exc:
        raise RuntimeError("live Hive fetch requires: pip install PyHive thrift sasl") from exc
    return hive


def fetch(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    sql: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    hive = _load_pyhive()
    config = connector.get("config") or {}
    query, values = sql_named_to_positional(sql, params)
    assert_select_only(query)
    if values:
        raise ValueError("hive connector currently requires rendered SQL without positional parameters")
    conn = hive.Connection(
        host=config["host"],
        port=int(config.get("port") or 10000),
        username=credentials.get("username") or credentials.get("user") or None,
        database=config.get("database") or "default",
        auth=config.get("auth") or "NONE",
    )
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        columns = [col[0] for col in cursor.description or []]
        rows = [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]
    finally:
        conn.close()
    denylist = {c.lower() for c in (config.get("column_denylist") or [])}
    events = filter_rows(rows, denylist)
    return events, {"backend": "hive", "database": config.get("database"), "rows_returned": len(events)}
