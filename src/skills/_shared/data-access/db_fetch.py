"""Dispatcher for read-only database connector fetchers."""

from __future__ import annotations

from typing import Any

import mysql_fetch
import oracle_fetch
import postgresql_fetch
import sqlite_fetch
import sqlserver_fetch
from db_common import (
    assert_select_only,
    credential_matches_engine,
    default_port,
    filter_rows,
    normalize_engine,
    sql_named_to_qmark,
    sql_named_to_positional,
)

fetch_mysql = mysql_fetch.fetch
fetch_postgresql = postgresql_fetch.fetch
fetch_oracle = oracle_fetch.fetch
fetch_sqlserver = sqlserver_fetch.fetch
fetch_sqlite = sqlite_fetch.fetch


def fetch_database(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    sql: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    config = connector.get("config") or {}
    engine = normalize_engine(config.get("engine"))
    cred_type = credentials.get("type")
    if not credential_matches_engine(cred_type, engine):
        raise ValueError(
            f"credential type {cred_type!r} does not match database engine {engine!r}"
        )

    assert_select_only(sql)
    if engine == "oracle":
        rows = fetch_oracle(connector, credentials, sql, params)
    elif engine == "sqlserver":
        rows = fetch_sqlserver(connector, credentials, sql, params)
    elif engine == "sqlite":
        rows = fetch_sqlite(connector, credentials, sql, params)
    else:
        query, values = sql_named_to_positional(sql, params)
        rows = fetch_mysql(connector, credentials, query, values) if engine == "mysql" else fetch_postgresql(connector, credentials, query, values)

    denylist = {c.lower() for c in (config.get("column_denylist") or [])}
    events = filter_rows(rows, denylist)

    meta = {
        "engine": engine,
        "database": config.get("database") or config.get("path"),
        "rows_returned": len(events),
        "sql_params": list(params.keys()),
    }
    return events, meta
