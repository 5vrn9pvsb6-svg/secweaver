"""SQLite database_ro fetcher."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from db_common import sql_named_to_qmark

REPO_ROOT = Path(__file__).resolve().parents[4]


def _database_path(config: dict[str, Any]) -> str:
    value = str(config.get("path") or config.get("database") or "").strip()
    if not value:
        raise ValueError("sqlite connector config requires path or database")
    return value


def fetch(
    connector: dict[str, Any],
    _credentials: dict[str, Any],
    sql: str,
    params: dict[str, Any],
) -> list[dict[str, Any]]:
    config = connector.get("config") or {}
    timeout = int((connector.get("constraints") or {}).get("query_timeout_sec") or 30)
    query, values = sql_named_to_qmark(sql, params)
    database = _database_path(config)
    uri = database
    use_uri = False
    if database != ":memory:":
        path = Path(database)
        if not path.is_absolute():
            path = (REPO_ROOT / path).resolve()
        uri = f"file:{path}?mode=ro"
        use_uri = True
    conn = sqlite3.connect(uri, timeout=timeout, uri=use_uri)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.execute(query, values)
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()
