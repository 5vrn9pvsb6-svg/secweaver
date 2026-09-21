"""MySQL / MariaDB database_ro fetcher."""

from __future__ import annotations

from typing import Any

from db_common import db_user_password, default_port


def _load_pymysql():
    try:
        import pymysql
    except ImportError as exc:
        raise RuntimeError("live MySQL fetch requires: pip install pymysql") from exc
    return pymysql


def fetch(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    query: str,
    values: list[Any],
) -> list[dict[str, Any]]:
    pymysql = _load_pymysql()
    config = connector.get("config") or {}
    timeout = int((connector.get("constraints") or {}).get("query_timeout_sec") or 30)
    user, password = db_user_password(credentials)
    conn = pymysql.connect(
        host=config["host"],
        port=int(config.get("port") or default_port("mysql")),
        user=user,
        password=password,
        database=config["database"],
        connect_timeout=timeout,
        read_timeout=timeout,
        cursorclass=pymysql.cursors.DictCursor,
    )
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, values)
            return list(cursor.fetchall())
    finally:
        conn.close()
