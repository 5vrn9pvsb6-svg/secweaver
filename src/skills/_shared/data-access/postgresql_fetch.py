"""PostgreSQL database_ro fetcher."""

from __future__ import annotations

from typing import Any

from db_common import db_user_password, default_port


def _load_psycopg():
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise RuntimeError("live PostgreSQL fetch requires: pip install psycopg[binary]") from exc
    return psycopg, dict_row


def fetch(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    query: str,
    values: list[Any],
) -> list[dict[str, Any]]:
    psycopg, dict_row = _load_psycopg()
    config = connector.get("config") or {}
    timeout = int((connector.get("constraints") or {}).get("query_timeout_sec") or 30)
    user, password = db_user_password(credentials)
    conninfo = {
        "host": config["host"],
        "port": int(config.get("port") or default_port("postgresql")),
        "dbname": config["database"],
        "user": user,
        "password": password,
        "connect_timeout": timeout,
    }
    if config.get("sslmode"):
        conninfo["sslmode"] = config["sslmode"]
    with psycopg.connect(**conninfo, row_factory=dict_row) as conn:
        conn.execute(f"SET statement_timeout = '{timeout}s'")
        with conn.cursor() as cursor:
            cursor.execute(query, values)
            return list(cursor.fetchall())
