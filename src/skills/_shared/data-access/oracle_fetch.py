"""Oracle / PL/SQL database_ro fetcher."""

from __future__ import annotations

from typing import Any

from db_common import db_user_password, default_port, sql_named_to_oracle


def _load_oracledb():
    try:
        import oracledb
    except ImportError as exc:
        raise RuntimeError("live Oracle/PLSQL fetch requires: pip install oracledb") from exc
    return oracledb


def _dsn(config: dict[str, Any], oracledb: Any) -> str:
    if config.get("dsn"):
        return str(config["dsn"])
    service_name = config.get("service_name") or config.get("database")
    return oracledb.makedsn(
        config["host"],
        int(config.get("port") or default_port("oracle")),
        service_name=str(service_name),
    )


def fetch(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    sql: str,
    params: dict[str, Any],
) -> list[dict[str, Any]]:
    oracledb = _load_oracledb()
    config = connector.get("config") or {}
    timeout = int((connector.get("constraints") or {}).get("query_timeout_sec") or 30)
    user, password = db_user_password(credentials)
    query, values = sql_named_to_oracle(sql, params)
    conn = oracledb.connect(
        user=user,
        password=password,
        dsn=_dsn(config, oracledb),
    )
    try:
        try:
            conn.call_timeout = timeout * 1000
        except AttributeError:
            pass
        with conn.cursor() as cursor:
            cursor.execute(query, values)
            columns = [str(col[0]) for col in (cursor.description or [])]
            return [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]
    finally:
        conn.close()
