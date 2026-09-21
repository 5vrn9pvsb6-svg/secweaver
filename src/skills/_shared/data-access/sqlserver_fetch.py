"""SQL Server / MSSQL database_ro fetcher."""

from __future__ import annotations

from typing import Any

from db_common import db_user_password, default_port, sql_named_to_qmark


def _load_pyodbc():
    try:
        import pyodbc
    except ImportError as exc:
        raise RuntimeError("live SQL Server fetch requires: pip install pyodbc") from exc
    return pyodbc


def _connection_string(config: dict[str, Any], credentials: dict[str, Any], timeout: int) -> str:
    if config.get("connection_string"):
        return str(config["connection_string"])
    user, password = db_user_password(credentials)
    driver = str(config.get("driver") or "ODBC Driver 18 for SQL Server")
    host = str(config["host"])
    port = int(config.get("port") or default_port("sqlserver"))
    server = f"{host},{port}"
    encrypt = "yes" if config.get("encrypt", True) else "no"
    trust = "yes" if config.get("trust_server_certificate", True) else "no"
    parts = [
        f"DRIVER={{{driver}}}",
        f"SERVER={server}",
        f"DATABASE={config['database']}",
        f"UID={user}",
        f"PWD={password}",
        f"Encrypt={encrypt}",
        f"TrustServerCertificate={trust}",
        f"Connection Timeout={timeout}",
    ]
    return ";".join(parts)


def fetch(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    sql: str,
    params: dict[str, Any],
) -> list[dict[str, Any]]:
    pyodbc = _load_pyodbc()
    config = connector.get("config") or {}
    timeout = int((connector.get("constraints") or {}).get("query_timeout_sec") or 30)
    query, values = sql_named_to_qmark(sql, params)
    conn = pyodbc.connect(_connection_string(config, credentials, timeout), timeout=timeout)
    try:
        try:
            conn.timeout = timeout
        except AttributeError:
            pass
        cursor = conn.cursor()
        cursor.execute(query, values)
        columns = [column[0] for column in (cursor.description or [])]
        return [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]
    finally:
        conn.close()
