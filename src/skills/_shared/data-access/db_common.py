"""Shared helpers for read-only database connector fetchers."""

from __future__ import annotations

import re
from typing import Any

NAMED_PARAM = re.compile(r":(\w+)\b")

MYSQL_ENGINES = frozenset({"mysql", "mariadb"})
POSTGRES_ENGINES = frozenset({"postgresql", "postgres", "pg", "pgsql"})
ORACLE_ENGINES = frozenset({"oracle", "plsql"})
SQLSERVER_ENGINES = frozenset({"sqlserver", "mssql", "ms_sql", "sql_server"})
SQLITE_ENGINES = frozenset({"sqlite", "sqlite3"})

MYSQL_CRED_TYPES = frozenset({"mysql", "mariadb"})
POSTGRES_CRED_TYPES = frozenset({"postgresql", "postgres", "pg", "pgsql"})
ORACLE_CRED_TYPES = frozenset({"oracle", "plsql"})
SQLSERVER_CRED_TYPES = frozenset({"sqlserver", "mssql", "ms_sql", "sql_server"})
SQLITE_CRED_TYPES = frozenset({"sqlite", "sqlite3", "none", ""})

FORBIDDEN_SQL = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|CALL|EXECUTE)\b",
    re.IGNORECASE,
)


def normalize_engine(engine: str | None) -> str:
    """Return canonical database engine id."""
    value = (engine or "mysql").lower()
    if value in MYSQL_ENGINES:
        return "mysql"
    if value in POSTGRES_ENGINES:
        return "postgresql"
    if value in ORACLE_ENGINES:
        return "oracle"
    if value in SQLSERVER_ENGINES:
        return "sqlserver"
    if value in SQLITE_ENGINES:
        return "sqlite"
    raise NotImplementedError(f"database engine not supported: {engine}")


def default_port(engine: str) -> int:
    if engine == "postgresql":
        return 5432
    if engine == "oracle":
        return 1521
    if engine == "sqlserver":
        return 1433
    return 3306


def credential_matches_engine(cred_type: str | None, engine: str) -> bool:
    cred = (cred_type or "").lower()
    if engine == "mysql":
        return cred in MYSQL_CRED_TYPES
    if engine == "postgresql":
        return cred in POSTGRES_CRED_TYPES
    if engine == "oracle":
        return cred in ORACLE_CRED_TYPES
    if engine == "sqlserver":
        return cred in SQLSERVER_CRED_TYPES
    return cred in SQLITE_CRED_TYPES


def sql_named_to_positional(sql: str, params: dict[str, Any]) -> tuple[str, list[Any]]:
    values: list[Any] = []

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in params:
            raise ValueError(f"missing SQL param: {name}")
        values.append(params[name])
        return "%s"

    query = NAMED_PARAM.sub(repl, sql)
    return query, values


def sql_named_to_oracle(sql: str, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    values: dict[str, Any] = {}

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in params:
            raise ValueError(f"missing SQL param: {name}")
        values[name] = params[name]
        return f":{name}"

    query = NAMED_PARAM.sub(repl, sql)
    return query, values


def sql_named_to_qmark(sql: str, params: dict[str, Any]) -> tuple[str, list[Any]]:
    values: list[Any] = []

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in params:
            raise ValueError(f"missing SQL param: {name}")
        values.append(params[name])
        return "?"

    query = NAMED_PARAM.sub(repl, sql)
    return query, values


def assert_select_only(sql: str) -> None:
    if FORBIDDEN_SQL.search(sql):
        raise ValueError("only SELECT queries allowed for database_ro")


def filter_rows(rows: list[dict[str, Any]], denylist: set[str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in rows:
        item = {k: v for k, v in dict(row).items() if str(k).lower() not in denylist}
        events.append(item)
    return events


def db_user_password(credentials: dict[str, Any]) -> tuple[str, str]:
    user = credentials.get("username") or credentials.get("user") or ""
    password = credentials.get("password") or ""
    return str(user), str(password)
