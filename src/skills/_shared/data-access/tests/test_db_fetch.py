"""Unit tests for DB SQL param binding and engine dispatch."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from db_fetch import (  # noqa: E402
    assert_select_only,
    credential_matches_engine,
    default_port,
    fetch_database,
    normalize_engine,
    sql_named_to_qmark,
    sql_named_to_positional,
)


class TestSqlParams(unittest.TestCase):
    def test_named_to_positional(self) -> None:
        sql = "SELECT * FROM t WHERE src_ip = :src_ip LIMIT :limit"
        q, vals = sql_named_to_positional(sql, {"src_ip": "1.1.1.1", "limit": 10})
        self.assertEqual(q, "SELECT * FROM t WHERE src_ip = %s LIMIT %s")
        self.assertEqual(vals, ["1.1.1.1", 10])

    def test_named_to_qmark(self) -> None:
        sql = "SELECT * FROM t WHERE src_ip = :src_ip LIMIT :limit"
        q, vals = sql_named_to_qmark(sql, {"src_ip": "1.1.1.1", "limit": 10})
        self.assertEqual(q, "SELECT * FROM t WHERE src_ip = ? LIMIT ?")
        self.assertEqual(vals, ["1.1.1.1", 10])

    def test_missing_param_raises(self) -> None:
        with self.assertRaises(ValueError):
            sql_named_to_positional("SELECT * FROM t WHERE x = :missing", {})

    def test_select_only_rejects_update(self) -> None:
        with self.assertRaises(ValueError):
            assert_select_only("UPDATE t SET x = 1")


class TestEngineHelpers(unittest.TestCase):
    def test_normalize_mysql_aliases(self) -> None:
        self.assertEqual(normalize_engine("mariadb"), "mysql")

    def test_normalize_postgres_aliases(self) -> None:
        self.assertEqual(normalize_engine("postgres"), "postgresql")
        self.assertEqual(normalize_engine("pg"), "postgresql")
        self.assertEqual(normalize_engine("pgsql"), "postgresql")

    def test_normalize_oracle_aliases(self) -> None:
        self.assertEqual(normalize_engine("oracle"), "oracle")
        self.assertEqual(normalize_engine("plsql"), "oracle")

    def test_normalize_sqlserver_and_sqlite_aliases(self) -> None:
        self.assertEqual(normalize_engine("mssql"), "sqlserver")
        self.assertEqual(normalize_engine("sql_server"), "sqlserver")
        self.assertEqual(normalize_engine("sqlite3"), "sqlite")

    def test_default_ports(self) -> None:
        self.assertEqual(default_port("mysql"), 3306)
        self.assertEqual(default_port("postgresql"), 5432)
        self.assertEqual(default_port("oracle"), 1521)
        self.assertEqual(default_port("sqlserver"), 1433)

    def test_credential_match(self) -> None:
        self.assertTrue(credential_matches_engine("mysql", "mysql"))
        self.assertTrue(credential_matches_engine("postgresql", "postgresql"))
        self.assertTrue(credential_matches_engine("plsql", "oracle"))
        self.assertTrue(credential_matches_engine("mssql", "sqlserver"))
        self.assertTrue(credential_matches_engine("sqlite", "sqlite"))
        self.assertFalse(credential_matches_engine("mysql", "postgresql"))


class TestFetchDatabase(unittest.TestCase):
    def _connector(self, engine: str) -> dict:
        return {
            "config": {
                "engine": engine,
                "host": "db.internal",
                "database": "sec_audit",
            },
            "constraints": {"query_timeout_sec": 5},
        }

    @patch("db_fetch.fetch_mysql")
    def test_fetch_mysql_dispatch(self, mock_mysql: MagicMock) -> None:
        mock_mysql.return_value = [{"src_ip": "1.1.1.1"}]
        connector = self._connector("mysql")
        creds = {"type": "mysql", "username": "ro", "password": "x"}
        events, meta = fetch_database(
            connector,
            creds,
            "SELECT * FROM login_events WHERE src_ip = :src_ip LIMIT :limit",
            {"src_ip": "1.1.1.1", "limit": 5},
        )
        self.assertEqual(events, [{"src_ip": "1.1.1.1"}])
        self.assertEqual(meta["engine"], "mysql")
        mock_mysql.assert_called_once()

    @patch("db_fetch.fetch_postgresql")
    def test_fetch_postgresql_dispatch(self, mock_pg: MagicMock) -> None:
        mock_pg.return_value = [{"hostname": "web-01"}]
        connector = self._connector("postgresql")
        creds = {"type": "postgresql", "username": "ro", "password": "x"}
        events, meta = fetch_database(
            connector,
            creds,
            "SELECT hostname FROM cmdb_hosts LIMIT :limit",
            {"limit": 10},
        )
        self.assertEqual(events, [{"hostname": "web-01"}])
        self.assertEqual(meta["engine"], "postgresql")
        mock_pg.assert_called_once()

    @patch("db_fetch.fetch_oracle")
    def test_fetch_oracle_dispatch(self, mock_oracle: MagicMock) -> None:
        mock_oracle.return_value = [{"USERNAME": "APP"}]
        connector = self._connector("plsql")
        creds = {"type": "oracle", "username": "ro", "password": "x"}
        events, meta = fetch_database(
            connector,
            creds,
            "SELECT USERNAME FROM DBA_USERS WHERE USERNAME = :username",
            {"username": "APP"},
        )
        self.assertEqual(events, [{"USERNAME": "APP"}])
        self.assertEqual(meta["engine"], "oracle")
        mock_oracle.assert_called_once()

    @patch("db_fetch.fetch_sqlserver")
    def test_fetch_sqlserver_dispatch(self, mock_sqlserver: MagicMock) -> None:
        mock_sqlserver.return_value = [{"src_ip": "1.1.1.1"}]
        connector = self._connector("mssql")
        creds = {"type": "sqlserver", "username": "ro", "password": "x"}
        events, meta = fetch_database(
            connector,
            creds,
            "SELECT * FROM login_events WHERE src_ip = :src_ip",
            {"src_ip": "1.1.1.1"},
        )
        self.assertEqual(events, [{"src_ip": "1.1.1.1"}])
        self.assertEqual(meta["engine"], "sqlserver")
        mock_sqlserver.assert_called_once()

    @patch("db_fetch.fetch_sqlite")
    def test_fetch_sqlite_dispatch(self, mock_sqlite: MagicMock) -> None:
        mock_sqlite.return_value = [{"hostname": "web-01"}]
        connector = {"config": {"engine": "sqlite", "path": "samples/audit.db"}}
        creds = {"type": "sqlite"}
        events, meta = fetch_database(
            connector,
            creds,
            "SELECT hostname FROM cmdb_hosts LIMIT :limit",
            {"limit": 10},
        )
        self.assertEqual(events, [{"hostname": "web-01"}])
        self.assertEqual(meta["engine"], "sqlite")
        self.assertEqual(meta["database"], "samples/audit.db")
        mock_sqlite.assert_called_once()

    def test_credential_engine_mismatch(self) -> None:
        with self.assertRaises(ValueError):
            fetch_database(
                self._connector("postgresql"),
                {"type": "mysql", "username": "ro", "password": "x"},
                "SELECT 1",
                {},
            )


if __name__ == "__main__":
    unittest.main()
