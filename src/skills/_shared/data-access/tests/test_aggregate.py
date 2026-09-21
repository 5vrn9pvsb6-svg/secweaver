"""Unit tests for multi-connector aggregation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aggregate import (  # noqa: E402
    dedupe_events,
    filter_connectors_by_host,
    merge_aggregate_events,
    resolve_connector_ids,
)


ASSET = {
    "asset_id": "asset-ssh-internal",
    "connector_id": "conn-a",
    "connector_ids": ["conn-b", "conn-a", "conn-c"],
    "aggregate": {"max_events": 2, "dedupe_by": ["src_ip", "user"]},
}


def _conn(cid: str, hostname: str | None = None) -> dict:
    cfg: dict = {"project": "p", "logstore": "x"}
    if hostname:
        cfg["hostname"] = hostname
    return {"connector_id": cid, "connector_type": "sls", "config": cfg}


class TestResolveConnectorIds(unittest.TestCase):
    def test_primary_first_dedupe(self) -> None:
        self.assertEqual(resolve_connector_ids(ASSET), ["conn-a", "conn-b", "conn-c"])

    def test_single_connector(self) -> None:
        self.assertEqual(resolve_connector_ids({"connector_id": "conn-x"}), ["conn-x"])


class TestHostFilter(unittest.TestCase):
    def test_host_matches_bound_connectors(self) -> None:
        ids = ["conn-global", "conn-web", "conn-db"]
        load = {
            "conn-global": _conn("conn-global"),
            "conn-web": _conn("conn-web", "web-01"),
            "conn-db": _conn("conn-db", "db-01"),
        }
        out = filter_connectors_by_host(ASSET, ids, {"host": "web-01"}, load.get)
        self.assertEqual(out, ["conn-web", "conn-global"])

    def test_no_host_returns_all(self) -> None:
        ids = ["conn-a", "conn-b"]
        load = {"conn-a": _conn("conn-a"), "conn-b": _conn("conn-b", "web-01")}
        self.assertEqual(filter_connectors_by_host(ASSET, ids, {}, load.get), ids)


class TestDedupe(unittest.TestCase):
    def test_dedupe_and_cap(self) -> None:
        events = [
            {"src_ip": "1.1.1.1", "user": "a", "evidence_id": "1"},
            {"src_ip": "1.1.1.1", "user": "a", "evidence_id": "2"},
            {"src_ip": "2.2.2.2", "user": "b", "evidence_id": "3"},
        ]
        merged = merge_aggregate_events(ASSET, events)
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0]["src_ip"], "1.1.1.1")


if __name__ == "__main__":
    unittest.main()
