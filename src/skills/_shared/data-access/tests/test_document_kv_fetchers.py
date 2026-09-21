"""Tests for MongoDB and Redis connector fetchers."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[3]
sys.path.insert(0, str(ROOT))

import extended_fetch  # noqa: E402
import mongodb_fetch  # noqa: E402
import redis_fetch  # noqa: E402


class FakeMongoCursor:
    def __init__(self, rows):
        self.rows = rows

    def sort(self, _sort):
        return self

    def limit(self, limit):
        self.rows = self.rows[:limit]
        return self

    def __iter__(self):
        return iter(self.rows)


class FakeMongoCollection:
    def find(self, find_filter, projection=None):
        self.find_filter = find_filter
        self.projection = projection
        return FakeMongoCursor([{"src_ip": find_filter["src_ip"], "action": "allow"}])


class FakeMongoDatabase:
    def __getitem__(self, _collection):
        return FakeMongoCollection()


class FakeMongoClient:
    def __init__(self, *_args, **_kwargs):
        pass

    def __getitem__(self, _database):
        return FakeMongoDatabase()

    def close(self):
        pass


class FakePymongo:
    MongoClient = FakeMongoClient


class FakeRedisClient:
    def get(self, key):
        return f"value:{key}"

    def scan_iter(self, match="*", count=100):
        yield f"{match}:1"
        yield f"{match}:2"


class FakeRedisModule:
    class Redis(FakeRedisClient):
        def __init__(self, *_args, **_kwargs):
            pass


class TestDocumentKvFetchers(unittest.TestCase):
    def test_mongodb_fetches_json_query(self) -> None:
        original = mongodb_fetch._load_pymongo
        mongodb_fetch._load_pymongo = lambda: FakePymongo
        try:
            events, meta = extended_fetch.fetch_extended_connector(
                {
                    "connector_id": "conn-mongodb",
                    "connector_type": "mongodb",
                    "config": {"host": "mongo.internal", "database": "security", "collection": "events"},
                },
                {"type": "mongodb", "username": "ro", "password": "x"},
                {
                    "template_id": "mongo-test",
                    "mongo_query": json.dumps({"collection": "events", "filter": {"src_ip": "203.0.113.10"}, "limit": 5}),
                    "params": {"limit": 5},
                },
            )
        finally:
            mongodb_fetch._load_pymongo = original

        self.assertEqual(meta["backend"], "mongodb")
        self.assertEqual(events, [{"src_ip": "203.0.113.10", "action": "allow"}])

    def test_redis_fetches_scan_query(self) -> None:
        original = redis_fetch._load_redis
        redis_fetch._load_redis = lambda: FakeRedisModule
        try:
            events, meta = extended_fetch.fetch_extended_connector(
                {
                    "connector_id": "conn-redis",
                    "connector_type": "redis",
                    "config": {"host": "redis.internal", "db": 0},
                },
                {"type": "redis", "password": "x"},
                {
                    "template_id": "redis-test",
                    "redis_query": json.dumps({"command": "SCAN", "match": "security:*", "limit": 2}),
                    "params": {"limit": 2},
                },
            )
        finally:
            redis_fetch._load_redis = original

        self.assertEqual(meta["backend"], "redis")
        self.assertEqual(meta["command"], "SCAN")
        self.assertEqual(events, [{"key": "security:*:1"}, {"key": "security:*:2"}])

    def test_onboarding_query_snippets_render_to_valid_json(self) -> None:
        mongo = json.loads((REPO_ROOT / "dataasset/onboarding/mongodb/template.snippet.json").read_text(encoding="utf-8"))
        redis = json.loads((REPO_ROOT / "dataasset/onboarding/redis/template.snippet.json").read_text(encoding="utf-8"))

        mongo_query = mongo["mongo_query"].format(src_ip="203.0.113.10", limit=5)
        redis_query = redis["redis_query"].format(key_pattern="security:*", limit=5)

        self.assertEqual(json.loads(mongo_query)["filter"]["src_ip"], "203.0.113.10")
        self.assertEqual(json.loads(redis_query)["match"], "security:*")


if __name__ == "__main__":
    unittest.main()
