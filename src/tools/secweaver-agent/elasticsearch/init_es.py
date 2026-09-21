#!/usr/bin/env python3
"""Install the public Agent index template, or verify recent ingestion.

No Operator, private registry, third-party Python dependency, or embedded secret
is required. Preview is offline; only --apply writes, using create-only semantics.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
TEMPLATE_NAME = "secweaver-public-agent-v1"
INDEX_PATTERN = "secweaver-public-agent-*"
MAX_RESPONSE = 4 * 1024 * 1024


class SetupError(RuntimeError):
    """A safe error that never includes server response bodies or credentials."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward authorization to a redirect destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SetupError("Redirect refused; configure the final ES HTTPS endpoint")


class Client:
    """Bounded, certificate-verified calls to one explicit ES origin."""

    def __init__(self, endpoint: str, username: str, password: str, ca_file: str = ""):
        try:
            url = urllib.parse.urlsplit(endpoint)
            port = url.port
        except ValueError:
            raise SetupError("Invalid ES HTTPS origin or port") from None
        if (url.scheme != "https" or not url.hostname or url.username is not None
                or url.password is not None or url.query or url.fragment
                or url.path not in ("", "/") or port == 0):
            raise SetupError("Use a direct HTTPS ES origin without credentials, path, query or fragment")
        self.endpoint = endpoint.rstrip("/")
        self.authorization = "Basic " + base64.b64encode(
            f"{username}:{password}".encode()
        ).decode()
        context = ssl.create_default_context(cafile=ca_file or None)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context),
        )

    def request(self, method: str, path: str, body=None, *, missing_ok=False):
        """Do not retry writes or print upstream errors, which may echo secrets."""
        request = urllib.request.Request(
            self.endpoint + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": self.authorization, "Content-Type": "application/json"},
            method=method,
        )
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise SetupError("ES response exceeds 4 MiB")
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            if missing_ok and error.code == 404:
                return None
            raise SetupError(f"ES {method} failed: HTTP {error.code}; check permissions and ES logs") from None
        except (urllib.error.URLError, OSError, ValueError):
            raise SetupError("ES connection, TLS, or JSON response failed; check endpoint and CA") from None


def template(replicas: int) -> dict:
    """Keep the mapping fixed; replica selection affects only future indices."""
    body = json.loads((ROOT / "index-template.json").read_text())
    body["template"]["settings"]["number_of_replicas"] = replicas
    return body


def canonical_template(body: dict) -> dict:
    """Normalize ES settings serialization, not meaningful configuration drift.

    ES may return numeric settings as strings under a nested ``index`` object,
    and add an empty component list. Treat those as the same create request.
    """
    result = json.loads(json.dumps(body))
    if result.get("composed_of") == []:
        result.pop("composed_of")
    settings = result.get("template", {}).get("settings", {})
    flat = {}

    def flatten(values, prefix=""):
        for key, value in values.items():
            name = prefix + key
            if isinstance(value, dict):
                flatten(value, name + ".")
            else:
                flat[name.removeprefix("index.")] = str(value)

    flatten(settings)
    result.setdefault("template", {})["settings"] = flat
    return result


def install(client: Client, body: dict) -> str:
    """Skip identical state, refuse drift, and prevent a concurrent overwrite.

    This owns one template only. Existing indices and retention policies are
    never changed, and failures do not trigger destructive rollback.
    """
    info = client.request("GET", "/")
    if (info.get("version", {}).get("distribution") == "opensearch"
            or not str(info.get("version", {}).get("number", "")).startswith("8.")):
        raise SetupError("This integration targets Elasticsearch 8.x, not OpenSearch or other majors")
    path = "/_index_template/" + TEMPLATE_NAME
    existing = client.request("GET", path, missing_ok=True)
    if existing is not None:
        entries = existing.get("index_templates", [])
        current = entries[0].get("index_template") if len(entries) == 1 else None
        if not isinstance(current, dict) or canonical_template(current) != canonical_template(body):
            raise SetupError("Template already exists with different settings; review it manually; nothing overwritten")
        return "Template already matches; no write needed"
    result = client.request("PUT", path + "?create=true", body)
    if not result.get("acknowledged"):
        raise SetupError("Template acknowledgement missing; inspect ES before retrying")
    return "Created " + TEMPLATE_NAME + "; no indices or retention policies modified"


def check(client: Client) -> str:
    """Read recent data without exposing host commands or raw log documents."""
    result = client.request("POST", "/" + INDEX_PATTERN + "/_search", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-30m", "lte": "now+1m"}}},
        "aggs": {"datasets": {"terms": {"field": "secweaver_dataset", "size": 20}}},
    })
    if result.get("timed_out") or result.get("_shards", {}).get("failed", 0):
        raise SetupError("Search incomplete; check ES shard health")
    buckets = result.get("aggregations", {}).get("datasets", {}).get("buckets", [])
    if not buckets:
        raise SetupError("No recent Agent events; inspect Agent, Filebeat, clock and index permissions")
    return "Recent events by dataset (not a full module acceptance): " + json.dumps(
        {row["key"]: row["doc_count"] for row in buckets}, sort_keys=True
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Create the ES template, never overwrite")
    mode.add_argument("--check", action="store_true", help="Read-only recent ingestion check")
    parser.add_argument("--endpoint", default=os.getenv("SECWEAVER_ES_URL", ""))
    parser.add_argument("--ca-file", default="", help="Private CA PEM; otherwise system trust")
    parser.add_argument("--username", default=os.getenv("SECWEAVER_ES_USER", ""))
    parser.add_argument("--replicas", type=int, choices=(0, 1, 2), default=1)
    args = parser.parse_args(argv)
    if not args.apply and not args.check:
        print(json.dumps(template(args.replicas), indent=2))
        return 0
    try:
        if not args.endpoint or not args.username:
            raise SetupError("--endpoint and --username are required for online operations")
        password = os.getenv("SECWEAVER_ES_PASSWORD")
        if password is None:
            password = getpass.getpass("ES password (not saved): ")
        if not password:
            raise SetupError("Empty ES password refused")
        client = Client(args.endpoint, args.username, password, args.ca_file)
        print(check(client) if args.check else install(client, template(args.replicas)))
        return 0
    except (SetupError, OSError, EOFError) as error:
        # Never dump an SSL/file exception that might reveal local secret paths.
        print(str(error) if isinstance(error, SetupError) else "Setup failed; check local CA and input", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
