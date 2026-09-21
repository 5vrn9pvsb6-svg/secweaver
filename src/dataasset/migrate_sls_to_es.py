#!/usr/bin/env python3
"""Migrate SLS evidence into date-partitioned SecWeaver ES indices.

The source is read through the normal DataAsset connector path. Writes are
explicitly directed to the HTTPS ingest gateway and require a separate writer
credential; the read-only query credential is never reused for bulk writes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_CONNECTOR = REPO_ROOT / "src" / "dataasset" / "test_connector.py"
SAFE_INDEX_RE = re.compile(r"^[a-z0-9._*-]+$")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def find_source_asset(source_root: Path, source_connector_id: str) -> str:
    for path in sorted((source_root / "assets").glob("*.json")):
        asset = load_json(path)
        if asset.get("connector_id") == source_connector_id:
            return str(asset["asset_id"])
    raise ValueError(f"source connector is not referenced by an asset: {source_connector_id}")


def fetch_source(
    source_root: Path,
    asset_id: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    env = os.environ.copy()
    env["DATAASSET_ROOT"] = str(source_root)
    result = subprocess.run(
        [sys.executable, str(TEST_CONNECTOR), asset_id, "--by-asset", "--params", json.dumps(params)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stdout.strip() or result.stderr.strip() or "source fetch failed"
        raise RuntimeError(detail)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"source fetch returned invalid JSON: {exc}") from exc
    if payload.get("status") == "error":
        raise RuntimeError(json.dumps(payload, ensure_ascii=False))
    return payload


def parse_event_time(event: dict[str, Any]) -> datetime:
    value = event.get("@timestamp") or event.get("timestamp") or event.get("time")
    if not value:
        raise ValueError("event has no timestamp/@timestamp/time field")
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def target_index(pattern: str, event: dict[str, Any]) -> str:
    if not SAFE_INDEX_RE.fullmatch(pattern):
        raise ValueError(f"unsafe target index pattern: {pattern}")
    base = pattern.rstrip("*").rstrip("-")
    if not base:
        raise ValueError(f"target index pattern has no base: {pattern}")
    return f"{base}-{parse_event_time(event):%Y.%m.%d}"


def build_bulk(events: list[dict[str, Any]], index_pattern: str, asset_type: str) -> dict[str, list[bytes]]:
    grouped: dict[str, list[bytes]] = defaultdict(list)
    for event in events:
        event = dict(event)
        event.setdefault("@timestamp", event.get("timestamp") or event.get("time"))
        event.setdefault("asset_type", asset_type)
        event.setdefault("migration_source", "sls")
        index = target_index(index_pattern, event)
        metadata: dict[str, Any] = {"index": {"_index": index}}
        if event.get("evidence_id"):
            metadata["index"]["_id"] = str(event["evidence_id"])
        grouped[index].append(json.dumps(metadata, ensure_ascii=False).encode("utf-8"))
        grouped[index].append(json.dumps(event, ensure_ascii=False).encode("utf-8"))
    return grouped


def bulk_write(
    ingest_url: str,
    username: str,
    password: str,
    ca_file: Path,
    index: str,
    lines: list[bytes],
) -> dict[str, Any]:
    body = b"\n".join(lines) + b"\n"
    url = ingest_url.rstrip("/") + "/" + urllib.parse.quote(index, safe="._-") + "/_bulk"
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-ndjson",
        },
        method="POST",
    )
    import base64

    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request.add_header("Authorization", f"Basic {token}")
    context = ssl.create_default_context(cafile=str(ca_file))
    try:
        with urllib.request.urlopen(request, context=context, timeout=90) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"ES ingest HTTP {exc.code}: {detail}") from exc
    if payload.get("errors"):
        failures = [
            item
            for item in payload.get("items", [])
            if isinstance(item, dict)
            for detail in item.values()
            if isinstance(detail, dict) and int(detail.get("status", 200)) >= 300
        ]
        raise RuntimeError(f"ES bulk returned {len(failures)} failed items")
    return {"index": index, "items": len(payload.get("items", []))}


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate SLS DataAsset events to SecWeaver ES")
    # Migration is operator-directed; a public checkout has no private catalogs.
    parser.add_argument("--config", required=True, help="Operator-owned migration mapping JSON")
    parser.add_argument("--source-root", required=True, help="Operator-owned source DataAsset directory")
    parser.add_argument("--mapping", action="append", required=True, help="target connector_id; repeat for multiple mappings")
    parser.add_argument("--time-start", required=True)
    parser.add_argument("--time-end", required=True)
    parser.add_argument("--params", default="{}", help="Additional source query parameters, e.g. client_ip")
    parser.add_argument("--ingest-url", required=True, help="HTTPS ingest gateway, e.g. https://ES_SERVER_IP:9443")
    parser.add_argument("--ca-file", required=True, help="CA that signs the ingest gateway certificate")
    parser.add_argument("--ingest-user", default=os.getenv("SECWEAVER_INGEST_USER", ""))
    parser.add_argument("--ingest-password", default=os.getenv("SECWEAVER_INGEST_PASSWORD", ""))
    parser.add_argument("--dry-run", action="store_true", help="Fetch and render counts without writing")
    args = parser.parse_args()

    source_root = Path(args.source_root).expanduser().resolve()
    config = load_json(Path(args.config).expanduser().resolve())
    mappings = config.get("mappings") or []
    selected = set(args.mapping)
    # A typo must not silently become a successful migration of zero sources.
    unknown = selected - {str(item.get("target_connector_id") or "") for item in mappings}
    if unknown:
        parser.error(f"unknown target mapping(s): {', '.join(sorted(unknown))}")
    params = json.loads(args.params)
    params.update({"time_start": args.time_start, "time_end": args.time_end})
    if not args.dry_run and (not args.ingest_user or not args.ingest_password):
        parser.error("bulk writes require --ingest-user/SECWEAVER_INGEST_USER and --ingest-password/SECWEAVER_INGEST_PASSWORD")
    ca_file = Path(args.ca_file).expanduser().resolve()
    if not ca_file.is_file():
        parser.error(f"CA file not found: {ca_file}")

    summaries: list[dict[str, Any]] = []
    failed = False
    for mapping in mappings:
        target_connector_id = str(mapping.get("target_connector_id") or "")
        if target_connector_id not in selected:
            continue
        try:
            source_connector_id = str(mapping["source_connector_id"])
            asset_id = find_source_asset(source_root, source_connector_id)
            source = fetch_source(source_root, asset_id, params)
            events = source.get("events") or []
            grouped = build_bulk(events, str(mapping["target_index"]), str(load_json(source_root / "assets" / f"{asset_id}.json").get("asset_type") or ""))
            written = []
            if not args.dry_run:
                for index, lines in grouped.items():
                    written.append(bulk_write(args.ingest_url, args.ingest_user, args.ingest_password, ca_file, index, lines))
            summaries.append({"target_connector_id": target_connector_id, "source_asset_id": asset_id, "events": len(events), "indices": sorted(grouped), "written": written, "dry_run": args.dry_run})
        except Exception as exc:  # noqa: BLE001 - migration boundary reports per-source failure.
            failed = True
            summaries.append({"target_connector_id": target_connector_id, "status": "error", "error": str(exc)})
    print(json.dumps({"status": "error" if failed else "ok", "migrations": summaries}, ensure_ascii=False, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
