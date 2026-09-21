#!/usr/bin/env python3
"""Run live connectivity test per asset; promote draft → active on success.

Usage:
  python3 src/dataasset/promote_after_connectivity.py \\
    --bundle bundle-incident-trace-default \\
    --params '{"src_ip":"203.0.113.10","host":"web-01","time_start":"...","time_end":"..."}'

  python3 src/dataasset/promote_after_connectivity.py \\
    --asset asset-secweaver-host-exec --params '{...}'

Only assets with asset_type in --types (default host_*, web_access_log) and status=draft are considered.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_ACCESS = REPO_ROOT / "src" / "skills" / "_shared" / "data-access"
sys.path.insert(0, str(DATA_ACCESS))

from fetch import EXECUTION_MODE_ONBOARDING_TEST, fetch  # noqa: E402
from dataasset.registry_write import registry_write_lock, write_json_atomic  # noqa: E402
from registry import DATAASSET_ROOT, load_asset, load_bundle, load_connector, load_templates  # noqa: E402
from template_select import build_fetch_plan, normalize_fetch_params  # noqa: E402

DEFAULT_TYPES = frozenset(
    {
        "web_access_log",
        "host_exec",
        "host_connect",
        "host_file_op",
    }
)


def asset_path(asset_id: str) -> Path:
    return DATAASSET_ROOT / "assets" / f"{asset_id}.json"


def load_asset_json(asset_id: str) -> dict:
    return json.loads(asset_path(asset_id).read_text(encoding="utf-8"))


def save_asset_json(asset_id: str, data: dict) -> None:
    """Promote only the version tested before another editor changes the asset."""
    with registry_write_lock(DATAASSET_ROOT):
        current = load_asset_json(asset_id)
        if current.get("status") != "draft" or {**current, "status": "active"} != data:
            raise ValueError(f"asset {asset_id} changed during connectivity test; retry promotion")
        write_json_atomic(asset_path(asset_id), data)


def test_asset_live(asset_id: str, params: dict) -> tuple[bool, str]:
    plan = build_fetch_plan(
        [asset_id],
        params,
        load_asset=load_asset,
        load_connector=load_connector,
        load_templates=load_templates,
    )
    if not plan:
        return False, "no fetch plan (check params / query_template_ids)"
    item = plan[0]
    try:
        result = fetch(
            item["asset_id"],
            item["template_id"],
            params,
            connector_id=item["connector_id"],
            resolve_secrets=True,
            execution_mode=EXECUTION_MODE_ONBOARDING_TEST,
        )
    except Exception as exc:
        return False, str(exc)
    meta = result.get("query_meta") or {}
    return True, f"template={result.get('template_id')} rows={meta.get('rows_returned', 0)}"


def collect_asset_ids(args: argparse.Namespace) -> list[str]:
    if args.asset:
        return [args.asset]
    bundle = load_bundle(args.bundle)
    return list(bundle.get("asset_ids") or [])


def main() -> int:
    parser = argparse.ArgumentParser(description="Connectivity test + draft→active promotion")
    parser.add_argument("--bundle", help="bundle_id (e.g. bundle-incident-trace-default)")
    parser.add_argument("--asset", help="single asset_id")
    parser.add_argument("--params", default="{}", help="fetch params JSON")
    parser.add_argument(
        "--types",
        default=",".join(sorted(DEFAULT_TYPES)),
        help="comma-separated asset_types to promote (default: WEB/D2)",
    )
    parser.add_argument("--dry-run", action="store_true", help="test only, do not write status")
    args = parser.parse_args()

    if not args.asset and not args.bundle:
        parser.error("specify --bundle or --asset")

    allowed_types = {t.strip() for t in args.types.split(",") if t.strip()}
    params = normalize_fetch_params(json.loads(args.params))

    results: list[dict] = []
    promoted = 0

    for asset_id in collect_asset_ids(args):
        data = load_asset_json(asset_id)
        atype = data.get("asset_type")
        status = data.get("status")
        if atype not in allowed_types:
            continue
        if status != "draft":
            results.append(
                {"asset_id": asset_id, "action": "skip", "reason": f"status={status}"}
            )
            continue

        ok, detail = test_asset_live(asset_id, params)
        entry = {"asset_id": asset_id, "asset_type": atype, "ok": ok, "detail": detail}
        if ok and not args.dry_run:
            data["status"] = "active"
            save_asset_json(asset_id, data)
            entry["action"] = "promoted"
            promoted += 1
        elif ok:
            entry["action"] = "would_promote"
        else:
            entry["action"] = "blocked"
        results.append(entry)

    print(json.dumps({"promoted": promoted, "dry_run": args.dry_run, "results": results}, ensure_ascii=False, indent=2))
    return 0 if all(r.get("ok") or r.get("action") == "skip" for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
