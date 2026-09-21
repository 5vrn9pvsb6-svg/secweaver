#!/usr/bin/env python3
"""Test dataasset connector connectivity (SLS / SSH / local_file / DB / HTTP / ES)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_ACCESS = REPO_ROOT / "src" / "skills" / "_shared" / "data-access"
sys.path.insert(0, str(DATA_ACCESS))

from fetch import EXECUTION_MODE_ONBOARDING_TEST, fetch  # noqa: E402
from registry import DATAASSET_ROOT, load_asset, load_connector, load_templates  # noqa: E402
from template_select import build_fetch_plan, normalize_fetch_params, select_template_for_asset  # noqa: E402


def emit_fetch_error(
    *,
    asset_id: str | None = None,
    connector_id: str | None = None,
    template_id: str | None = None,
    error_type: str,
    message: str,
) -> None:
    """Emit machine-readable operator diagnostics without a traceback."""
    print(
        json.dumps(
            {
                "status": "error",
                "asset_id": asset_id,
                "connector_id": connector_id,
                "template_id": template_id,
                "error": {"type": error_type, "message": message},
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Test connector live fetch")
    parser.add_argument("target_id", help="connector_id or asset_id (with --by-asset)")
    parser.add_argument(
        "--by-asset",
        action="store_true",
        help="target is asset_id",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="with --by-asset: print multi-connector fetch plan only",
    )
    parser.add_argument(
        "--connector",
        metavar="CONNECTOR_ID",
        help="with --by-asset: fetch only this connector from the asset plan",
    )
    parser.add_argument("--params", default="{}", help="fetch params JSON")
    parser.add_argument("--dry-run", action="store_true", help="render only, no Vault decrypt")
    args = parser.parse_args()

    params = normalize_fetch_params(json.loads(args.params))

    if args.by_asset:
        asset_id = args.target_id
        asset = load_asset(asset_id)
        plan = build_fetch_plan(
            [asset_id],
            params,
            load_asset=load_asset,
            load_connector=load_connector,
            load_templates=load_templates,
        )
        if args.plan:
            print(json.dumps({"fetch_plan": plan}, ensure_ascii=False, indent=2))
            return 0
        if args.connector:
            plan = [p for p in plan if p["connector_id"] == args.connector]
        if not plan:
            emit_fetch_error(
                asset_id=asset_id,
                connector_id=args.connector,
                error_type="NoFetchPlan",
                message="no fetch plan entries; check required query parameters and templates",
            )
            return 1
        item = plan[0]
        try:
            result = fetch(
                item["asset_id"],
                item["template_id"],
                params,
                connector_id=item["connector_id"],
                resolve_secrets=not args.dry_run,
                execution_mode=EXECUTION_MODE_ONBOARDING_TEST,
            )
        except Exception as exc:  # noqa: BLE001 - CLI boundary returns structured diagnostics.
            emit_fetch_error(
                asset_id=item.get("asset_id"),
                connector_id=item.get("connector_id"),
                template_id=item.get("template_id"),
                error_type=type(exc).__name__,
                message=str(exc),
            )
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    connector = load_connector(args.target_id)
    assets_dir = DATAASSET_ROOT / "assets"
    asset_id = None
    for path in sorted(assets_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        from aggregate import resolve_connector_ids  # noqa: WPS433

        if args.target_id in resolve_connector_ids(data):
            asset_id = data["asset_id"]
            break
    if not asset_id:
        print(f"no asset references connector {args.target_id}", file=sys.stderr)
        return 1
    asset = load_asset(asset_id)
    templates = load_templates()
    template_id, reason = select_template_for_asset(asset, connector, params, templates)
    if not template_id:
        emit_fetch_error(
            asset_id=asset_id,
            connector_id=connector["connector_id"],
            error_type="NoTemplate",
            message=f"no template: {reason}",
        )
        return 1

    try:
        result = fetch(
            asset_id,
            template_id,
            params,
            connector_id=connector["connector_id"],
            resolve_secrets=not args.dry_run,
            execution_mode=EXECUTION_MODE_ONBOARDING_TEST,
        )
    except Exception as exc:  # noqa: BLE001 - CLI boundary returns structured diagnostics.
        emit_fetch_error(
            asset_id=asset_id,
            connector_id=connector["connector_id"],
            template_id=template_id,
            error_type=type(exc).__name__,
            message=str(exc),
        )
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
