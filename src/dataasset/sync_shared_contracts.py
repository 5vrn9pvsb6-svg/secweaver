#!/usr/bin/env python3
"""Preview or apply canonical shared DataAsset contracts to local roots."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

try:
    from .validate_roots import PUBLIC_ROOT, discover_roots, shared_contract_paths
except ImportError:  # Direct script execution has no package context.
    from validate_roots import PUBLIC_ROOT, discover_roots, shared_contract_paths


def sync_shared_contracts(
    roots: list[Path],
    *,
    public_root: Path = PUBLIC_ROOT,
    write: bool = False,
) -> dict[str, Any]:
    """Compare roots with the canonical policy and optionally copy changed files.

    Only paths classified as ``shared`` are considered. Credentials and
    environment-owned inventory therefore remain outside this operation.
    """
    canonical = public_root.expanduser().resolve()
    normalized_roots = [root.expanduser().resolve() for root in roots]
    changes: list[dict[str, str]] = []
    for root in normalized_roots:
        if root == canonical:
            continue
        for relative in shared_contract_paths(canonical):
            source = canonical / relative
            target = root / relative
            reason = "missing" if not target.is_file() else "content differs"
            if target.is_file() and source.read_bytes() == target.read_bytes():
                continue
            changes.append({"root": str(root), "path": relative, "reason": reason})
            if write:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
    return {
        "ok": not changes or write,
        "mode": "write" if write else "check",
        "summary": {"root_count": len(normalized_roots), "change_count": len(changes)},
        "changes": changes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check or copy canonical shared DataAsset contracts into local roots"
    )
    parser.add_argument("--root", action="append", type=Path, help="target root; repeatable")
    parser.add_argument("--public-root", type=Path, default=PUBLIC_ROOT, help="canonical public root")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="preview drift and return non-zero when found")
    mode.add_argument("--write", action="store_true", help="copy shared files after review")
    parser.add_argument("--json", action="store_true", dest="json_output", help="print structured output")
    args = parser.parse_args()

    roots = args.root or discover_roots()
    result = sync_shared_contracts(roots, public_root=args.public_root, write=args.write)
    if args.json_output:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for item in result["changes"]:
            action = "SYNCED" if args.write else "DRIFT"
            print(f"{action}: {item['root']}/{item['path']}: {item['reason']}")
        if not result["changes"]:
            print("Shared DataAsset contracts are synchronized.")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
