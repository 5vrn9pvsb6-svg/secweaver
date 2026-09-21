#!/usr/bin/env python3
"""Calculate a deterministic source-tree fingerprint for release provenance."""

import argparse
import hashlib
from pathlib import Path


EXCLUDED_DIRS = {
    ".git",
    ".cache",
    ".pytest_cache",
    "__pycache__",
    "bin",
    "dist",
    "private",
    "runtime",
    "vendor",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".tmp", ".swp"}


def source_fingerprint(root: Path) -> str:
    root = root.resolve()
    digest = hashlib.sha256()
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and not any(part in EXCLUDED_DIRS for part in path.relative_to(root).parts)
        and path.suffix not in EXCLUDED_SUFFIXES
        and path.name != ".DS_Store"
    )
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error(f"source root is not a directory: {args.root}")
    print(source_fingerprint(args.root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
