#!/usr/bin/env python3
"""Create and verify Agent provenance carried by history-free source archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    # Direct module loading in repository tests does not add src/scripts to the
    # import path, while normal script execution does.
    sys.path.insert(0, str(SCRIPT_DIR))

from source_fingerprint import source_fingerprint


SCHEMA_VERSION = "1"
PROVENANCE_NAME = ".secweaver-source-archive.json"
AGENT_ROOT = Path("src/tools/secweaver-agent")
FINGERPRINT_TOOL = Path("src/scripts/source_fingerprint.py")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9][A-Za-z0-9.-]*)?$")


class ProvenanceError(ValueError):
    """Raised when an archive cannot prove which immutable source tree it contains."""


def sha256_file(path: Path) -> str:
    """Return a lowercase SHA-256 digest without depending on platform utilities."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provenance_path(root: Path) -> Path:
    return root / PROVENANCE_NAME


def create_provenance(root: Path, source_commit: str, version_commit: str) -> dict[str, str]:
    """Write provenance after the Git-backed release gate has accepted the source tree."""
    root = root.resolve()
    if not COMMIT_PATTERN.fullmatch(source_commit):
        raise ProvenanceError(f"invalid source commit: {source_commit}")
    if not COMMIT_PATTERN.fullmatch(version_commit):
        raise ProvenanceError(f"invalid Agent VERSION commit: {version_commit}")

    version = (root / AGENT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not VERSION_PATTERN.fullmatch(version):
        raise ProvenanceError(f"invalid Agent VERSION: {version}")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "source_commit": source_commit,
        "agent_version": version,
        "agent_version_commit": version_commit,
        "agent_source_sha256": source_fingerprint(root / AGENT_ROOT),
        "fingerprint_tool_sha256": sha256_file(root / FINGERPRINT_TOOL),
    }
    provenance_path(root).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def load_and_verify_provenance(root: Path, expected_version: str = "") -> dict[str, str]:
    """Verify archive metadata and recompute every digest before release tooling runs."""
    root = root.resolve()
    path = provenance_path(root)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ProvenanceError(f"missing {PROVENANCE_NAME}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvenanceError(f"cannot read {PROVENANCE_NAME}: {exc}") from exc

    required = {
        "schema_version",
        "source_commit",
        "agent_version",
        "agent_version_commit",
        "agent_source_sha256",
        "fingerprint_tool_sha256",
    }
    if set(payload) != required or not all(isinstance(payload.get(key), str) for key in required):
        raise ProvenanceError(f"{PROVENANCE_NAME} has an unsupported field set")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise ProvenanceError(f"unsupported source archive schema: {payload['schema_version']}")
    for field in ("source_commit", "agent_version_commit"):
        if not COMMIT_PATTERN.fullmatch(payload[field]):
            raise ProvenanceError(f"invalid {field}: {payload[field]}")

    canonical_version = (root / AGENT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if payload["agent_version"] != canonical_version:
        raise ProvenanceError("archive Agent VERSION does not match its provenance")
    if expected_version and payload["agent_version"] != expected_version:
        raise ProvenanceError(
            f"requested VERSION {expected_version} differs from archive VERSION {payload['agent_version']}"
        )

    actual_tool_digest = sha256_file(root / FINGERPRINT_TOOL)
    if payload["fingerprint_tool_sha256"] != actual_tool_digest:
        raise ProvenanceError("archive fingerprint tool differs from exported provenance")
    actual_source_digest = source_fingerprint(root / AGENT_ROOT)
    if payload["agent_source_sha256"] != actual_source_digest:
        raise ProvenanceError("archive Agent source differs from exported provenance")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="write provenance into an extracted archive")
    create.add_argument("--root", type=Path, required=True)
    create.add_argument("--source-commit", required=True)
    create.add_argument("--version-commit", required=True)

    verify = subparsers.add_parser("verify", help="verify archive provenance and source digests")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--expected-version", default="")

    field = subparsers.add_parser("field", help="print one field from verified provenance")
    field.add_argument("--root", type=Path, required=True)
    field.add_argument("name", choices=("source_commit", "agent_version", "agent_version_commit"))

    args = parser.parse_args()
    try:
        if args.command == "create":
            create_provenance(args.root, args.source_commit, args.version_commit)
        else:
            payload = load_and_verify_provenance(
                args.root,
                getattr(args, "expected_version", ""),
            )
            if args.command == "field":
                print(payload[args.name])
    except (OSError, ProvenanceError) as exc:
        print(f"source archive provenance: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
