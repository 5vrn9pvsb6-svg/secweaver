#!/usr/bin/env python3
"""Create a history-free community archive and verify private roots are absent."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from release_scan import OPEN_SOURCE_EXCLUDED_PREFIXES, check_export_policy

REPO_ROOT = Path(__file__).resolve().parents[2]


def archive_members(path: Path) -> list[str]:
    with tarfile.open(path, "r:gz") as archive:
        return [member.name.lstrip("./") for member in archive.getmembers()]


def private_members(names: list[str]) -> list[str]:
    return sorted(name for name in names if any(name.startswith(prefix) for prefix in OPEN_SOURCE_EXCLUDED_PREFIXES))


def worktree_changes() -> list[str]:
    """Return uncommitted paths because the archive is intentionally built from HEAD."""
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return [f"git status failed: {result.stderr.strip()}"]
    return [line for line in result.stdout.splitlines() if line.strip()]


def verify_archive(path: Path) -> bool:
    """Run the public gates inside the exact history-free archive tree.

    Running from a temporary extraction catches excluded-file links, missing
    generated metadata, and imports that accidentally rely on private siblings.
    No network or credential-backed fetch is performed by these gates.
    """
    with tempfile.TemporaryDirectory(prefix="secweaver-community-verify-") as directory:
        root = Path(directory)
        with tarfile.open(path, "r:gz") as archive:
            archive.extractall(root)
        python = os.environ.get("PYTHON", sys.executable)
        commands = [
            [python, "src/scripts/release_scan.py"],
            [python, "src/scripts/check_docs_links.py"],
            [python, "src/scripts/check_public_doc_commands.py"],
            [python, "src/scripts/generate_supply_chain.py", "--check"],
            [python, "src/secweaver.py", "validate", "--json", "--strict"],
            [python, "src/skills/risk-identification/scripts/validate_policy_sync.py", "--strict"],
            [python, "tests/run_tests.py"],
            [python, "src/secweaver.py", "demo", "all", "-o", "examples/reports"],
            # Demo generation rewrites public fixtures; verify the final archive tree.
            [python, "src/scripts/release_scan.py"],
        ]
        for command in commands:
            result = subprocess.run(command, cwd=root, text=True, capture_output=True, check=False)
            if result.returncode != 0:
                print(f"ERROR: archive verification failed: {' '.join(command)}")
                if result.stdout:
                    print(result.stdout.rstrip())
                if result.stderr:
                    print(result.stderr.rstrip())
                return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export the current Git HEAD without company-private roots or internal history."
    )
    parser.add_argument("output", type=Path, help="Destination .tar.gz path")
    args = parser.parse_args()

    changes = worktree_changes()
    if changes:
        print("ERROR: open-source export requires a clean Git worktree; archive source is HEAD.")
        for change in changes[:50]:
            print(f"  {change}")
        return 1

    policy_issues = check_export_policy()
    if policy_issues:
        for issue in policy_issues:
            print(f"ERROR: {issue.path}: {issue.message}")
        return 1

    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="secweaver-community-", suffix=".tar.gz", delete=False) as handle:
        temporary = Path(handle.name)
    try:
        result = subprocess.run(
            [
                "git",
                "archive",
                "--worktree-attributes",
                "--format=tar.gz",
                f"--output={temporary}",
                "HEAD",
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            print(f"ERROR: git archive failed: {result.stderr.strip()}")
            return 1
        leaked = private_members(archive_members(temporary))
        if leaked:
            print("ERROR: private paths found in community archive:")
            for name in leaked[:50]:
                print(f"  {name}")
            return 1
        if not verify_archive(temporary):
            return 1
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)

    print(f"open-source archive: {output}")
    print("This archive is history-free. Never mirror or push the internal Git history to a public remote.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
