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

from release_scan import OPEN_SOURCE_EXCLUDED_PREFIXES, check_export_policy, is_local_vault_path

REPO_ROOT = Path(__file__).resolve().parents[2]


def archive_members(path: Path) -> list[str]:
    """Normalize the optional ./ prefix without stripping hidden path components."""
    with tarfile.open(path, "r:gz") as archive:
        return [member.name.removeprefix("./") for member in archive.getmembers()]


def private_members(names: list[str]) -> list[str]:
    """Inspect actual tar members: attributes alone cannot prove Vault exclusion."""
    return sorted(
        name for name in names
        if is_local_vault_path(name)
        or any(name.startswith(prefix) for prefix in OPEN_SOURCE_EXCLUDED_PREFIXES)
    )


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


def run_checked(command: list[str], cwd: Path) -> str:
    """Run one export prerequisite and surface its bounded diagnostic on failure."""
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    return result.stdout.strip()


def add_source_provenance(raw_archive: Path, output: Path) -> None:
    """Repack Git's history-free tree with provenance produced by the Git release gate.

    The receipt is added only after the clean checkout passes the production Agent
    version check. Archive consumers can therefore verify exact Agent bytes without
    carrying repository history or relying on an environment-only bypass.
    """
    verifier = REPO_ROOT / "src/tools/secweaver-agent/scripts/verify-release-version.sh"
    run_checked([str(verifier)], REPO_ROOT)
    source_commit = run_checked(["git", "rev-parse", "HEAD"], REPO_ROOT)
    version_commit = run_checked(
        ["git", "log", "-1", "--format=%H", "--", "src/tools/secweaver-agent/VERSION"],
        REPO_ROOT,
    )

    with tempfile.TemporaryDirectory(prefix="secweaver-community-stage-") as directory:
        root = Path(directory)
        with tarfile.open(raw_archive, "r:gz") as archive:
            archive.extractall(root)
        provenance = root / "src/scripts/source_archive_provenance.py"
        run_checked(
            [
                os.environ.get("PYTHON", sys.executable),
                str(provenance),
                "create",
                "--root",
                str(root),
                "--source-commit",
                source_commit,
                "--version-commit",
                version_commit,
            ],
            root,
        )
        with tarfile.open(output, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for child in sorted(root.iterdir(), key=lambda path: path.name):
                archive.add(child, arcname=child.name, recursive=True)


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
    with tempfile.NamedTemporaryFile(prefix="secweaver-community-raw-", suffix=".tar.gz", delete=False) as handle:
        raw_archive = Path(handle.name)
    with tempfile.NamedTemporaryFile(prefix="secweaver-community-", suffix=".tar.gz", delete=False) as handle:
        temporary = Path(handle.name)
    try:
        result = subprocess.run(
            [
                "git",
                "archive",
                "--worktree-attributes",
                "--format=tar.gz",
                f"--output={raw_archive}",
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
        try:
            add_source_provenance(raw_archive, temporary)
        except RuntimeError as exc:
            print(f"ERROR: source archive provenance failed: {exc}")
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
        raw_archive.unlink(missing_ok=True)
        temporary.unlink(missing_ok=True)

    print(f"open-source archive: {output}")
    print("This archive is history-free. Never mirror or push the internal Git history to a public remote.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
