#!/usr/bin/env python3
"""Reject private-delivery source commands from public Markdown documents."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PRIVATE_DOC_DIRS = {
    ".git",
    ".venv",
    ".venv-fetch",
    "__pycache__",
    "book",
    "dataasset_es",
    "dataasset_my",
    "dataasset_sls_proxy",
    "docs_my",
    "dist",
    "node_modules",
    "private",
    "runtime",
    "tmp",
}
PRIVATE_DELIVERY_MARKER = re.compile(r"<!--\s*private-delivery(?:\s*:[^>]*)?\s*-->", re.IGNORECASE)
# Keep both names recognized so historical documents cannot bypass the gate after
# the private operator implementation moved from ``src/portable``.
PRIVATE_COMMAND_RE = re.compile(r"(?<![A-Za-z0-9_])src/(?:portable|es-operator|server)/[A-Za-z0-9_./:${}~+*-]+")
MARKER_LOOKBACK_LINES = 4


@dataclass
class Issue:
    path: str
    line: int
    reference: str
    message: str


def is_private_doc_path(path: Path) -> bool:
    """Skip private and generated trees so the gate models the public archive."""
    try:
        relative = path.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        return False
    parts = relative.parts
    if any(part in PRIVATE_DOC_DIRS for part in parts):
        return True
    relative_name = relative.as_posix()
    return relative_name in {"src/server", "src/es-operator", "portable"} or relative_name.startswith(
        ("src/server/", "src/es-operator/", "portable/")
    )


def markdown_files(paths: list[str]) -> list[Path]:
    candidates = [(REPO_ROOT / item).resolve() for item in paths] if paths else [REPO_ROOT]
    files: list[Path] = []
    for candidate in candidates:
        if candidate.is_dir():
            files.extend(
                path
                for path in sorted(candidate.rglob("*.md"))
                if not is_private_doc_path(path)
            )
        elif candidate.suffix.lower() == ".md" and candidate.exists() and not is_private_doc_path(candidate):
            files.append(candidate)
    return sorted(set(files))


def check_text(path: Path, text: str) -> list[Issue]:
    """Require an adjacent HTML marker for every private source command reference.

    A four-line lookback lets a marker sit immediately above a fenced command block,
    while keeping accidental prose references from silently authorizing private paths.
    """
    lines = text.splitlines()
    issues: list[Issue] = []
    for index, line in enumerate(lines):
        for match in PRIVATE_COMMAND_RE.finditer(line):
            start = max(0, index - MARKER_LOOKBACK_LINES)
            context = "\n".join(lines[start : index + 1])
            if PRIVATE_DELIVERY_MARKER.search(context):
                continue
            issues.append(
                Issue(
                    path=path.relative_to(REPO_ROOT).as_posix(),
                    line=index + 1,
                    reference=match.group(0),
                    message="private source command requires <!-- private-delivery --> marker",
                )
            )
    return issues


def check_file(path: Path) -> list[Issue]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    return check_text(path, text)


def run(paths: list[str]) -> list[Issue]:
    issues: list[Issue] = []
    for path in markdown_files(paths):
        issues.extend(check_file(path))
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Check public Markdown for private source commands.")
    parser.add_argument("paths", nargs="*", help="Markdown files or directories; defaults to the repository")
    parser.add_argument("--json", action="store_true", help="Print structured JSON output")
    args = parser.parse_args()
    issues = run(args.paths)
    if args.json:
        print(json.dumps({"ok": not issues, "summary": {"issue_count": len(issues)}, "issues": [issue.__dict__ for issue in issues]}, ensure_ascii=False, indent=2))
    else:
        for issue in issues:
            print(f"ERROR: {issue.path}:{issue.line}: {issue.reference}: {issue.message}", file=sys.stderr)
        print(f"public-doc-command-check: {len(issues)} issue(s)", file=sys.stderr)
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
