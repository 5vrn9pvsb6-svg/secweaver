#!/usr/bin/env python3
"""Check local Markdown links without requiring network access."""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
LINK_RE = re.compile(r"!?\[[^\]]*]\(([^)]+)\)")
HEADING_RE = re.compile(r"^\s{0,3}#{1,6}[ \t]+(.+?)[ \t]*#*[ \t]*$")
EXPLICIT_ANCHOR_RE = re.compile(r"<a\s+[^>]*(?:id|name)\s*=\s*[\"']([^\"']+)[\"'][^>]*>", re.IGNORECASE)
FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
IGNORED_DIRS = {
    ".cache",
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


@dataclass
class Issue:
    path: str
    target: str
    message: str


def is_ignored(path: Path) -> bool:
    """Apply exclusions to repository-relative parts, never ancestor directories.

    Community archives are commonly extracted below ``/tmp``. Looking at every
    absolute path component would therefore skip the entire release candidate.
    """
    try:
        relative = path.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        return False
    relative_name = relative.as_posix()
    # Private source trees are excluded by their explicit repository roots;
    # do not skip unrelated documentation merely because it has a ``server``
    # or ``portable`` directory of its own.
    if relative_name in {"src/server", "src/es-operator", "portable"} or relative_name.startswith(
        ("src/server/", "src/es-operator/", "portable/")
    ):
        return True
    return any(part in IGNORED_DIRS for part in relative.parts)


def markdown_files(paths: list[str]) -> list[Path]:
    if paths:
        candidates = [(REPO_ROOT / path).resolve() for path in paths]
    else:
        candidates = sorted(REPO_ROOT.rglob("*.md"))
    files: list[Path] = []
    for candidate in candidates:
        if is_ignored(candidate):
            continue
        if candidate.is_dir():
            files.extend(path for path in sorted(candidate.rglob("*.md")) if not is_ignored(path))
        elif candidate.suffix.lower() == ".md" and candidate.exists():
            files.append(candidate)
    return sorted(set(files))


def normalize_target(raw: str) -> str:
    target = raw.strip()
    if " " in target and not target.startswith("<"):
        target = target.split(" ", 1)[0]
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    return target.strip()


def should_skip(target: str) -> bool:
    if not target:
        return True
    parsed = urlparse(target)
    return bool(parsed.netloc) or bool(parsed.scheme)


def target_path(source: Path, target: str) -> Path | None:
    clean = normalize_target(target)
    if should_skip(clean):
        return None
    path_text = unquote(urlparse(clean).path)
    if not path_text:
        return source.resolve()
    path = Path(path_text)
    if path.is_absolute():
        return None
    return (source.parent / path).resolve()


def target_fragment(target: str) -> str:
    """Return the decoded local fragment, excluding URL query parameters."""
    clean = normalize_target(target)
    if should_skip(clean):
        return ""
    return unquote(urlparse(clean).fragment)


def github_heading_slug(heading: str) -> str:
    """Approximate GitHub/CommonMark heading IDs for repository documentation.

    GitHub removes punctuation before replacing each whitespace character with a
    hyphen. Keeping individual spaces is intentional: ``D1 ↔ D2`` becomes
    ``d1--d2``, which is relied on by existing cross-source documentation.
    Explicit ``<a id=...>`` anchors remain the preferred compatibility contract
    when a heading contains punctuation whose renderer behavior may vary.
    """
    heading = re.sub(r"<[^>]+>", "", heading)
    heading = re.sub(r"!\[([^]]*)]\([^)]*\)", r"\1", heading)
    heading = re.sub(r"\[([^]]+)]\([^)]*\)", r"\1", heading)
    heading = heading.replace("`", "").replace("*", "").lower()
    retained: list[str] = []
    for character in heading:
        category = unicodedata.category(character)
        if character in {"-", "_"} or character.isspace() or category[0] in {"L", "N"}:
            retained.append(character)
    return "".join("-" if character.isspace() else character for character in retained).strip("-")


def markdown_anchors(path: Path) -> set[str]:
    """Collect renderer-style heading IDs and stable explicit HTML anchors.

    Fenced code is excluded because examples often contain Markdown snippets
    that must not become navigable document sections. Duplicate headings use
    GitHub's ``-1``, ``-2`` suffix convention.
    """
    text = path.read_text(encoding="utf-8")
    anchors: set[str] = set()
    heading_counts: dict[str, int] = {}
    fence_character = ""
    fence_length = 0
    for line in text.splitlines():
        fence = FENCE_RE.match(line)
        if fence:
            marker = fence.group(1)
            if not fence_character:
                fence_character = marker[0]
                fence_length = len(marker)
            elif marker[0] == fence_character and len(marker) >= fence_length:
                fence_character = ""
                fence_length = 0
            continue
        if fence_character:
            continue
        anchors.update(unquote(anchor) for anchor in EXPLICIT_ANCHOR_RE.findall(line))
        heading = HEADING_RE.match(line)
        if not heading:
            continue
        base = github_heading_slug(heading.group(1))
        if not base:
            continue
        duplicate_index = heading_counts.get(base, 0)
        heading_counts[base] = duplicate_index + 1
        anchors.add(base if duplicate_index == 0 else f"{base}-{duplicate_index}")
    return anchors


def check_file(path: Path) -> list[Issue]:
    issues: list[Issue] = []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return issues
    anchor_cache: dict[Path, set[str]] = {}
    for match in LINK_RE.finditer(text):
        raw_target = match.group(1)
        resolved = target_path(path, raw_target)
        if resolved is None:
            continue
        try:
            resolved.relative_to(REPO_ROOT)
        except ValueError:
            issues.append(Issue(path.relative_to(REPO_ROOT).as_posix(), raw_target, "link escapes repository"))
            continue
        if not resolved.exists():
            issues.append(Issue(path.relative_to(REPO_ROOT).as_posix(), raw_target, "local link target does not exist"))
            continue
        fragment = target_fragment(raw_target)
        if fragment and resolved.is_file() and resolved.suffix.lower() == ".md":
            try:
                # A long index may link to the same target many times; parse that
                # target once per source file to keep the repository scan bounded.
                if resolved not in anchor_cache:
                    anchor_cache[resolved] = markdown_anchors(resolved)
                anchors = anchor_cache[resolved]
            except UnicodeDecodeError:
                continue
            if fragment not in anchors:
                issues.append(
                    Issue(path.relative_to(REPO_ROOT).as_posix(), raw_target, "local Markdown anchor does not exist")
                )
    return issues


def run(paths: list[str]) -> list[Issue]:
    issues: list[Issue] = []
    for path in markdown_files(paths):
        issues.extend(check_file(path))
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Check local Markdown links in the repository.")
    parser.add_argument("paths", nargs="*", help="Markdown files or directories. Defaults to all *.md files.")
    parser.add_argument("--json", action="store_true", help="Print structured JSON output.")
    args = parser.parse_args()

    issues = run(args.paths)
    if args.json:
        print(
            json.dumps(
                {
                    "ok": not issues,
                    "summary": {"issue_count": len(issues)},
                    "issues": [issue.__dict__ for issue in issues],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        for issue in issues:
            print(f"ERROR: {issue.path}: {issue.target}: {issue.message}", file=sys.stderr)
        print(f"docs-link-check: {len(issues)} issue(s)", file=sys.stderr)
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
