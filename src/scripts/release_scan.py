#!/usr/bin/env python3
"""Pre-release hygiene checks for the open-source tree."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# These internal source roots are separate deliverables. Keep the scanner and
# git-archive boundary aligned so a forced add cannot leak them into a release.
OPEN_SOURCE_EXCLUDED_PREFIXES = (
    "dataasset_my/",
    "dataasset_es/",
    "dataasset_sls_proxy/",
    "docs_my/",
    "src/server/",
    "src/secweaver-server/",
    "book/",
    "portable/",
    "src/es-operator/",
)

TRACKED_PRIVATE_PREFIXES = (
    *OPEN_SOURCE_EXCLUDED_PREFIXES,
    "tmp/",
    "testdatasets/",
    "dataasset/credentials/secrets/",
)

PRIVATE_PREFIXES = TRACKED_PRIVATE_PREFIXES

# Internal captures and unversioned historical verification notes are not public
# release evidence. Keep their exclusion aligned with the archive attributes.
OPEN_SOURCE_EXCLUDED_FILES = {
    "src/tools/secweaver-agent/P0_FIXES_VERIFICATION_REPORT.md",
    "attack_test/environmentDeployment/Case1-SQLi-LFI-Alert-Confirmation.pdf",
    "attack_test/environmentDeployment/Case2-CmdI-MemoryWebshell.pdf",
    "attack_test/environmentDeployment/Case3-DataExfil-Fileless.pdf",
    "attack_test/environmentDeployment/Case4-Web-SSH-Lateral.pdf",
    "attack_test/environmentDeployment/SecWeaver-AI-Native-Security-Practice.pdf",
    "attack_test/environmentDeployment/attack-case-skill-analysis.md",
    "attack_test/environmentDeployment/attack-timeline-2026-07-05.md",
}

PRIVATE_FILES = {
    ".DS_Store",
    "dataasset_ts.zip",
    "src/skills/traceability-analysis/webhook-config.json",
}

# wis-log and gateway_plugin_log are intentionally public onboarding resource
# names. They do not grant access and must not trigger a private-marker failure;
# credentials and other private content in the same file are still scanned.
PRIVATE_MARKER_PATTERNS = (
    re.compile(r"tenant_id\s*[:=]\s*28"),
    # Split the literal so the scanner does not match its own policy definition.
    re.compile(r"code" + r"\.tiger-sec" + r"\.cn", re.IGNORECASE),
)

REQUIRED_PUBLIC_FILES = {
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "attack_test/README.md",
    "sbom/secweaver-source.cdx.json",
}

DATAASSET_PRIVATE_MARKER_PATTERNS = (
    re.compile(r"\btigersec\b", re.IGNORECASE),
    re.compile(r"\btsin\b", re.IGNORECASE),
    re.compile(r"\bmengxiang\b", re.IGNORECASE),
    re.compile(r"/opt/tslogs/", re.IGNORECASE),
    re.compile(r"\bage1[0-9a-z]{40,}\b"),
)

# These are public logical Logstore identities exposed by the SLS Proxy policy.
# Mask only exact tokens before scanning so physical resource names, suffixes,
# prefixes, credentials, and all other private markers remain blocking findings.
PUBLIC_DATAASSET_RESOURCE_NAMES = frozenset(
    {
        "tigersec-host-exec",
        "tigersec-sys-messages",
        "tigersec-tsin-access",
    }
)

IPV4_CANDIDATE_RE = re.compile(
    r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?"
)

RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# Public labs legitimately use RFC1918 topology, so the repository-wide scan
# cannot reject every private address. These split literals identify ranges
# observed in real acceptance environments and block them anywhere in a public
# release candidate without making the scanner match its own policy source.
KNOWN_INTERNAL_ACCEPTANCE_NETWORKS = (
    ipaddress.ip_network("10.0." + "6.0/24"),
)

# Match common developer checkout roots without rejecting operational examples
# such as /home/www/.ssh or standard Windows installation paths.
DEVELOPER_WORKSPACE_RE = re.compile(
    r"(?<![A-Za-z0-9_])/(?:Users|home)/[^/\s\"']+/(?:Desktop|Documents|Downloads|Projects|Workspace|workspace|work)/"
)

SECRET_PATTERNS = (
    re.compile(r"SEC[0-9a-fA-F]{32,}"),
    re.compile(r"LTAI[0-9A-Za-z]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
)

TEXT_SUFFIXES = {
    ".json",
    ".md",
    ".py",
    ".js",
    ".ts",
    ".yml",
    ".yaml",
    ".toml",
    ".sh",
    ".txt",
    ".go",
}

TEXT_FILENAMES = {
    ".gitignore",
    "Dockerfile",
    "Makefile",
}

MAX_TEXT_SCAN_BYTES = 2_000_000

IGNORED_DIRS = {
    ".git",
    ".venv",
    ".venv-fetch",
    "__pycache__",
    "node_modules",
}


@dataclass
class Issue:
    severity: str
    path: str
    message: str


def git_output(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout.decode("utf-8", errors="replace")


def split_z(text: str) -> list[str]:
    return [item for item in text.split("\0") if item]


def git_ls_files() -> list[str]:
    return split_z(git_output(["ls-files", "-z"]))


def git_staged_files() -> list[str]:
    return split_z(git_output(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT"]))


def git_untracked_files() -> list[str]:
    return split_z(git_output(["ls-files", "--others", "--exclude-standard", "-z"]))


def has_git_worktree() -> bool:
    """Return whether the scan root has Git metadata available.

    Community archives are intentionally history-free. The scanner must still
    inspect those extracted files, while repository checkouts retain the more
    precise tracked/staged/untracked Git views.
    """
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == b"true"


def filesystem_files() -> list[str]:
    """List scan candidates when a history-free source archive is extracted."""
    return [
        path.relative_to(REPO_ROOT).as_posix()
        for path in REPO_ROOT.rglob("*")
        if path.is_file()
    ]


def is_private_path(path: str) -> bool:
    return path in OPEN_SOURCE_EXCLUDED_FILES or any(
        path.startswith(prefix) for prefix in PRIVATE_PREFIXES
    )


def collect_candidate_paths(*, include_untracked: bool = True) -> list[str]:
    if has_git_worktree():
        paths = set(git_ls_files())
        paths.update(git_staged_files())
        if include_untracked:
            paths.update(git_untracked_files())
    else:
        # A git archive has no index or worktree metadata; inspect every
        # extracted file and apply the same private/ignored path filters below.
        paths = set(filesystem_files())
    return sorted(
        path
        for path in paths
        if path
        and not is_private_path(path)
        and not is_ignored_path(path)
        and (REPO_ROOT / path).exists()
    )


def check_export_policy() -> list[Issue]:
    issues: list[Issue] = []
    attributes = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
    for prefix in OPEN_SOURCE_EXCLUDED_PREFIXES:
        root = prefix.rstrip("/")
        if f"/{root}/ export-ignore" not in attributes:
            issues.append(Issue("error", ".gitattributes", f"missing export-ignore for private root: /{root}/"))
    for path in sorted(OPEN_SOURCE_EXCLUDED_FILES):
        if f"/{path} export-ignore" not in attributes and not (
            path.endswith(".pdf")
            and "/attack_test/environmentDeployment/*.pdf export-ignore" in attributes
        ):
            issues.append(Issue("error", ".gitattributes", f"missing export-ignore for internal file: /{path}"))
    return issues


def is_ignored_path(path: str) -> bool:
    parts = Path(path).parts
    return any(part in IGNORED_DIRS for part in parts)


def read_text(path: Path) -> str | None:
    if not path.is_file():
        return None
    if path.stat().st_size > MAX_TEXT_SCAN_BYTES:
        return None
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in TEXT_FILENAMES:
        try:
            sample = path.read_bytes()
        except OSError:
            return None
        if b"\0" in sample:
            return None
        try:
            return sample.decode("utf-8")
        except UnicodeDecodeError:
            return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def check_private_paths(paths: list[str]) -> list[Issue]:
    issues: list[Issue] = []
    for path in paths:
        if path in PRIVATE_FILES or path.endswith("/.DS_Store") or path.endswith(".zip"):
            issues.append(Issue("error", path, "private or generated file is present in release candidate"))
        for prefix in PRIVATE_PREFIXES:
            if path.startswith(prefix):
                issues.append(Issue("error", path, f"path under private prefix {prefix!r} is present in release candidate"))
    return issues


def check_required_public_files(paths: list[str]) -> list[Issue]:
    """Require legal and supply-chain metadata in every release candidate."""
    available = set(paths)
    return [
        Issue("error", path, "required public release file is missing")
        for path in sorted(REQUIRED_PUBLIC_FILES - available)
    ]


def check_community_version_consistency(root: Path = REPO_ROOT) -> list[Issue]:
    """Require every public Community version surface to match the latest changelog.

    The Agent version is deliberately excluded: it is an immutable component
    identity with an independent release lifecycle under secweaver-agent/VERSION.
    """
    text_sources = {
        # Component releases can appear above Community releases. Only a pure
        # SemVer heading defines the Community package identity.
        "CHANGELOG.md": (
            r"(?m)^## \[((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?)] - ",
            "latest release heading",
        ),
        "pyproject.toml": (r'(?m)^version\s*=\s*"([^"]+)"', "project version"),
        "src/secweaver.py": (r'version="SecWeaver CLI ([^"]+)"', "CLI version"),
    }
    versions: dict[str, str] = {}
    issues: list[Issue] = []
    for relative_path, (pattern, label) in text_sources.items():
        text = read_text(root / relative_path)
        match = re.search(pattern, text or "")
        if not match:
            issues.append(Issue("error", relative_path, f"cannot read Community {label}"))
            continue
        versions[relative_path] = match.group(1)

    sbom_path = "sbom/secweaver-source.cdx.json"
    try:
        sbom = json.loads((root / sbom_path).read_text(encoding="utf-8"))
        versions[sbom_path] = str(sbom["metadata"]["component"]["version"])
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
        issues.append(Issue("error", sbom_path, "cannot read Community SBOM root version"))

    expected = versions.get("CHANGELOG.md")
    if expected is None:
        return issues
    for relative_path, version in versions.items():
        if version != expected:
            issues.append(
                Issue(
                    "error",
                    relative_path,
                    f"Community version {version!r} does not match latest changelog version {expected!r}",
                )
            )
    return issues


def check_private_markers(paths: list[str]) -> list[Issue]:
    """Reject internal markers and local developer paths in public text.

    Runtime reports may contain local metadata. Published examples must instead
    use repository-relative paths. Common checkout roots are also rejected in
    source and docs while operational paths such as /home/www/.ssh remain valid.
    """
    issues: list[Issue] = []
    for path in paths:
        text = read_text(REPO_ROOT / path)
        if text is None:
            continue
        if path.startswith("examples/reports/") and re.search(r"/(?:Users|home)/[^/\s\"]+/|[A-Za-z]:[\\/]+Users[\\/]", text):
            issues.append(Issue("error", path, "published report contains a developer home path; use repository-relative metadata"))
        elif DEVELOPER_WORKSPACE_RE.search(text):
            issues.append(Issue("error", path, "public file contains a local developer workspace path; resolve paths at runtime"))
        for pattern in PRIVATE_MARKER_PATTERNS:
            if pattern.search(text):
                issues.append(Issue("error", path, f"file contains private marker: {pattern.pattern}"))
    return issues


def check_dataasset_private_content(paths: list[str]) -> list[Issue]:
    """Reject environment-specific identifiers and RFC1918 addresses in public assets."""
    issues: list[Issue] = []
    for path in paths:
        if not path.startswith("dataasset/"):
            continue
        text = read_text(REPO_ROOT / path)
        if text is None:
            continue

        # Public logical names are not secrets and are required by copyable
        # onboarding templates. Token boundaries prevent near-match bypasses.
        marker_scan_text = text
        for resource_name in PUBLIC_DATAASSET_RESOURCE_NAMES:
            marker_scan_text = re.sub(
                rf"(?<![A-Za-z0-9_-]){re.escape(resource_name)}(?![A-Za-z0-9_-])",
                "",
                marker_scan_text,
                flags=re.IGNORECASE,
            )
        for pattern in DATAASSET_PRIVATE_MARKER_PATTERNS:
            if pattern.search(path) or pattern.search(marker_scan_text):
                issues.append(
                    Issue("error", path, f"public dataasset contains private environment marker: {pattern.pattern}")
                )

        private_addresses: set[str] = set()
        for candidate in IPV4_CANDIDATE_RE.findall(text):
            address_text = candidate.split("/", 1)[0]
            try:
                address = ipaddress.ip_address(address_text)
            except ValueError:
                continue
            if any(address in network for network in RFC1918_NETWORKS):
                private_addresses.add(candidate)
        for candidate in sorted(private_addresses):
            issues.append(
                Issue("error", path, f"public dataasset contains RFC1918 address: {candidate}")
            )
    return issues


def check_known_internal_acceptance_networks(paths: list[str]) -> list[Issue]:
    """Reject known live-environment addresses from every public text file.

    Unlike public DataAsset, narrative docs and attack fixtures may need private
    topology. This narrow denylist protects ranges known to identify acceptance
    systems while preserving explicitly synthetic lab networks.
    """
    issues: list[Issue] = []
    for path in paths:
        text = read_text(REPO_ROOT / path)
        if text is None:
            continue
        blocked_addresses: set[str] = set()
        for candidate in IPV4_CANDIDATE_RE.findall(text):
            address_text = candidate.split("/", 1)[0]
            try:
                address = ipaddress.ip_address(address_text)
            except ValueError:
                continue
            if any(address in network for network in KNOWN_INTERNAL_ACCEPTANCE_NETWORKS):
                blocked_addresses.add(candidate)
        for candidate in sorted(blocked_addresses):
            issues.append(
                Issue(
                    "error",
                    path,
                    f"public release contains known internal acceptance address: {candidate}",
                )
            )
    return issues


def check_secret_patterns(paths: list[str]) -> list[Issue]:
    issues: list[Issue] = []
    for path in paths:
        text = read_text(REPO_ROOT / path)
        if text is None:
            continue
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                issues.append(Issue("error", path, f"possible secret matched pattern: {pattern.pattern}"))
    return issues


def check_placeholders(paths: list[str]) -> list[Issue]:
    issues: list[Issue] = []
    for path in paths:
        if path not in {"README.md", "README.zh-CN.md", "CONTRIBUTING.md"} and not path.startswith(".github/"):
            continue
        text = read_text(REPO_ROOT / path)
        if text and "YOUR_ORG" in text:
            issues.append(Issue("warning", path, "YOUR_ORG placeholder remains in public contributor metadata"))
    return issues


def run_scan(*, include_untracked: bool = True) -> list[Issue]:
    paths = collect_candidate_paths(include_untracked=include_untracked)
    issues: list[Issue] = []
    issues.extend(check_export_policy())
    issues.extend(check_required_public_files(paths))
    issues.extend(check_community_version_consistency())
    issues.extend(check_private_paths(paths))
    issues.extend(check_private_markers(paths))
    issues.extend(check_dataasset_private_content(paths))
    issues.extend(check_known_internal_acceptance_networks(paths))
    issues.extend(check_secret_patterns(paths))
    issues.extend(check_placeholders(paths))
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SecWeaver open-source release hygiene checks.")
    parser.add_argument("--json", action="store_true", help="Print structured JSON output.")
    parser.add_argument("--tracked-only", action="store_true", help="Only scan tracked/staged files. Default also scans untracked files.")
    args = parser.parse_args()

    issues = run_scan(include_untracked=not args.tracked_only)
    errors = [issue for issue in issues if issue.severity == "error"]
    if args.json:
        print(
            json.dumps(
                {
                    "ok": not errors,
                    "summary": {
                        "error_count": len(errors),
                        "warning_count": len(issues) - len(errors),
                    },
                    "issues": [issue.__dict__ for issue in issues],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        for issue in issues:
            prefix = "ERROR" if issue.severity == "error" else "WARN"
            print(f"{prefix}: {issue.path}: {issue.message}", file=sys.stderr)
        print(
            f"release-scan: {len(errors)} error(s), {len(issues) - len(errors)} warning(s)",
            file=sys.stderr,
        )
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
