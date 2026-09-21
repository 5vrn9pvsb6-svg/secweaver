#!/usr/bin/env python3
"""Validate every local DataAsset root and shared platform contracts."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from .validate import REPO_ROOT, validate
except ImportError:  # Direct script execution has no package context.
    from validate import REPO_ROOT, validate

PUBLIC_ROOT = REPO_ROOT / "dataasset"
SHARED_CONTRACT_FILES = (
    "configure/connector-catalog.json",
    "configure/external-connectors.json",
    "schema/connector-catalog.schema.json",
    "schema/connector-onboarding-profile.schema.json",
    "schema/external-connectors.schema.json",
)
ONBOARDING_FILENAMES = ("asset.json", "connector.json", "template.snippet.json")
POLICY_PATH = Path("configure/shared-contracts.json")
POLICY_SCHEMA_PATH = Path("schema/shared-contracts.schema.json")


def discover_roots(repo_root: Path = REPO_ROOT) -> list[Path]:
    """Find checked-in roots while excluding similarly named code/UI folders."""
    candidates = [repo_root / "dataasset", *sorted(repo_root.glob("dataasset_*"))]
    return [
        path.resolve()
        for path in candidates
        if (path / "configure").is_dir() and (path / "schema").is_dir()
    ]


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_policy(public_root: Path) -> dict[str, Any] | None:
    path = public_root / POLICY_PATH
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: policy must be a JSON object")
    return payload


def _patterns(policy: dict[str, Any], category: str) -> list[str]:
    """Normalize simple shared entries and reasoned override/root entries."""
    values = policy.get(category) or []
    result: list[str] = []
    for value in values:
        if isinstance(value, str):
            result.append(value)
        elif isinstance(value, dict) and isinstance(value.get("pattern"), str):
            result.append(value["pattern"])
    return result


def _matches(relative: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(relative, pattern)


def _expand(root: Path, patterns: list[str]) -> set[str]:
    """Expand policy patterns only across files already inside a registry root."""
    files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }
    return {relative for relative in files if any(_matches(relative, pattern) for pattern in patterns)}


def contract_policy_issues(
    roots: list[Path],
    *,
    public_root: Path = PUBLIC_ROOT,
) -> list[dict[str, str]]:
    """Verify that every governed JSON file has one explicit ownership class.

    Classifying all roots prevents a newly added private object from silently
    becoming a shared contract, while requiring a reason for intentional drift.
    Credentials are outside contract_scope and are never opened here.
    """
    public_root = public_root.resolve()
    try:
        policy = _read_policy(public_root)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [{"root": str(public_root), "path": str(POLICY_PATH), "reason": f"invalid policy: {exc}"}]
    if policy is None:
        return [{"root": str(public_root), "path": str(POLICY_PATH), "reason": "missing policy"}]

    issues: list[dict[str, str]] = []
    schema_path = public_root / POLICY_SCHEMA_PATH
    if not schema_path.is_file():
        issues.append({"root": str(public_root), "path": str(POLICY_SCHEMA_PATH), "reason": "missing schema"})
    else:
        try:
            import jsonschema

            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            for error in jsonschema.Draft202012Validator(schema).iter_errors(policy):
                location = ".".join(str(item) for item in error.path) or "(root)"
                issues.append(
                    {
                        "root": str(public_root),
                        "path": str(POLICY_PATH),
                        "reason": f"schema [{location}]: {error.message}",
                    }
                )
        except ImportError:
            issues.append(
                {
                    "root": str(public_root),
                    "path": str(POLICY_SCHEMA_PATH),
                    "reason": "jsonschema dependency is required to validate contract policy",
                }
            )
        except (OSError, json.JSONDecodeError) as exc:
            issues.append({"root": str(public_root), "path": str(POLICY_SCHEMA_PATH), "reason": f"invalid schema: {exc}"})

    categories = {
        category: _patterns(policy, category)
        for category in ("shared", "override", "root_owned")
    }
    scope_patterns = [str(pattern) for pattern in policy.get("contract_scope") or []]
    for pattern in categories["shared"]:
        if not _expand(public_root, [pattern]):
            issues.append(
                {
                    "root": str(public_root),
                    "path": pattern,
                    "reason": "shared pattern matches no canonical file",
                }
            )

    for root in roots:
        normalized_root = root.resolve()
        for relative in sorted(_expand(normalized_root, scope_patterns)):
            matched = [
                category
                for category, patterns in categories.items()
                if any(_matches(relative, pattern) for pattern in patterns)
            ]
            if len(matched) != 1:
                reason = "unclassified" if not matched else f"classified more than once: {matched}"
                issues.append({"root": str(normalized_root), "path": relative, "reason": reason})
    return issues


def shared_contract_paths(public_root: Path = PUBLIC_ROOT) -> list[str]:
    """Return files whose bytes define shared behavior across local overlays."""
    policy = _read_policy(public_root.resolve())
    if policy is not None:
        return sorted(_expand(public_root.resolve(), _patterns(policy, "shared")))

    # Compatibility fallback keeps standalone callers and older registry fixtures
    # working until they add the explicit shared-contract policy.
    paths = list(SHARED_CONTRACT_FILES)
    onboarding = public_root / "onboarding"
    if onboarding.is_dir():
        for directory in sorted(path for path in onboarding.iterdir() if path.is_dir()):
            for filename in ONBOARDING_FILENAMES:
                if (directory / filename).is_file():
                    paths.append((Path("onboarding") / directory.name / filename).as_posix())
    return paths


def contract_drift(
    roots: list[Path],
    *,
    public_root: Path = PUBLIC_ROOT,
) -> list[dict[str, str]]:
    """Compare shared catalogs, schemas and skeletons without reading credentials."""
    public_root = public_root.resolve()
    drift: list[dict[str, str]] = []
    policy = _read_policy(public_root)
    shared_patterns = _patterns(policy, "shared") if policy is not None else []
    expected_paths = set(shared_contract_paths(public_root))
    for root in roots:
        if root.resolve() == public_root:
            continue
        for relative in sorted(expected_paths):
            expected = public_root / relative
            actual = root / relative
            if not actual.is_file():
                drift.append({"root": str(root), "path": relative, "reason": "missing"})
            elif _digest(expected) != _digest(actual):
                drift.append({"root": str(root), "path": relative, "reason": "content differs"})
        if shared_patterns:
            for relative in sorted(_expand(root, shared_patterns) - expected_paths):
                drift.append({"root": str(root), "path": relative, "reason": "unexpected shared file"})
    return drift


def validate_all_roots(roots: list[Path], *, strict: bool = False) -> dict[str, Any]:
    """Aggregate validation results and treat shared-contract drift as an error."""
    normalized = [root.expanduser().resolve() for root in roots]
    root_results: list[dict[str, Any]] = []
    blocking = 0
    for root in normalized:
        report = validate(root)
        payload = report.as_json(strict=strict)
        root_results.append(
            {
                "root": str(root),
                "ok": payload["ok"],
                "summary": payload["summary"],
                "issues": payload["issues"],
            }
        )
        blocking += int(payload["summary"]["blocking_count"])

    policy_issues = contract_policy_issues(normalized)
    drift = contract_drift(normalized)
    blocking += len(policy_issues) + len(drift)
    return {
        "ok": blocking == 0,
        "strict": strict,
        "summary": {
            "root_count": len(normalized),
            "contract_policy_issue_count": len(policy_issues),
            "contract_drift_count": len(drift),
            "blocking_count": blocking,
        },
        "roots": root_results,
        "contract_policy_issues": policy_issues,
        "contract_drift": drift,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate all DataAsset roots and shared contracts")
    parser.add_argument("--root", action="append", type=Path, help="root to validate; repeatable")
    parser.add_argument("--strict", action="store_true", help="treat warnings as blocking")
    parser.add_argument("--json", action="store_true", dest="json_output", help="print JSON report")
    args = parser.parse_args()

    roots = args.root or discover_roots()
    result = validate_all_roots(roots, strict=args.strict)
    if args.json_output:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for item in result["roots"]:
            summary = item["summary"]
            print(
                f"{item['root']}: {summary['error_count']} error(s), "
                f"{summary['warning_count']} warning(s), "
                f"{summary['blocking_count']} blocking issue(s)"
            )
        for item in result["contract_drift"]:
            print(f"CONTRACT DRIFT: {item['root']}/{item['path']}: {item['reason']}")
        for item in result["contract_policy_issues"]:
            print(f"CONTRACT POLICY: {item['root']}/{item['path']}: {item['reason']}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
