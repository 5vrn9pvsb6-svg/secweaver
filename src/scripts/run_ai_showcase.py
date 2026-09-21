#!/usr/bin/env python3
"""Run all credential-free Showcase cases by default, or one explicit case."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

# Support both the documented script entrypoint and package imports in tests.
if __package__:
    from .ai_showcase_reports import limitations, render_case, render_suite, verdict
else:
    from ai_showcase_reports import limitations, render_case, render_suite, verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = REPO_ROOT / "examples/ai-showcase/cases.json"
CLI_PATH = REPO_ROOT / "src/secweaver.py"
FORBIDDEN_LIVE_ARGS = {"--fetch", "--notify"}


def load_catalog() -> dict[str, Any]:
    """Load the committed catalog and reject a non-offline top-level contract."""
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    if catalog.get("offline") is not True:
        raise ValueError("AI Showcase catalog must declare offline=true")
    cases = catalog.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("AI Showcase catalog requires a non-empty cases array")
    return catalog


def select_case(catalog: dict[str, Any], case_id: str) -> dict[str, Any]:
    """Resolve a single explicit ID; omission is handled by the suite entrypoint."""
    for case in catalog["cases"]:
        if case.get("case_id") == case_id:
            return case
    available = ", ".join(str(case.get("case_id")) for case in catalog["cases"])
    raise ValueError(f"unknown showcase case {case_id!r}; available: {available}")


def resolve_repo_file(relative: str, *, label: str) -> Path:
    """Resolve a catalog file while preventing paths from escaping the checkout."""
    path = (REPO_ROOT / relative).resolve()
    try:
        path.relative_to(REPO_ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} escapes repository: {relative}") from exc
    if not path.is_file():
        raise ValueError(f"{label} does not exist: {relative}")
    return path


def expected_mismatches(actual: Any, expected: Any, path: str = "result") -> list[str]:
    """Compare only stable catalog fields so richer Skill output can evolve safely."""
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [f"{path}: expected object, got {type(actual).__name__}"]
        issues: list[str] = []
        for key, value in expected.items():
            if key not in actual:
                issues.append(f"{path}.{key}: missing")
                continue
            issues.extend(expected_mismatches(actual[key], value, f"{path}.{key}"))
        return issues
    return [] if actual == expected else [f"{path}: expected {expected!r}, got {actual!r}"]


def validate_case(case: dict[str, Any]) -> None:
    """Enforce the no-network showcase boundary before starting a Skill process.

    Traceability resolves public-IP intelligence by default even with --fetch
    disabled, so its offline entry must explicitly opt out of that lookup.
    """
    if case.get("offline") is not True:
        raise ValueError(f"case {case.get('case_id')} must declare offline=true")
    resolve_repo_file(str(case.get("input", "")), label="case input")
    resolve_repo_file(str(case.get("skill_doc", "")), label="Skill document")
    cli_args = case.get("cli_args")
    if not isinstance(cli_args, list) or cli_args[:2] != ["skill", case.get("skill")]:
        raise ValueError(f"case {case.get('case_id')} has invalid cli_args")
    forbidden = FORBIDDEN_LIVE_ARGS.intersection(str(arg) for arg in cli_args)
    if forbidden:
        raise ValueError(f"case {case.get('case_id')} enables live behavior: {sorted(forbidden)}")
    if case.get("skill") == "traceability-analysis":
        for required in ("--no-notify", "--no-ip-intel"):
            if required not in cli_args:
                raise ValueError(f"case {case.get('case_id')} requires {required} for offline use")


def run_case(case: dict[str, Any], output_dir: Path | None = None) -> dict[str, Any]:
    """Verify a case and save JSON plus a readable report before declaring success.

    A report write failure is a case failure, so a successful run never silently
    means JSON-only completion. Reruns replace both artifacts; host-authored
    interpretation must be refreshed against this run's evidence afterwards.
    """
    validate_case(case)
    process = subprocess.run(
        [sys.executable, str(CLI_PATH), *case["cli_args"]],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise RuntimeError(f"showcase case {case['case_id']} failed: {detail}")
    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"showcase case {case['case_id']} returned invalid JSON") from exc

    mismatches = expected_mismatches(result, case.get("expected", {}))
    if mismatches:
        raise RuntimeError("showcase expectation mismatch:\n- " + "\n- ".join(mismatches))

    if output_dir is None:
        output_path = REPO_ROOT / str(case["output"])
        allowed_root = (REPO_ROOT / "outputs/ai-showcase").resolve()
        try:
            output_path.resolve().relative_to(allowed_root)
        except ValueError as exc:
            raise ValueError(f"case output must stay under outputs/ai-showcase: {case['output']}") from exc
    else:
        output_path = output_dir.expanduser().resolve() / f"{case['case_id']}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    input_path = resolve_repo_file(str(case["input"]), label="case input")
    evidence = json.loads(input_path.read_text(encoding="utf-8"))
    report_path = output_path.with_suffix(".md")
    report_path.write_text(render_case(case, evidence, result, input_path, output_path), encoding="utf-8")
    return {
        "ok": True,
        "offline": True,
        "case_id": case["case_id"],
        "skill": case["skill"],
        "output": output_path.as_posix(),
        "report": report_path.as_posix(),
        "report_kind": "structured_result",
        "verdict": verdict(result),
        "limitations": limitations(result),
        "expected_verdict_matched": True,
    }


def run_suite(catalog: dict[str, Any], output_dir: Path | None = None) -> dict[str, Any]:
    """Attempt every catalog entry in order and persist this run's success/failure list.

    Sequential subprocesses bound resource use, with run_case's 60-second timeout
    per case. A failed case must not hide later regressions. Failed entries expose
    no output link: a file left by an older run is not evidence of current success.
    """
    results: list[dict[str, Any]] = []
    for case in catalog["cases"]:
        try:
            results.append(run_case(case, output_dir))
        except (OSError, RuntimeError, UnicodeError, ValueError, subprocess.TimeoutExpired) as exc:
            results.append({"ok": False, "case_id": case["case_id"], "error": str(exc)})
    passed = sum(result["ok"] for result in results)
    summary = {
        "ok": passed == len(results), "offline": True, "mode": "all",
        "total": len(results), "passed": passed, "failed": len(results) - passed,
        "results": results,
    }
    destination = output_dir or REPO_ROOT / "outputs/ai-showcase"
    destination = destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    summary["output"] = str(destination / "suite-summary.json")
    summary["report"] = str(destination / "suite-summary.md")
    summary["report_kind"] = "structured_result"
    Path(summary["report"]).write_text(render_suite(summary), encoding="utf-8")
    Path(summary["output"]).write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    """Default to the whole catalog while preserving explicit single-case output."""
    parser = argparse.ArgumentParser(description="Run offline SecWeaver cases and write JSON + readable Markdown reports.")
    parser.add_argument("case_id", nargs="?", help="Run only this case ID; omitted means all cases.")
    parser.add_argument("--all", action="store_true", help="Explicitly run all catalog cases (the default).")
    parser.add_argument("--list", action="store_true", help="List available offline cases without running one.")
    parser.add_argument("--json", action="store_true", help="Print the run summary as JSON.")
    parser.add_argument("--output-dir", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.all and args.case_id:
        parser.error("--all cannot be combined with a case ID")

    try:
        catalog = load_catalog()
        if args.list:
            for case in catalog["cases"]:
                print(f"{case['case_id']}: {case['title']}")
            return 0
        summary = (run_case(select_case(catalog, args.case_id), args.output_dir)
                   if args.case_id else run_suite(catalog, args.output_dir))
    except (OSError, RuntimeError, UnicodeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    elif summary.get("mode") == "all":
        for result in summary["results"]:
            print(f"{'PASS' if result['ok'] else 'FAIL'}: {result['case_id']}")
            print(f"Result: {result['output']}" if result["ok"] else f"Error: {result['error']}")
            if result["ok"]:
                print(f"Report: {result['report']}")
        print(f"Offline showcase: {summary['passed']}/{summary['total']} passed; {summary['failed']} failed")
        print(f"Summary: {summary['output']}")
        print(f"Report: {summary['report']}")
    else:
        print(f"Offline showcase passed: {summary['case_id']}")
        print(f"Skill: {summary['skill']}")
        print(f"Result: {summary['output']}")
        print(f"Report: {summary['report']}")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
