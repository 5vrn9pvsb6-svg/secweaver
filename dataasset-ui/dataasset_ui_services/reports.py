"""Demo report helpers for the DataAsset UI."""

from __future__ import annotations

import subprocess

from .common import REPORTS_DIR, ROOT, SECWEAVER_CLI, read_json, rel_to_root, subprocess_env, validation_python


def read_reports() -> dict:
    report_files = {
        "completeness": "demo-completeness-output.json",
        "alert": "demo-alert-output.json",
        "traceability": "demo-traceability-output.json",
        "risk": "demo-risk-output.json",
    }
    reports: dict[str, dict] = {}
    for name, filename in report_files.items():
        path = REPORTS_DIR / filename
        if path.exists():
            reports[name] = {
                "file": rel_to_root(path),
                "data": read_json(path),
            }
        else:
            reports[name] = {
                "file": rel_to_root(path),
                "missing": True,
            }
    return reports


def run_demo_all() -> subprocess.CompletedProcess[str]:
    python_bin = validation_python()
    return subprocess.run(
        [python_bin, str(SECWEAVER_CLI), "demo", "all"],
        cwd=ROOT,
        env=subprocess_env(),
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )
