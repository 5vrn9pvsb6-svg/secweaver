#!/usr/bin/env python3
"""Compatibility entrypoint; pipeline orchestration lives in skill_runtime."""

import sys
from pathlib import Path

# Preserve direct script execution without installing a package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from skill_runtime.pipeline import main, run_alert, run_completeness, run_risk, run_traceability  # noqa: E402,F401

if __name__ == "__main__":
    raise SystemExit(main())
