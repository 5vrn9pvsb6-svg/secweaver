#!/usr/bin/env python3
"""Compatibility entrypoint; prepare orchestration lives in skill_runtime."""

import sys
from pathlib import Path

# Preserve direct script execution without installing a package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from skill_runtime.prepare import main  # noqa: E402,F401

if __name__ == "__main__":
    raise SystemExit(main())
