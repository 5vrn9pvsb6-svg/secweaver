#!/usr/bin/env python3
"""Unified unittest entry for SecWeaver open-source tests."""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# unittest discovery temporarily treats each suite directory as an import root.
# Keep repository packages importable for tests that use absolute ``src.*`` imports.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TEST_SUITES: tuple[tuple[str, str], ...] = (
    ("tests", "test_*.py"),
    ("src/skills/_shared/data-access/tests", "test_*.py"),
    ("src/skills/data-source-completeness/scripts/tests", "test_*.py"),
    ("src/skills/risk-identification/scripts/tests", "test_*.py"),
    ("src/skills/risk-identification/tests", "test_*.py"),
    ("src/skills/log-format-discovery/scripts/tests", "test_*.py"),
    ("src/skills/traceability-analysis/scripts/tests", "test_*.py"),
    ("src/skills/alert-confirmation/scripts/tests", "test_*.py"),
    ("src/skills/evidence-fetch/tests", "test_*.py"),
)


def build_suite() -> unittest.TestSuite:
    """Discover every public Python suite required by Community archives.

    Server runtimes are implemented and tested in Go. Keeping retired Python
    server tests here would preserve a second, conflicting source of behavior.
    """
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for relative_dir, pattern in TEST_SUITES:
        start_dir = REPO_ROOT / relative_dir
        if not start_dir.is_dir():
            raise FileNotFoundError(f"test directory not found: {start_dir}")
        discovered = loader.discover(str(start_dir), pattern=pattern)
        suite.addTests(discovered)
    return suite


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run all SecWeaver open-source unit tests.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose unittest output.")
    args = parser.parse_args(argv)

    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(build_suite())
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
