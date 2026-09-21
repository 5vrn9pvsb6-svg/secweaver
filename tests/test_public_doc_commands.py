"""Regression tests for the public-document private-command gate."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPO_ROOT / "src" / "scripts" / "check_public_doc_commands.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_public_doc_commands", CHECKER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CHECKER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestPublicDocCommands(unittest.TestCase):
    def setUp(self) -> None:
        self.checker = load_checker()

    def test_unmarked_private_command_is_rejected(self) -> None:
        path = REPO_ROOT / "README.md"
        issues = self.checker.check_text(path, "```bash\nsrc/es-operator/secweaver-portable up\n```")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].line, 2)

    def test_unmarked_private_wildcard_reference_is_rejected(self) -> None:
        path = REPO_ROOT / "README.md"
        issues = self.checker.check_text(path, "See `src/server/*` for deployment commands.\n")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].reference, "src/server/*")

    def test_adjacent_private_delivery_marker_allows_command(self) -> None:
        path = REPO_ROOT / "README.md"
        text = "<!-- private-delivery: supplied separately -->\n```bash\nsudo src/server/install.sh\n```"
        self.assertEqual(self.checker.check_text(path, text), [])

    def test_public_tree_has_no_unmarked_private_commands(self) -> None:
        self.assertEqual(self.checker.run([]), [])


if __name__ == "__main__":
    unittest.main()
