"""Run the real browser credential save logic without accessing local secrets."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


@unittest.skipUnless(shutil.which("node"), "Node.js is required for the UI JavaScript regression")
class TestCredentialForm(unittest.TestCase):
    def test_namespace_is_independent_from_credential_type(self) -> None:
        """Synthetic DOM/API fixtures cover the save path, not source-text assertions."""
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [shutil.which("node"), str(root / "tests" / "ui" / "credential-form.cjs")],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
