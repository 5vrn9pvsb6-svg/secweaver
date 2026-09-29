"""Regression coverage for history-free Agent release provenance."""

from __future__ import annotations

import importlib.util
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "src/scripts/source_archive_provenance.py"
SPEC = importlib.util.spec_from_file_location("source_archive_provenance", MODULE_PATH)
assert SPEC and SPEC.loader
PROVENANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVENANCE)


class TestSourceArchiveProvenance(unittest.TestCase):
    def make_archive_tree(self, directory: str) -> Path:
        root = Path(directory)
        agent = root / "src/tools/secweaver-agent"
        scripts = root / "src/scripts"
        agent.mkdir(parents=True)
        scripts.mkdir(parents=True)
        (agent / "VERSION").write_text("1.2.3\n", encoding="utf-8")
        (agent / "agent.go").write_text("package main\n", encoding="utf-8")
        shutil.copy2(REPO_ROOT / "src/scripts/source_fingerprint.py", scripts)
        return root

    def test_receipt_verifies_exact_history_free_tree(self) -> None:
        with TemporaryDirectory() as directory:
            root = self.make_archive_tree(directory)
            payload = PROVENANCE.create_provenance(root, "a" * 40, "b" * 40)

            verified = PROVENANCE.load_and_verify_provenance(root, "1.2.3")

            self.assertEqual(verified, payload)
            self.assertEqual(verified["source_commit"], "a" * 40)

    def test_receipt_rejects_agent_source_changes(self) -> None:
        with TemporaryDirectory() as directory:
            root = self.make_archive_tree(directory)
            PROVENANCE.create_provenance(root, "a" * 40, "b" * 40)
            (root / "src/tools/secweaver-agent/agent.go").write_text(
                "package main\n// changed\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "Agent source differs"):
                PROVENANCE.load_and_verify_provenance(root, "1.2.3")

    def test_receipt_rejects_fingerprint_tool_changes(self) -> None:
        with TemporaryDirectory() as directory:
            root = self.make_archive_tree(directory)
            PROVENANCE.create_provenance(root, "a" * 40, "b" * 40)
            with (root / "src/scripts/source_fingerprint.py").open("a", encoding="utf-8") as handle:
                handle.write("\n# changed\n")

            with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "fingerprint tool differs"):
                PROVENANCE.load_and_verify_provenance(root, "1.2.3")


if __name__ == "__main__":
    unittest.main()
