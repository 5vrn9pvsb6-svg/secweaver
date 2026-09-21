"""Regression tests for repository-local AI host adapter generation."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
AI_HOST_SETUP = REPO_ROOT / "src/scripts/ai_host_setup.py"


def load_ai_host_setup():
    """Load the standalone maintenance script under unittest discovery."""
    spec = importlib.util.spec_from_file_location("ai_host_setup", AI_HOST_SETUP)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {AI_HOST_SETUP}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ai_host_setup = load_ai_host_setup()


class TestAiHostSetup(unittest.TestCase):
    def make_repo(self, root: Path) -> None:
        """Create the minimum canonical Skill tree accepted by the setup command."""
        skill_root = root / "src/skills/example"
        skill_root.mkdir(parents=True)
        (root / "src/skills/README.md").write_text("# canonical index\n", encoding="utf-8")
        (skill_root / "SKILL.md").write_text("# canonical implementation sentinel\n", encoding="utf-8")

    def test_all_hosts_generate_thin_idempotent_adapters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            for host, adapter in ai_host_setup.HOSTS.items():
                with self.subTest(host=host):
                    action, relative_path = ai_host_setup.setup_host(host, root)
                    self.assertEqual(action, "created")
                    self.assertEqual(relative_path, Path(adapter.path))
                    generated = (root / relative_path).read_text(encoding="utf-8")
                    self.assertIn(ai_host_setup.GENERATED_MARKER, generated)
                    self.assertIn("src/skills/", generated)
                    self.assertNotIn("canonical implementation sentinel", generated)
                    second_action, _ = ai_host_setup.setup_host(host, root)
                    self.assertEqual(second_action, "unchanged")

    def test_all_selector_preflights_and_generates_every_adapter(self) -> None:
        """The quickstart path must configure every host without partial writes."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            conflict = root / ai_host_setup.HOSTS["workbuddy"].path
            conflict.parent.mkdir(parents=True)
            conflict.write_text("user-owned configuration\n", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                ai_host_setup.setup_hosts("all", root)
            self.assertFalse((root / ai_host_setup.HOSTS["codex"].path).exists())

            conflict.unlink()
            results = ai_host_setup.setup_hosts("all", root)
            self.assertEqual(len(results), len(ai_host_setup.HOSTS))
            self.assertTrue(all(action == "created" for action, _ in results))
            self.assertTrue(
                all((root / adapter.path).is_file() for adapter in ai_host_setup.HOSTS.values())
            )

    def test_existing_user_configuration_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            target = root / ai_host_setup.HOSTS["cursor"].path
            target.parent.mkdir(parents=True)
            target.write_text("user-owned rule\n", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                ai_host_setup.setup_host("cursor", root)
            self.assertEqual(target.read_text(encoding="utf-8"), "user-owned rule\n")

    def test_wrong_repository_root_is_rejected_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                ai_host_setup.setup_host("codex", root)
            self.assertFalse((root / ".agents").exists())


if __name__ == "__main__":
    unittest.main()
