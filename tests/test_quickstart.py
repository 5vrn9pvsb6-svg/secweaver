"""Regression tests for the cross-platform quickstart orchestration."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
QUICKSTART = REPO_ROOT / "src/scripts/quickstart.py"


def load_quickstart():
    """Load the standalone entrypoint without requiring src to be a package."""
    spec = importlib.util.spec_from_file_location("secweaver_quickstart", QUICKSTART)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {QUICKSTART}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


quickstart = load_quickstart()


class QuickstartTests(unittest.TestCase):
    def test_version_probe_accepts_the_supported_test_interpreter(self) -> None:
        result = subprocess.run(
            [sys.executable, "-c", quickstart.VENV_VERSION_CHECK],
            check=False,
        )
        self.assertEqual(result.returncode, 0)

    def test_powershell_launcher_delegates_without_string_evaluation(self) -> None:
        launcher = (REPO_ROOT / "quickstart.ps1").read_text(encoding="utf-8")
        self.assertIn("src/scripts/quickstart.py", launcher)
        self.assertIn("@Arguments", launcher)
        self.assertNotIn("Invoke-Expression", launcher)

    def test_virtual_environment_interpreter_matches_platform(self) -> None:
        root = Path("checkout/.venv")
        self.assertEqual(
            quickstart.venv_python_path(root, "windows"),
            root / "Scripts/python.exe",
        )
        self.assertEqual(
            quickstart.venv_python_path(root, "posix"),
            root / "bin/python",
        )

    def test_existing_other_platform_venv_is_rejected_before_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".venv/bin").mkdir(parents=True)
            (root / ".venv/bin/python").touch()
            commands: list[list[str]] = []

            with self.assertRaisesRegex(quickstart.QuickstartError, "no windows Python"):
                quickstart.run_quickstart(
                    repo_root=root,
                    platform_name="windows",
                    runner=lambda command, _cwd: commands.append(list(command)),
                )
            self.assertEqual(commands, [])

    def test_new_windows_venv_runs_the_complete_shared_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements-data-access.txt").touch()
            commands: list[list[str]] = []

            def fake_runner(command, _cwd):
                """Materialize the interpreter when the simulated venv step runs."""
                recorded = list(command)
                commands.append(recorded)
                if recorded[1:3] == ["-m", "venv"]:
                    interpreter = root / ".venv/Scripts/python.exe"
                    interpreter.parent.mkdir(parents=True)
                    interpreter.touch()

            result = quickstart.run_quickstart(
                repo_root=root,
                platform_name="windows",
                runtime_python=Path(sys.executable),
                runner=fake_runner,
            )

            self.assertEqual(result, root.resolve() / ".venv/Scripts/python.exe")
            self.assertEqual(commands[0][1:3], ["-m", "venv"])
            self.assertEqual(commands[2][1:4], ["-m", "pip", "install"])
            self.assertEqual(commands[3][1:], ["src/secweaver.py", "validate"])
            self.assertEqual(commands[4][1:4], ["src/secweaver.py", "demo", "all"])
            self.assertEqual(
                commands[5][1:],
                ["src/scripts/ai_host_setup.py", "--host", "all"],
            )


if __name__ == "__main__":
    unittest.main()
