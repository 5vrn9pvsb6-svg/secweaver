"""Regression tests for the POSIX/WSL2 quickstart orchestration."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
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
    def test_native_powershell_launcher_is_not_published(self) -> None:
        self.assertFalse((REPO_ROOT / "quickstart.ps1").exists())

    def test_version_probe_accepts_the_supported_test_interpreter(self) -> None:
        result = subprocess.run(
            [sys.executable, "-c", quickstart.VENV_VERSION_CHECK],
            check=False,
        )
        self.assertEqual(result.returncode, 0)

    def test_virtual_environment_uses_posix_layout(self) -> None:
        root = Path("checkout/.venv")
        self.assertEqual(
            quickstart.venv_python_path(root),
            root / "bin/python",
        )

    def test_native_windows_is_rejected_with_wsl_install_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands: list[list[str]] = []

            with self.assertRaisesRegex(quickstart.QuickstartError, "wsl --install"):
                quickstart.run_quickstart(
                    repo_root=root,
                    platform_name="windows",
                    runner=lambda command, _cwd: commands.append(list(command)),
                )
            self.assertEqual(commands, [])

    def test_wsl1_is_rejected_with_conversion_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            commands: list[list[str]] = []

            with self.assertRaisesRegex(quickstart.QuickstartError, "set-version Ubuntu 2"):
                quickstart.run_quickstart(
                    repo_root=Path(directory),
                    platform_name="posix",
                    kernel_release="4.4.0-19041-Microsoft",
                    runner=lambda command, _cwd: commands.append(list(command)),
                )
            self.assertEqual(commands, [])

    def test_wsl2_kernel_is_supported(self) -> None:
        self.assertEqual(
            quickstart.detect_wsl_version("5.15.153.1-microsoft-standard-WSL2"),
            2,
        )

    def test_existing_windows_venv_is_rejected_on_posix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".venv/Scripts").mkdir(parents=True)
            (root / ".venv/Scripts/python.exe").touch()
            commands: list[list[str]] = []

            with self.assertRaisesRegex(quickstart.QuickstartError, "no POSIX Python"):
                quickstart.run_quickstart(
                    repo_root=root,
                    platform_name="posix",
                    runner=lambda command, _cwd: commands.append(list(command)),
                )
            self.assertEqual(commands, [])

    def test_new_posix_venv_runs_the_complete_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements-data-access.txt").touch()
            commands: list[list[str]] = []

            def fake_runner(command, _cwd):
                """Materialize the interpreter when the simulated venv step runs."""
                recorded = list(command)
                commands.append(recorded)
                if recorded[1:3] == ["-m", "venv"]:
                    interpreter = root / ".venv/bin/python"
                    interpreter.parent.mkdir(parents=True)
                    interpreter.touch()

            result = quickstart.run_quickstart(
                repo_root=root,
                platform_name="posix",
                runtime_python=Path(sys.executable),
                runner=fake_runner,
            )

            self.assertEqual(result, root.resolve() / ".venv/bin/python")
            self.assertEqual(commands[0][1:3], ["-m", "venv"])
            self.assertEqual(commands[2][1:], ["src/dataasset/credentials/init_vault.py", "--check-ref", "vault://sls/sls-proxy-query"])
            self.assertEqual(commands[3][1:4], ["-m", "pip", "install"])
            self.assertEqual(commands[4][1:], ["src/secweaver.py", "validate"])
            self.assertEqual(commands[5][1:4], ["src/secweaver.py", "demo", "all"])
            self.assertEqual(
                commands[6][1:],
                ["src/scripts/ai_host_setup.py", "--host", "all"],
            )

    def test_explicit_offline_skip_does_not_invoke_vault(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            interpreter = root / ".venv/bin/python"
            interpreter.parent.mkdir(parents=True)
            interpreter.touch()
            commands = []
            quickstart.run_quickstart(repo_root=root, platform_name="posix", skip_vault=True,
                                     runner=lambda command, _cwd: commands.append(list(command)))
            self.assertFalse(any("init_vault.py" in " ".join(command) for command in commands))
            self.assertFalse((root / "dataasset/credentials").exists())

    def test_vault_failure_stops_before_dependency_download_and_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            interpreter = root / ".venv/bin/python"
            interpreter.parent.mkdir(parents=True)
            interpreter.touch()
            commands = []

            def runner(command, _cwd):
                """Model an unready Vault without touching local keys or tools."""
                commands.append(list(command))
                if "src/dataasset/credentials/init_vault.py" in command:
                    raise subprocess.CalledProcessError(1, command)

            with patch("builtins.print") as output, self.assertRaises(subprocess.CalledProcessError):
                quickstart.run_quickstart(repo_root=root, platform_name="posix", runner=runner,
                                         vault_check_ref="vault://es/private-query")
            self.assertEqual(commands[-1][-1], "vault://es/private-query")
            self.assertEqual(len(commands), 2)
            self.assertFalse(any("completed" in str(call) for call in output.call_args_list))

    def test_make_options_are_explicit_and_forwarded(self) -> None:
        for options, expected in (([], False), (["SKIP_VAULT=1"], True), (["SKIP_VAULT=0"], False)):
            with self.subTest(options=options):
                result = subprocess.run(["make", "-n", "quickstart", "VAULT_CHECK_REF=vault://es/query", *options],
                                        cwd=REPO_ROOT, capture_output=True, text=True, check=True)
                self.assertEqual("--skip-vault" in result.stdout, expected)
                self.assertIn('--vault-check-ref "vault://es/query"', result.stdout)


if __name__ == "__main__":
    unittest.main()
