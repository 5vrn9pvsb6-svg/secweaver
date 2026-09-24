#!/usr/bin/env python3
"""Set up and verify the credential-free SecWeaver quickstart on POSIX or WSL2."""

from __future__ import annotations

import argparse
import os
import platform
import shlex
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MINIMUM_PYTHON = (3, 10)
VENV_VERSION_CHECK = (
    "import sys; minimum=(3,10); actual=sys.version_info[:2]; "
    "sys.exit('SecWeaver requires Python 3.10+; virtual environment uses '"
    "+'.'.join(map(str, actual))) if actual < minimum else None"
)
CommandRunner = Callable[[Sequence[str], Path], None]


class QuickstartError(RuntimeError):
    """Report an environment problem before a partial quickstart is created."""


def current_platform() -> str:
    """Classify native Windows separately because Community clients require WSL2."""
    return "windows" if os.name == "nt" else "posix"


def detect_wsl_version(kernel_release: str | None = None) -> int | None:
    """Identify WSL1/WSL2 from the Linux kernel release without invoking Windows tools."""
    release = (kernel_release or platform.release()).lower()
    if "wsl2" in release or "microsoft-standard" in release:
        return 2
    if "microsoft" in release:
        return 1
    return None


def venv_python_path(venv_dir: Path) -> Path:
    """Resolve the supported POSIX venv interpreter without shell activation."""
    return venv_dir / "bin" / "python"


def display_command(command: Sequence[str]) -> str:
    """Render diagnostic output for the POSIX shell used by Linux, macOS, and WSL2."""
    return shlex.join(command)


def run_command(command: Sequence[str], cwd: Path) -> None:
    """Run one bounded setup step and preserve its native exit status."""
    print(f"+ {display_command(command)}", flush=True)
    subprocess.run(list(command), cwd=cwd, check=True)


def quickstart_commands(
    venv_python: Path,
    requirements: Path,
    report_dir: Path,
) -> list[list[str]]:
    """Build the POSIX/WSL2 workflow from shell-independent Python entrypoints."""
    python = str(venv_python)
    return [
        [python, "-m", "pip", "install", "-r", str(requirements)],
        [python, "src/secweaver.py", "validate"],
        [python, "src/secweaver.py", "demo", "all", "-o", str(report_dir)],
        [python, "src/scripts/ai_host_setup.py", "--host", "all"],
    ]


def resolve_repo_path(repo_root: Path, value: Path) -> Path:
    """Resolve user-selected output paths relative to the checkout by default."""
    return value.expanduser().resolve() if value.is_absolute() else (repo_root / value).resolve()


def run_quickstart(
    *,
    repo_root: Path = REPO_ROOT,
    venv_dir: Path = Path(".venv"),
    report_dir: Path = Path("examples/reports"),
    platform_name: str | None = None,
    kernel_release: str | None = None,
    runtime_python: Path | None = None,
    runner: CommandRunner = run_command,
) -> Path:
    """Create the venv and run setup steps on Linux, macOS, or WSL2.

    Native Windows stops before touching the checkout and points users to WSL2. An
    existing directory without a POSIX interpreter is rejected so a Windows venv
    cannot be reused accidentally from WSL2.
    """
    if sys.version_info[:2] < MINIMUM_PYTHON:
        actual = ".".join(str(part) for part in sys.version_info[:2])
        raise QuickstartError(f"SecWeaver requires Python 3.10+; found Python {actual}")

    selected_platform = platform_name or current_platform()
    if selected_platform != "posix":
        raise QuickstartError(
            "SecWeaver Community does not run directly on native Windows. "
            "Install WSL2 from an elevated Windows terminal with 'wsl --install', "
            "restart if prompted, then run 'make quickstart' inside the Ubuntu WSL shell."
        )
    if detect_wsl_version(kernel_release) == 1:
        raise QuickstartError(
            "SecWeaver Community requires WSL2; WSL1 is not supported. "
            "From an elevated Windows terminal run 'wsl --set-version Ubuntu 2', "
            "then retry inside Ubuntu."
        )

    root = repo_root.resolve()
    selected_runtime = (runtime_python or Path(sys.executable)).resolve()
    selected_venv = resolve_repo_path(root, venv_dir)
    selected_reports = resolve_repo_path(root, report_dir)
    venv_python = venv_python_path(selected_venv)

    if selected_venv.exists() and not venv_python.is_file():
        raise QuickstartError(
            f"{selected_venv} exists but has no POSIX Python interpreter; "
            "remove it or choose a different --venv-dir"
        )
    if not venv_python.is_file():
        runner([str(selected_runtime), "-m", "venv", str(selected_venv)], root)
    if not venv_python.is_file():
        raise QuickstartError(f"virtual environment creation did not produce {venv_python}")

    runner([str(venv_python), "-c", VENV_VERSION_CHECK], root)
    for command in quickstart_commands(
        venv_python,
        root / "requirements-data-access.txt",
        selected_reports,
    ):
        runner(command, root)

    print("\nSecWeaver quickstart completed.")
    print(f"Reports: {selected_reports}")
    print("AI hosts: Codex, Cursor, Claude Code, OpenClaw, WorkBuddy")
    print("Next: open an AI host in this repository and ask: Run the SecWeaver offline showcase.")
    print("Cases: examples/ai-showcase/README.md")
    return venv_python


def main(argv: list[str] | None = None) -> int:
    """Parse the stable quickstart options used by POSIX and WSL2 environments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--venv-dir", type=Path, default=Path(".venv"))
    parser.add_argument("--report-dir", type=Path, default=Path("examples/reports"))
    args = parser.parse_args(argv)
    try:
        run_quickstart(venv_dir=args.venv_dir, report_dir=args.report_dir)
    except (OSError, QuickstartError, subprocess.CalledProcessError) as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            message = f"command failed with exit code {exc.returncode}: {display_command(exc.cmd)}"
        else:
            message = str(exc)
        print(f"ERROR: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
