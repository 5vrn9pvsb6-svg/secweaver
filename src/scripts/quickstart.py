#!/usr/bin/env python3
"""Set up and verify the credential-free SecWeaver quickstart on any host OS."""

from __future__ import annotations

import argparse
import os
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
    """Return the virtual-environment layout used by the current interpreter."""
    return "windows" if os.name == "nt" else "posix"


def venv_python_path(venv_dir: Path, platform_name: str) -> Path:
    """Resolve the venv interpreter without relying on shell activation."""
    if platform_name == "windows":
        return venv_dir / "Scripts" / "python.exe"
    if platform_name == "posix":
        return venv_dir / "bin" / "python"
    raise ValueError(f"unsupported platform layout: {platform_name}")


def display_command(command: Sequence[str]) -> str:
    """Render diagnostic output with quoting appropriate for the current OS."""
    if os.name == "nt":
        return subprocess.list2cmdline(list(command))
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
    """Build the shared POSIX/Windows workflow from platform-neutral Python entrypoints."""
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
    runtime_python: Path | None = None,
    runner: CommandRunner = run_command,
) -> Path:
    """Create the venv and run setup steps in the same order on every supported OS.

    An existing directory without this platform's interpreter is rejected instead
    of mixing POSIX and Windows virtual-environment layouts in one checkout.
    """
    if sys.version_info[:2] < MINIMUM_PYTHON:
        actual = ".".join(str(part) for part in sys.version_info[:2])
        raise QuickstartError(f"SecWeaver requires Python 3.10+; found Python {actual}")

    root = repo_root.resolve()
    selected_platform = platform_name or current_platform()
    selected_runtime = (runtime_python or Path(sys.executable)).resolve()
    selected_venv = resolve_repo_path(root, venv_dir)
    selected_reports = resolve_repo_path(root, report_dir)
    venv_python = venv_python_path(selected_venv, selected_platform)

    if selected_venv.exists() and not venv_python.is_file():
        raise QuickstartError(
            f"{selected_venv} exists but has no {selected_platform} Python interpreter; "
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
    """Parse the stable quickstart options shared by Make and PowerShell."""
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
