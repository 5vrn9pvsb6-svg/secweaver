"""Shared DataAsset root resolution.

DATAASSET_ROOT lets local/private deployments point SecWeaver at a private
asset directory while keeping the cleaned open-source dataasset/ as default.
"""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]


def resolve_dataasset_root(value: str | None = None, *, repo_root: Path = REPO_ROOT) -> Path:
    configured = value if value is not None else os.environ.get("DATAASSET_ROOT")
    if not configured:
        return repo_root / "dataasset"
    path = Path(configured).expanduser()
    return path if path.is_absolute() else repo_root / path


DATAASSET_ROOT = resolve_dataasset_root()


def dataasset_path(*parts: str) -> Path:
    return DATAASSET_ROOT.joinpath(*parts)


def format_path(path: Path, *, repo_root: Path = REPO_ROOT) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
