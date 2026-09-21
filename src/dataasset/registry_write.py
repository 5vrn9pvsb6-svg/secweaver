"""Shared filesystem write boundary for Studio and CLI DataAsset edits."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


@contextmanager
def registry_write_lock(root: Path, *, timeout: float = 10.0) -> Iterator[None]:
    """Serialize cooperating writers for one registry across processes.

    The ignored lock file remains stable across atomic object replacements. A
    bounded wait makes a stuck editor visible instead of hanging the UI forever.
    """
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / ".dataasset-write.lock.tmp"
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    with os.fdopen(descriptor, "r+b") as handle:
        deadline = time.monotonic() + timeout
        if os.name == "nt":
            import msvcrt

            # Windows byte-range locks require an existing byte at offset zero.
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"\0")
                handle.flush()

            def acquire() -> None:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)

            def release() -> None:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            def acquire() -> None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

            def release() -> None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

        while True:
            try:
                acquire()
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"DataAsset write lock busy: {root}") from exc
                time.sleep(0.05)
        try:
            yield
        finally:
            release()


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Replace one JSON object without exposing truncated content to readers."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if path.exists():
                os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
