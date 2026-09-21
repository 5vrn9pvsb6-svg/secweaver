"""Switch the install channel only after validating all five immutable archives.

Run on a trusted publisher-owned tree. This does not sign or rebuild packages,
rotate update trust, or choose a version based on directory ordering. The caller
explicitly promotes a reviewed version; installers resolve it over HTTPS once.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile


def regular(path: Path) -> None:
    """Reject links and group/world-writable publication components."""
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o022:
        raise ValueError(f"not a publisher-owned regular file: {path.name}")


def promote(root: Path, version: str) -> None:
    """Verify all platforms first; atomic replacement prevents partial pointers.

    Failures leave the prior channel intact. Archives must not be modified by
    concurrent publishers; directory permissions are an operational boundary.
    """
    if len(version) > 64 or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.-]+)?", version):
        raise ValueError("invalid release version")
    root = root.absolute()
    for directory in [root, root / version]:
        mode = directory.lstat().st_mode
        if not stat.S_ISDIR(mode) or mode & 0o022:
            raise ValueError("release directories must be publisher-owned, without symlinks")
    for platform in ("linux_amd64", "linux_arm64", "linux_loong64", "windows_amd64", "windows_arm64"):
        ext = ".tar.gz" if platform.startswith("linux") else ".zip"
        package = root / version / f"secweaver-agent_{version}_{platform}{ext}"
        checksum = Path(str(package) + ".sha256")
        regular(package)
        regular(checksum)
        if not 0 < package.stat().st_size <= 256 * 1024 * 1024 or checksum.stat().st_size > 1024:
            raise ValueError("invalid package or checksum size")
        parts = checksum.read_text(encoding="ascii").split()
        if len(parts) != 2 or parts[1].lstrip("*") != package.name or not re.fullmatch(r"[a-fA-F0-9]{64}", parts[0]):
            raise ValueError("invalid package checksum sidecar")
        digest = hashlib.sha256()
        with package.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != parts[0].lower():
            raise ValueError("package checksum mismatch")
    pointer = root / "latest-version.txt"
    if pointer.exists() or pointer.is_symlink():
        regular(pointer)
    fd, temporary = tempfile.mkstemp(prefix=".latest-version-", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(version + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
        os.replace(temporary, pointer)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    promote(args.release_root, args.version)
    print("install channel promoted: " + args.version)
