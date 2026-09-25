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
import subprocess
import tempfile


def regular(path: Path) -> None:
    """Reject links and group/world-writable publication components."""
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o022:
        raise ValueError(f"not a publisher-owned regular file: {path.name}")


def runtime_readable(paths, runtime_user):
    """Check the service identity, including ancestor traversal and OS ACLs.

    Never grant permissions or impersonate a user implicitly. Root publishers
    explicitly opt into a bounded runuser check before changing the pointer.
    """
    if not runtime_user:
        return
    for path in paths:
        try:
            subprocess.run(["runuser", "-u", runtime_user, "--", "test",
                            "-x" if path.is_dir() else "-r", str(path)],
                           check=True, timeout=10, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError(f"runtime-user readability check failed: {path}; verify user, parent permissions and runuser availability") from exc


def promote(root: Path, version: str, runtime_user: str = "") -> None:
    """Verify all platforms first; atomic replacement prevents partial pointers.

    Failures leave the prior channel intact. Archives must not be modified by
    concurrent publishers; directory permissions are an operational boundary.
    """
    if len(version) > 64 or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.-]+)?", version):
        raise ValueError("invalid release version")
    root = root.absolute()
    public_paths = [root, root / version]
    for directory in [root, root / version]:
        mode = directory.lstat().st_mode
        if not stat.S_ISDIR(mode) or mode & 0o022:
            raise ValueError("release directories must be publisher-owned, without symlinks")
        if mode & 0o555 != 0o555:
            raise ValueError(f"public release directory must be readable/traversable (0755 recommended): {directory}")
    for platform in ("linux_amd64", "linux_arm64", "linux_loong64", "windows_amd64", "windows_arm64"):
        ext = ".tar.gz" if platform.startswith("linux") else ".zip"
        package = root / version / f"secweaver-agent_{version}_{platform}{ext}"
        checksum = Path(str(package) + ".sha256")
        regular(package)
        regular(checksum)
        for path in (package, checksum):
            if path.stat().st_mode & 0o444 != 0o444:
                raise ValueError(f"public release file must be readable (0644 recommended): {path.name}")
            public_paths.append(path)
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
    # Validate before writing even a temporary pointer: root readability alone
    # cannot prove that the Gateway can serve any archive under restrictive ACLs.
    runtime_readable(public_paths, runtime_user)
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
    parser.add_argument("--runtime-user", default="", help="Linux service account to check using runuser before promotion")
    args = parser.parse_args()
    promote(args.release_root, args.version, args.runtime_user)
    print("install channel promoted: " + args.version)
