"""Switch the install channel only after validating selected immutable archives.

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


def validate_release(root: Path, version: str, platforms, public_paths) -> None:
    """Validate only the immutable archives used by one OS family.

    A platform release may advance independently, so Linux and Windows can
    point at different version directories. The legacy global pointer still
    calls this helper for both families, preserving old Bootstrap behavior.
    """
    if len(version) > 64 or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.-]+)?", version
    ):
        raise ValueError(f"invalid release version: {version!r}")
    directory = root / version
    mode = directory.lstat().st_mode
    if not stat.S_ISDIR(mode) or mode & 0o022:
        raise ValueError("release directories must be publisher-owned, without symlinks")
    if mode & 0o555 != 0o555:
        raise ValueError(f"public release directory must be readable/traversable (0755 recommended): {directory}")
    public_paths.append(directory)
    for platform in platforms:
        ext = ".tar.gz" if platform.startswith("linux") else ".zip"
        package = directory / f"secweaver-agent_{version}_{platform}{ext}"
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


def write_pointer(root: Path, name: str, version: str) -> Path:
    """Write one pointer through a same-directory fsync and atomic replace.

    The three pointers are prepared before any replacement. A failure cannot
    publish a malformed value, although callers should still treat the
    pointer set as a short sequence of individually atomic updates.
    """
    pointer = root / name
    if pointer.exists() or pointer.is_symlink():
        regular(pointer)
    fd, temporary = tempfile.mkstemp(prefix=f".{name}-", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(version + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
        return Path(temporary)
    except Exception:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def promote(
    root: Path,
    version: str,
    runtime_user: str = "",
    linux_version: str = "",
    windows_version: str = "",
) -> None:
    """Validate and publish global plus independent Linux/Windows pointers.

    ``version`` remains the complete legacy release selected by old Agents.
    Optional family versions validate only their own immutable archives, which
    lets operators roll Linux and Windows on separate schedules without
    breaking clients that still read ``latest-version.txt``.
    """
    if len(version) > 64 or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.-]+)?", version
    ):
        raise ValueError("invalid release version")
    linux_version = linux_version or version
    windows_version = windows_version or version
    root = root.absolute()
    root_mode = root.lstat().st_mode
    if not stat.S_ISDIR(root_mode) or root_mode & 0o022:
        raise ValueError("release root must be publisher-owned, without symlinks")
    if root_mode & 0o555 != 0o555:
        raise ValueError(f"public release directory must be readable/traversable (0755 recommended): {root}")
    public_paths = [root]
    validate_release(root, version, (
        "linux_amd64", "linux_arm64", "linux_loong64", "windows_amd64", "windows_arm64"
    ), public_paths)
    if linux_version != version:
        validate_release(root, linux_version, ("linux_amd64", "linux_arm64", "linux_loong64"), public_paths)
    if windows_version != version:
        validate_release(root, windows_version, ("windows_amd64", "windows_arm64"), public_paths)
    for pointer_name in (
        "latest-version.txt", "latest-linux-version.txt", "latest-windows-version.txt"
    ):
        pointer = root / pointer_name
        if pointer.exists() or pointer.is_symlink():
            regular(pointer)
    # Validate before writing: the Gateway must be able to traverse every
    # selected artifact under its runtime identity, not only as the publisher.
    runtime_readable(public_paths, runtime_user)
    pointer_values = {
        "latest-version.txt": version,
        "latest-linux-version.txt": linux_version,
        "latest-windows-version.txt": windows_version,
    }
    temporary = {}
    try:
        for name, selected in pointer_values.items():
            temporary[name] = write_pointer(root, name, selected)
        for name, temporary_path in temporary.items():
            os.replace(temporary_path, root / name)
    finally:
        for temporary_path in temporary.values():
            if temporary_path.exists():
                temporary_path.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--version", required=True, help="complete legacy release for latest-version.txt")
    parser.add_argument("--linux-version", default="", help="optional Linux-only release version")
    parser.add_argument("--windows-version", default="", help="optional Windows-only release version")
    parser.add_argument("--runtime-user", default="", help="Linux service account to check using runuser before promotion")
    args = parser.parse_args()
    promote(args.release_root, args.version, args.runtime_user, args.linux_version, args.windows_version)
    print(
        "install channel promoted: "
        f"global={args.version} linux={args.linux_version or args.version} "
        f"windows={args.windows_version or args.version}"
    )
