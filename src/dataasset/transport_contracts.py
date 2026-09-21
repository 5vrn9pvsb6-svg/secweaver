"""Canonical endpoint and CA path contracts shared by validation and fetch."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlsplit


def _is_literal_loopback(hostname: str) -> bool:
    """Accept loopback names and IP literals without DNS or alternate encodings."""
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def validate_secure_endpoint(url: str, *, label: str = "connector endpoint") -> str:
    """Require HTTPS, allowing plain HTTP only for an explicit loopback target."""
    value = str(url or "").strip()
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{label} must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{label} must not contain user information")
    if parsed.scheme == "http" and not _is_literal_loopback(parsed.hostname):
        raise ValueError(f"{label} must use HTTPS; HTTP is allowed only for a loopback endpoint")
    return value


def resolve_ca_file(ca_file: object, dataasset_root: Path, *, label: str) -> Path:
    """Resolve a CA path and prevent relative paths or symlinks escaping the registry.

    Absolute CA paths remain supported for system-managed trust files. Relative
    paths are operator-owned registry content and must stay below DATAASSET_ROOT
    after resolving symlinks.
    """
    if not isinstance(ca_file, str) or not ca_file.strip():
        raise ValueError(f"{label} ca_file must be a nonempty path string")
    path = Path(ca_file).expanduser()
    if path.is_absolute():
        return path
    root = dataasset_root.resolve()
    resolved = (root / path).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"{label} relative ca_file must stay inside DATAASSET_ROOT")
    return resolved
