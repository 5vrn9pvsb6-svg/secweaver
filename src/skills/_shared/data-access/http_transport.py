"""Secure transport policy for credential-bearing connector HTTP requests."""

from __future__ import annotations

import ssl
import sys
import urllib.request
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from dataasset_paths import DATAASSET_ROOT, REPO_ROOT

SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from dataasset.transport_contracts import resolve_ca_file, validate_secure_endpoint  # noqa: E402


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so authentication material never reaches another URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("connector redirects are not allowed; configure the final endpoint")


def ssl_context(
    config: dict[str, Any] | None,
    url: str,
    *,
    verify_keys: Iterable[str] = ("tls_verify", "verify_tls"),
    label: str = "connector endpoint",
    dataasset_root: Path | None = None,
) -> ssl.SSLContext | None:
    """Build a verified TLS context and resolve private CAs from DATAASSET_ROOT.

    Multiple historical verification keys are accepted for compatibility, but
    their values must agree. Live data access fails closed instead of silently
    disabling certificate or hostname verification.
    """
    value = validate_secure_endpoint(url, label=label)
    settings = config or {}
    configured: list[tuple[str, bool]] = []
    for key in verify_keys:
        if key not in settings:
            continue
        verify = settings[key]
        if not isinstance(verify, bool):
            raise ValueError(f"{label} {key} must be a boolean")
        configured.append((key, verify))
    if any(not verify for _, verify in configured):
        key = next(key for key, verify in configured if not verify)
        raise ValueError(f"{label} {key}=false is not allowed; configure ca_file for a private CA")
    if urlsplit(value).scheme == "http":
        if settings.get("ca_file"):
            raise ValueError(f"{label} ca_file requires an HTTPS endpoint")
        return None

    ca_file_value = settings.get("ca_file")
    if not ca_file_value:
        return ssl.create_default_context()
    ca_file = resolve_ca_file(ca_file_value, dataasset_root or DATAASSET_ROOT, label=label)
    if not ca_file.is_file():
        raise FileNotFoundError(f"{label} ca_file not found: {ca_file}")
    return ssl.create_default_context(cafile=str(ca_file))


def open_secure_request(
    request: urllib.request.Request,
    *,
    timeout: int,
    config: dict[str, Any] | None = None,
    verify_keys: Iterable[str] = ("tls_verify", "verify_tls"),
    label: str = "connector endpoint",
    dataasset_root: Path | None = None,
):
    """Open one request with local redirect policy and verified TLS settings."""
    context = ssl_context(
        config,
        request.full_url,
        verify_keys=verify_keys,
        label=label,
        dataasset_root=dataasset_root,
    )
    handlers: list[Any] = [NoRedirect()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers).open(request, timeout=timeout)
