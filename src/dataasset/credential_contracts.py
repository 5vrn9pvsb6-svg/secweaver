"""Shared credential-reference and lifecycle contracts for DataAsset runtimes."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


VAULT_REF_PATTERN = re.compile(r"^vault://[^/]+/.+$")
CREDENTIAL_STATUSES = frozenset({"active", "disabled"})


def normalize_credentials_ref(credentials_ref: str) -> str:
    """Normalize separators without weakening the vault namespace/name contract."""
    ref = credentials_ref.strip().replace("\\", "/")
    if ref.startswith("vault://"):
        body = ref.removeprefix("vault://")
        while "//" in body:
            body = body.replace("//", "/")
        return "vault://" + body.strip("/")
    return ref


def validate_credentials_ref(credentials_ref: str) -> str:
    """Return a normalized vault reference or raise before any filesystem access."""
    normalized = normalize_credentials_ref(credentials_ref)
    body = normalized.removeprefix("vault://") if normalized.startswith("vault://") else ""
    parts = body.split("/")
    if (
        not VAULT_REF_PATTERN.fullmatch(normalized)
        or len(parts) < 2
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError(f"invalid credentials_ref: {credentials_ref}")
    return normalized


def credential_secret_path(credentials_root: Path, credentials_ref: str) -> Path:
    """Map a validated vault reference to its encrypted file inside one registry."""
    normalized = validate_credentials_ref(credentials_ref)
    relative = normalized.removeprefix("vault://")
    secrets_root = (credentials_root / "secrets").resolve()
    candidate = (secrets_root / f"{relative}.enc.yaml").resolve()
    if secrets_root not in candidate.parents:
        raise ValueError(f"credentials_ref escapes the credential root: {credentials_ref}")
    return candidate


def parse_credential_statuses(payload: Any) -> dict[str, str]:
    """Validate and normalize lifecycle state, rejecting typos instead of enabling them."""
    if not isinstance(payload, dict):
        raise ValueError("credential status must be an object")
    statuses: dict[str, str] = {}
    for raw_ref, raw_status in payload.items():
        ref = validate_credentials_ref(str(raw_ref))
        status = str(raw_status)
        if status not in CREDENTIAL_STATUSES:
            allowed = ", ".join(sorted(CREDENTIAL_STATUSES))
            raise ValueError(f"credential {ref}: unsupported status {status!r}; expected {allowed}")
        if ref in statuses:
            raise ValueError(f"credential status contains duplicate normalized reference: {ref}")
        statuses[ref] = status
    return statuses


def load_credential_status_file(path: Path) -> dict[str, str]:
    """Load one optional status registry and fail closed on malformed lifecycle data."""
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid credential status file: {path}: {exc}") from exc
    return parse_credential_statuses(payload)
