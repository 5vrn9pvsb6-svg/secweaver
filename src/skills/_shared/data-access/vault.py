"""Resolve vault:// credentials_ref via local SOPS (platform layer only)."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from dataasset_paths import DATAASSET_ROOT, REPO_ROOT

SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from dataasset.credential_contracts import validate_credentials_ref  # noqa: E402

CREDENTIALS_ROOT = DATAASSET_ROOT / "credentials"
RESOLVE_SCRIPT = REPO_ROOT / "src" / "dataasset" / "credentials" / "resolve.py"


def normalize_credentials_ref(credentials_ref: str) -> str:
    """Compatibility wrapper that now enforces the canonical Vault path contract."""
    return validate_credentials_ref(credentials_ref)


def resolve_credentials(credentials_ref: str) -> dict[str, Any]:
    """Decrypt credentials for connector execution. Never pass result to LLM context."""
    normalized_ref = normalize_credentials_ref(credentials_ref)
    if not RESOLVE_SCRIPT.is_file():
        raise FileNotFoundError(f"missing resolve script: {RESOLVE_SCRIPT}")

    result = subprocess.run(
        [sys.executable, str(RESOLVE_SCRIPT), normalized_ref],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(CREDENTIALS_ROOT),
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "vault resolve failed")

    data = json.loads(result.stdout)
    data.pop("_meta", None)
    return data


def credentials_ref_only(connector: dict[str, Any]) -> str:
    ref = connector.get("credentials_ref", "")
    if not ref:
        raise ValueError(f"connector {connector.get('connector_id')} missing credentials_ref")
    return normalize_credentials_ref(str(ref))
