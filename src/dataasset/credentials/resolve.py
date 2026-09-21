#!/usr/bin/env python3
"""Resolve vault:// credentials_ref via local SOPS encrypted files."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

DATAASSET_MODULE_ROOT = Path(__file__).resolve().parents[1]
if str(DATAASSET_MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(DATAASSET_MODULE_ROOT))

from credential_contracts import (  # noqa: E402
    credential_secret_path,
    load_credential_status_file,
    normalize_credentials_ref as _normalize_credentials_ref,
)

SENSITIVE_KEYS = {
    "access_key_secret",
    "secret_access_key",
    "access_key",
    "password",
    "private_key",
    "client_secret",
    "token",
    "access_token",
    "api_key",
    "app_key",
    "key_value",
    "api_secret",
    "secret_id",
    "secret_key",
    "security_token",
    "session_token",
    "keytab",
}

REPO_ROOT = Path(__file__).resolve().parents[3]


def resolve_dataasset_root() -> Path:
    configured = os.environ.get("DATAASSET_ROOT")
    if not configured:
        return REPO_ROOT / "dataasset"
    path = Path(configured).expanduser()
    return path if path.is_absolute() else REPO_ROOT / path


ROOT = str(resolve_dataasset_root() / "credentials")
SECRETS_DIR = os.path.join(ROOT, "secrets")
AGE_KEY = os.path.join(ROOT, ".age", "key.txt")
SOPS_CONFIG = os.path.join(ROOT, ".sops.yaml")
STATUS_FILE = os.path.join(ROOT, "credential-status.json")
SOPS_BIN_ENV = "SOPS_BIN"

# Desktop launchers and service runners often do not inherit the interactive
# shell PATH. Keep this fallback small and platform-neutral; an explicit
# SOPS_BIN or PATH entry always wins.
DEFAULT_EXECUTABLE_DIRS = (
    Path("/opt/homebrew/bin"),
    Path("/usr/local/bin"),
    Path("/opt/local/bin"),
    Path.home() / ".local" / "bin",
    Path.home() / "bin",
)


def normalize_credentials_ref(credentials_ref: str) -> str:
    """Compatibility wrapper around the shared DataAsset credential contract."""
    return _normalize_credentials_ref(credentials_ref)


def ref_to_path(credentials_ref: str) -> str:
    return str(credential_secret_path(Path(ROOT), credentials_ref))


def ensure_credential_active(credentials_ref: str) -> None:
    try:
        normalized_ref = _normalize_credentials_ref(credentials_ref)
        statuses = load_credential_status_file(Path(STATUS_FILE))
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    if statuses.get(normalized_ref) == "disabled":
        raise RuntimeError(f"credential is disabled: {normalized_ref}")


def _sops_env() -> dict[str, str]:
    env = os.environ.copy()
    env["SOPS_CONFIG"] = SOPS_CONFIG
    key_file = os.environ.get("SOPS_AGE_KEY_FILE") or AGE_KEY
    if os.path.isfile(key_file):
        env["SOPS_AGE_KEY_FILE"] = key_file
    return env


def find_executable(name: str) -> str:
    """Resolve a local executable despite non-login/service PATHs."""
    override_name = SOPS_BIN_ENV if name == "sops" else f"{name.upper()}_BIN"
    override = os.environ.get(override_name, "").strip()
    if override:
        candidate = Path(override).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        raise RuntimeError(
            f"{override_name} points to a missing or non-executable file: {candidate}"
        )

    resolved = shutil.which(name)
    if resolved:
        return resolved

    searched = []
    for directory in DEFAULT_EXECUTABLE_DIRS:
        candidate = directory / name
        searched.append(str(candidate))
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    searched_text = ", ".join(searched)
    raise RuntimeError(
        f"{name} not found in PATH or fallback locations ({searched_text}); "
        f"set {override_name}=/absolute/path/to/{name}"
    )


def resolve(credentials_ref: str) -> dict:
    normalized_ref = normalize_credentials_ref(credentials_ref)
    ensure_credential_active(normalized_ref)
    path = ref_to_path(normalized_ref)
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"secret not found for {normalized_ref}: {path}\n"
            "run: src/dataasset/credentials/sops-vault.sh edit " + normalized_ref
        )
    if not os.path.isfile(SOPS_CONFIG):
        raise FileNotFoundError(
            f"missing {SOPS_CONFIG}; run: src/dataasset/credentials/sops-vault.sh init"
        )

    try:
        sops_bin = find_executable("sops")
        result = subprocess.run(
            [sops_bin, "-d", "--output-type", "json", path],
            capture_output=True,
            text=True,
            check=True,
            env=_sops_env(),
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(exc.stderr.strip() or "sops decrypt failed") from exc

    data = json.loads(result.stdout)
    data["_meta"] = {
        "credentials_ref": normalized_ref,
        "source": os.path.relpath(path, ROOT).replace(os.sep, "/"),
    }
    return data


def mask_secrets(data: dict) -> dict:
    masked = {}
    for key, value in data.items():
        if key == "_meta":
            masked[key] = value
        elif key in SENSITIVE_KEYS and value:
            masked[key] = "***"
        else:
            masked[key] = value
    return masked


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve vault:// via SOPS")
    parser.add_argument("credentials_ref", help="e.g. vault://sls/security-readonly")
    parser.add_argument(
        "--mask",
        action="store_true",
        help="mask sensitive fields (for get without --show-secrets)",
    )
    args = parser.parse_args()

    try:
        data = resolve(args.credentials_ref)
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.mask:
        data = mask_secrets(data)
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
