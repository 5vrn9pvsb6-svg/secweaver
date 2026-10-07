#!/usr/bin/env python3
"""Initialize a local age/SOPS Vault without replacing existing trust material."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
PLACEHOLDER = "REPLACE_WITH_YOUR_AGE_PUBLIC_KEY"
DEFAULT_CHECK_REF = "vault://sls/sls-proxy-query"
TOOL_TIMEOUT_SECONDS = 30
ENCRYPTED_FIELDS = (
    "access_key_secret|secret_access_key|password|private_key|token|access_token|"
    "api_key|api_secret|security_token|session_token|client_secret|secret_key|"
    "key_value|app_key|keytab"
)


class VaultInitError(RuntimeError):
    """Stop setup rather than rotate a key or hide a broken existing Vault."""


def resolve_tool(name: str, override_name: str) -> str:
    """Honor explicit tool overrides, including invalid ones, like the Vault CLI."""
    override = os.environ.get(override_name)
    candidates = [override] if override else [shutil.which(name), *(
        str(Path(base).expanduser() / name)
        for base in ("/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "~/.local/bin", "~/bin")
    )]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return str(Path(candidate).resolve())
    raise VaultInitError(
        f"Vault setup requires {name}; install SOPS and age using your approved package source "
        f"(macOS: brew install sops age), or set {override_name} to its executable. "
        "For offline demos only, use make quickstart SKIP_VAULT=1."
    )


def run_tool(command: list[str], *, env: dict[str, str], input_text: str | None = None) -> str:
    """Bound native crypto operations and kill descendants on timeout.

    Never include native stderr in errors: an invalid key or policy can expose
    sensitive material. Output is returned only to the caller, never logged.
    """
    with subprocess.Popen(
        command, env=env, text=True, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    ) as process:
        try:
            stdout, _stderr = process.communicate(input_text, timeout=TOOL_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise VaultInitError("Vault crypto check timed out after 30 seconds; check local tools/key services.") from exc
        except BaseException:
            # Native tools have their own session, so Ctrl-C in quickstart must
            # explicitly terminate them rather than wait indefinitely on exit.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        if process.returncode:
            raise VaultInitError("Vault policy/key check failed; restore the original policy and matching private key. No key rotation was performed.")
    return stdout


def policy_text(recipient: str) -> str:
    """Generate the single bundled rule; custom policies are never rewritten."""
    return (
        "creation_rules:\n"
        "  - path_regex: secrets/.*\\.enc\\.yaml$\n"
        f"    encrypted_regex: '^({ENCRYPTED_FIELDS})$'\n"
        f"    age: {recipient}\n"
    )


def is_shipped_placeholder(text: str) -> bool:
    """Recognize only bundled templates, not arbitrary YAML containing a marker.

    This is a template comparison, not a YAML parser. Native SOPS remains the
    authority for every non-template policy, including key_groups and KMS.
    """
    def normalized(value: str) -> str:
        return "\n".join(line.rstrip() for line in value.splitlines() if line.strip() and not line.lstrip().startswith("#"))

    templates = [policy_text(PLACEHOLDER)]
    example = REPO_ROOT / "dataasset/credentials/.sops.yaml.example"
    if example.is_file():
        templates.append(example.read_text(encoding="utf-8"))
    return normalized(text) in {normalized(template) for template in templates}


def check_policy(policy: Path, key: Path, asset_root: Path, check_ref: str, sops: str) -> None:
    """Round-trip only synthetic data under the selected rule; never read secrets."""
    parts = check_ref.removeprefix("vault://").split("/")
    if not check_ref.startswith("vault://") or len(parts) < 2 or any(part in ("", ".", "..") for part in parts):
        raise VaultInitError("--check-ref must use vault://namespace/name without empty or dot path segments")
    env = dict(os.environ, DATAASSET_ROOT=str(asset_root), SOPS_CONFIG=str(policy))
    if key.is_file():
        env["SOPS_AGE_KEY_FILE"] = str(key)
    probe = json.dumps({"access_key_secret": "secweaver-init-probe", "password": "secweaver-init-probe", "token": "secweaver-init-probe"})
    encrypted = run_tool([
        sops, "--config", str(policy), "--encrypt", "--filename-override",
        "secrets/" + "/".join(parts) + ".enc.yaml", "--input-type", "json", "--output-type", "json", "/dev/stdin",
    ], env=env, input_text=probe)
    run_tool([sops, "--decrypt", "--input-type", "json", "--output-type", "json", "/dev/stdin"], env=env, input_text=encrypted)


def publish_file(source: Path, destination: Path) -> None:
    """Persist contents and rename before exposing a usable policy to UI writers."""
    with source.open("rb") as handle:
        os.fsync(handle.fileno())
    os.replace(source, destination)
    directory = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def initialize_vault(asset_root: Path, *, check_ref: str = DEFAULT_CHECK_REF) -> str:
    """Create an empty Vault or verify an existing one, without generating secrets.

    A persistent flock inode serializes initializers; unlinking it would allow
    competing locks. Candidate keys/policies stay in a private temporary directory
    until a native crypto check passes. Publish the key before the policy so an
    interrupted commit can safely reuse that key on the next run.
    """
    sops = resolve_tool("sops", "SOPS_BIN")
    asset_root = asset_root.resolve()
    if not asset_root.is_dir():
        raise VaultInitError(f"DATAASSET_ROOT does not exist: {asset_root}; select or copy a DataAsset registry first.")
    vault = asset_root / "credentials"
    if vault.is_symlink() or (vault / ".age").is_symlink():
        raise VaultInitError("Vault directories must not be symlinks; select the actual DataAsset root instead.")
    vault.mkdir(exist_ok=True)
    age_dir = vault / ".age"
    age_dir.mkdir(mode=0o700, exist_ok=True)
    key, policy = age_dir / "key.txt", vault / ".sops.yaml"
    lock_fd = os.open(age_dir / "init.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise VaultInitError("Vault initialization is already running; wait for it to finish and retry.") from exc
        if policy.is_symlink() or key.is_symlink():
            raise VaultInitError("Vault policy/key is a symlink; use regular files or configure an external SOPS key instead.")
        existing = policy.read_text(encoding="utf-8") if policy.exists() else None
        if existing is not None and PLACEHOLDER not in existing:
            check_policy(policy, key, asset_root, check_ref, sops)
            return "existing policy/key preserved; crypto check passed"

        # Lost configuration never licenses generating a replacement key for
        # existing ciphertext. Enumerate names only; no saved credential is opened.
        if any((vault / "secrets").rglob("*.enc.yaml")):
            raise VaultInitError("Vault contains ciphertext but its policy is missing/uninitialized; restore the original .sops.yaml and private key. Refusing to reinitialize.")
        if existing is not None and not is_shipped_placeholder(existing):
            raise VaultInitError("Custom Vault policy contains a placeholder; configure its recipients manually. Existing policy was preserved.")
        keygen = resolve_tool("age-keygen", "AGE_KEYGEN_BIN")
        with tempfile.TemporaryDirectory(prefix="init-", dir=age_dir) as directory:
            staging = Path(directory)
            candidate_key = key
            if not key.exists():
                candidate_key = staging / "key.txt"
                run_tool([keygen, "-o", str(candidate_key)], env=dict(os.environ))
                candidate_key.chmod(0o600)
            recipient = run_tool([keygen, "-y", str(candidate_key)], env=dict(os.environ)).strip()
            candidate_policy = staging / ".sops.yaml"
            candidate_policy.write_text(policy_text(recipient), encoding="utf-8")
            candidate_policy.chmod(0o600)
            check_policy(candidate_policy, candidate_key, asset_root, check_ref, sops)
            if candidate_key != key:
                publish_file(candidate_key, key)
            publish_file(candidate_policy, policy)
        return "initialized; local age key protected with mode 600; no placeholder credentials created"


def main(argv: list[str] | None = None) -> int:
    """Expose the same safe lifecycle to quickstart and the shell Vault CLI."""
    if sys.version_info[:2] < (3, 10):
        print("ERROR: Vault initialization requires Python 3.10+; no key or policy was changed.", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-ref", default=DEFAULT_CHECK_REF, help="Synthetic check path for an existing restricted policy")
    args = parser.parse_args(argv)
    root = Path(os.environ.get("DATAASSET_ROOT") or REPO_ROOT / "dataasset").expanduser()
    if not root.is_absolute():
        root = REPO_ROOT / root
    try:
        status = initialize_vault(root, check_ref=args.check_ref)
    except (OSError, UnicodeError, VaultInitError) as exc:
        print(f"ERROR: Vault initialization failed: {exc}", file=sys.stderr)
        return 1
    print(f"[OK] Vault: {status} ({root / 'credentials'})")
    print("Back up the matching private key securely; never commit it to Git.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
