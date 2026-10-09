#!/usr/bin/env python3
"""Linux systemd SaaS recovery; Python 3.6+, no external Python packages."""
import argparse
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urljoin, urlsplit


def read_json(path):
    # Strict object input and bounded reads prevent accidental use of a log,
    # symlink, special file or a different product's state as configuration.
    regular(path)
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("JSON exceeds 4 MiB: " + str(path))
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object: " + str(path))
    return value


def regular(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected a non-symlink regular file: " + str(path))


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for part in iter(lambda: source.read(1024 * 1024), b""):
            result.update(part)
    return result.hexdigest()


def run(args, timeout=60):
    # Never include subprocess output in raised errors: startup tools may print
    # authorization material. Diagnostics are kept in the root-only work dir.
    result = subprocess.run([str(x) for x in args], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        fd, log = tempfile.mkstemp(prefix="secweaver-recovery-error-", suffix=".log")
        with os.fdopen(fd, "wb") as destination:
            destination.write(result.stdout[-65536:])
        raise RuntimeError("Command failed (exit {}): {}; private diagnostic: {}".format(result.returncode, args[0], log))
    return result.stdout.decode("utf-8", errors="replace")


def https_url(url, origin):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != urlsplit(origin).netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Recovery URLs must use the trusted profile's HTTPS origin without credentials/query")
    return url


def download(url, path, origin, maximum):
    # curl is already an installation prerequisite on supported systemd hosts.
    # Do not follow redirects or disable certificate validation during recovery.
    https_url(url, origin)
    code = run(["curl", "--silent", "--show-error", "--fail", "--proto", "=https",
                "--connect-timeout", "10", "--max-time", "180", "--max-filesize", str(maximum),
                "--output", path, "--write-out", "%{http_code}", url], timeout=190)
    if code != "200" or path.stat().st_size > maximum:
        raise ValueError("Download did not return a bounded HTTP 200 response")


def prepare_config(cfg, profile):
    # This recovery path is SaaS-only. Preserve ES/private PKI and every unrelated
    # field; only the exact known missing shipped CA can be removed automatically.
    result = copy.deepcopy(cfg)
    license_cfg = cfg.get("license", {})
    if cfg.get("deployment_mode") == "es_private" or license_cfg.get("server_url", "").rstrip("/") != profile["server_url"]:
        raise ValueError("Not the SaaS server in the trusted profile; private ES requires its own CA")
    update = result.setdefault("update", {})
    ca = update.get("ca_file", "")
    known = {"/opt/secweaver-agent/shipper/ca.crt", "/opt/secweaver-agent/etc/shipper/ca.crt"}
    if ca:
        if ca not in known or Path(ca).exists() or Path(ca).is_symlink():
            raise ValueError("Custom/existing update CA requires operator review; it was not removed")
        update.pop("ca_file", None)
    key = base64.b64decode(profile["public_key"], validate=True)
    if len(key) != 32 or "ed25519-" + hashlib.sha256(key).hexdigest()[:16] != profile["key_id"]:
        raise ValueError("Invalid trusted profile public key")
    if profile["key_id"] in update.get("revoked_key_ids", []):
        raise ValueError("Profile key has been revoked locally; recovery must not override revocation")
    existing = update.get("public_key", "")
    if existing and existing != profile["public_key"]:
        raise ValueError("Different existing public key requires operator review")
    update["public_key"] = profile["public_key"]
    update["manifest_url"] = profile["scheduled_manifest_url"]
    # Do not silently enable an intentionally disabled updater. Future installs
    # remain tenant/campaign controlled, including machines bridged manually.
    update["require_server_policy"] = True
    return result


def atomic_copy(source, target, mode):
    # Replace on the destination filesystem and fsync before rename. The service
    # must be stopped by the caller; keep the original binary/config for rollback.
    fd, name = tempfile.mkstemp(prefix=".recovery-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as destination, source.open("rb") as src:
            shutil.copyfileobj(src, destination)
            destination.flush()
            os.fchmod(destination.fileno(), mode)
            os.fsync(destination.fileno())
        os.replace(name, str(target))
        directory = os.open(str(target.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def check_pending(state_dir):
    # Cooperate with the running updater without deleting its lock, replay or
    # rollback state. Recheck after service stop before making any mutation.
    for name in ("update.lock", "health.pending", "activation.attempted"):
        if (state_dir / name).exists():
            raise ValueError("Existing update transaction requires recovery first: " + name)
    state = state_dir / "state.json"
    if state.exists() and read_json(state).get("health_pending"):
        raise ValueError("Existing update is awaiting health confirmation")


def wait_health(service, status_path, device_id, target, started, timeout):
    # Require fresh module health from the new process, not only a successful
    # systemctl return. Low-traffic hosts need no synthetic security events.
    deadline = time.monotonic() + timeout
    stable_since = None
    while time.monotonic() < deadline:
        try:
            run(["systemctl", "is-active", "--quiet", service], timeout=10)
            health = read_json(status_path)
            modules = health.get("modules", {})
            observed = health.get("agent_version", "")
            # Repair can unblock an existing campaign immediately. A healthy
            # newer binary is success, not a reason to overwrite it with backup.
            version_ok = bool(re.fullmatch(r"\d+\.\d+\.\d+", observed)) and tuple(map(int, observed.split("."))) >= tuple(map(int, target.split(".")))
            healthy = (status_path.stat().st_mtime >= started and version_ok
                       and health.get("device_id") == device_id and modules
                       and all(m.get("status") == "running" for m in modules.values()))
            if healthy:
                stable_since = stable_since or time.monotonic()
                if time.monotonic() - stable_since >= 15:
                    return observed
            else:
                stable_since = None
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
            stable_since = None
        time.sleep(2)
    raise RuntimeError("Service did not produce fresh matching device/version/module health before timeout")


def recover(args):
    root = Path(args.root).resolve()
    config = Path(args.config or str(root / "etc/config.json"))
    binary = Path(args.binary or str(root / "bin/secweaver-agent"))
    regular(config)
    regular(binary)
    profile = read_json(Path(args.profile))
    if profile.get("schema_version") != 1:
        raise ValueError("Unsupported recovery profile")
    if not re.fullmatch(r"\d+\.\d+\.\d+", profile.get("version", "")) or tuple(map(int, profile["version"].split("."))) < (0, 3, 83):
        raise ValueError("Recovery target must be 0.3.83 or later; this script cannot authorize a downgrade")
    https_url(profile["scheduled_manifest_url"], profile["server_url"])
    cfg = read_json(config)
    original_hash = digest(config)
    original_binary_hash = digest(binary)
    version_output = run([binary, "version"])
    match = re.search(r"\b0\.3\.[0-9]+\b", version_output)
    current = match.group(0) if match else "unknown"
    allowed = {"repair": {"0.3.79", profile["version"]}, "migrate": {"0.3.45", "0.3.64", profile["version"]}}
    if current not in allowed[args.mode]:
        raise ValueError("Unexpected installed version {}; this recovery is scoped to {}".format(current, sorted(allowed[args.mode])))
    changed = prepare_config(cfg, profile)
    license_cfg = cfg.get("license", {})
    state_path = Path(license_cfg.get("state_path") or str(root / "data/license-state.json"))
    key_path = Path(license_cfg.get("identity_key_path") or str(state_path.parent / "device-ed25519.key"))
    regular(key_path)
    identity_key_hash = digest(key_path)
    device_id = read_json(state_path).get("device_id", "")
    if not re.fullmatch(r"swd_[a-z2-7]{52}", device_id):
        raise ValueError("Missing existing device_v2 identity; do not enroll a replacement during recovery")
    state_dir = Path(cfg.get("update", {}).get("state_dir") or str(root / "data/update"))
    check_pending(state_dir)
    service = args.service
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+", service):
        raise ValueError("Invalid service name")
    # --value is unavailable in CentOS 7's systemd 219; match the named property.
    command = run(["systemctl", "show", service, "--property=ExecStart"])
    if str(config) not in command or (str(binary) not in command and str(binary.parent / "secweaver-agent-launch") not in command):
        raise ValueError("Service ExecStart does not match config/binary; pass the actual --config/--binary/--service")
    run(["systemctl", "is-active", "--quiet", service])
    if shutil.disk_usage(str(root)).free < 256 * 1024 * 1024:
        raise ValueError("Recovery requires at least 256 MiB free space")
    with tempfile.TemporaryDirectory(prefix="secweaver-recovery-") as directory:
        work = Path(directory)
        manifest_file = work / "manifest.json"
        download(profile["manifest_url"], manifest_file, profile["server_url"], 4 * 1024 * 1024)
        if digest(manifest_file) != profile["manifest_sha256"]:
            raise ValueError("Pinned manifest SHA-256 mismatch")
        envelope = read_json(manifest_file)
        manifest = json.loads(base64.b64decode(envelope["payload"], validate=True))
        if manifest.get("latest", {}).get("version") != profile["version"] or envelope.get("key_id") != profile["key_id"]:
            raise ValueError("Pinned release version/signer mismatch")
        candidate = binary
        migrating = args.mode == "migrate" and current != profile["version"]
        if migrating:
            arch = {"x86_64": "amd64", "aarch64": "arm64", "loongarch64": "loong64"}.get(platform.machine())
            artifact = manifest["binaries"]["linux_" + str(arch)]
            candidate = work / "secweaver-agent"
            download(urljoin(profile["manifest_url"], artifact["url"]), candidate, profile["server_url"], 64 * 1024 * 1024)
            if digest(candidate) != artifact["sha256"] or candidate.stat().st_size != artifact["size"]:
                raise ValueError("Pinned binary hash/size mismatch; refusing to execute")
            candidate.chmod(0o700)
            if profile["version"] not in run([candidate, "version"]).split():
                raise ValueError("Candidate version mismatch")
        check_state = work / "check-state"
        check_state.mkdir()
        for name in ("state.json", "trusted-update-keys.json"):
            source = state_dir / name
            if source.exists():
                regular(source)
                shutil.copyfile(str(source), str(check_state / name))
        # The hash pin authenticates bytes before first execution. The native
        # checker then verifies Ed25519, expiry, generation and local revocations.
        run([candidate, "update", "check", "-manifest-url", profile["manifest_url"], "-public-key", profile["public_key"],
             "-device-id", device_id, "-state-dir", check_state, "-status-output", work / "check.json"], timeout=60)
        result = read_json(work / "check.json")
        if result.get("status") not in ("up_to_date", "update_available") or result.get("latest_version") != profile["version"]:
            raise ValueError("Signed check did not approve this target: " + str(result.get("reason", "unknown")))
        staged = work / "config.json"
        staged.write_text(json.dumps(changed, indent=2) + "\n", encoding="utf-8")
        staged.chmod(0o600)
        run([candidate, "run", "-config", staged, "-dry-run"], timeout=60)
        if not args.apply:
            return {"status": "checked", "mode": args.mode, "current": current, "target": profile["version"], "device_id": device_id, "apply_required": True}
        backup_root = root / "data/recovery"
        backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        backup = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%d-%H%M%S-"), dir=str(backup_root)))
        shutil.copy2(str(config), str(backup / "config.json"))
        (backup / "config.json").chmod(0o600)
        shutil.copy2(str(binary), str(backup / "secweaver-agent"))
        # Stop before the final checks. A concurrent normal update/config edit
        # wins; do not overwrite it using our earlier snapshot.
        stopped = False
        mutated = False
        expected_binary_hash = original_binary_hash
        try:
            stopped = True
            run(["systemctl", "stop", service], timeout=90)
            check_pending(state_dir)
            if digest(config) != original_hash or digest(binary) != original_binary_hash:
                raise ValueError("Config/binary changed during precheck; retry from a fresh snapshot")
            if read_json(state_path).get("device_id") != device_id or digest(key_path) != identity_key_hash:
                raise ValueError("Device identity changed during precheck")
            mutated = True
            atomic_copy(staged, config, 0o600)
            if migrating:
                atomic_copy(candidate, binary, stat.S_IMODE(binary.stat().st_mode))
                expected_binary_hash = digest(candidate)
            started = time.time()
            run(["systemctl", "start", service], timeout=60)
            installed = wait_health(service, Path(cfg.get("status_path") or str(root / "data/status.json")), device_id,
                                    profile["version"] if migrating else current, started, args.health_timeout)
            if digest(key_path) != identity_key_hash or read_json(state_path).get("device_id") != device_id:
                raise ValueError("Device identity changed after restart")
        except BaseException as error:
            # Do not undo an automatic update that started after service resume.
            # Its own updater owns rollback/replay state and binary activation.
            if mutated:
                try:
                    check_pending(state_dir)
                    if digest(binary) != expected_binary_hash:
                        raise ValueError("Binary changed after recovery")
                except (OSError, ValueError):
                    raise RuntimeError("Concurrent update detected; no rollback attempted. Inspect service and backup: " + str(backup))
            if stopped:
                try:
                    run(["systemctl", "stop", service], timeout=90)
                    if mutated:
                        atomic_copy(backup / "config.json", config, 0o600)
                        atomic_copy(backup / "secweaver-agent", binary, stat.S_IMODE((backup / "secweaver-agent").stat().st_mode))
                    run(["systemctl", "start", service], timeout=60)
                except BaseException as restore_error:
                    raise RuntimeError("Recovery failed: {}; restoration failed: {}; backup: {}".format(error, restore_error, backup))
            raise RuntimeError("Recovery failed: {}; restoration attempted. Inspect service and backup: {}".format(error, backup))
        return {"status": "recovered", "mode": args.mode, "current": current, "installed": installed,
                "device_id": device_id, "backup": str(backup), "automatic_update_enabled": changed["update"].get("enabled", False)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["repair", "migrate"], required=True)
    parser.add_argument("--profile", default=str(Path(__file__).with_name("saas-0.3.83.json")))
    parser.add_argument("--root", default="/opt/secweaver-agent")
    parser.add_argument("--config")
    parser.add_argument("--binary")
    parser.add_argument("--service", default="secweaver-agent.service")
    parser.add_argument("--health-timeout", type=int, default=180)
    parser.add_argument("--apply", action="store_true", help="back up, repair/migrate, restart and verify; default only checks")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Run as root on a Linux systemd host")
    if not 30 <= args.health_timeout <= 600:
        parser.error("--health-timeout must be 30..600 seconds")
    os.umask(0o077)
    # A host-local process lock serializes recovery invocations. The normal
    # updater owns its separate lock; check_pending never removes either lock.
    lock_path = Path(args.root).resolve() / "data/.saas-recovery.lock"
    fd = None
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(recover(args), ensure_ascii=True))
    except Exception as error:
        print(json.dumps({"status": "failed", "reason": str(error)}), file=sys.stderr)
        return 1
    finally:
        if fd is not None:
            os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
