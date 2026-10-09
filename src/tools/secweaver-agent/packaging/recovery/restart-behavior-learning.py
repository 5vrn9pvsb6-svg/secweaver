#!/usr/bin/env python3
"""Explicit Linux/systemd learning recovery; Python 3.6+, no network access."""
import argparse
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


def read_json(path, maximum=4 << 20):
    # Reject special files and symlinks before bounded reads. State is observed,
    # never rewritten: the Agent remains responsible for authenticating its HMAC.
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("Expected bounded regular JSON file: " + str(path))
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object: " + str(path))
    return value


def run(argv, allowed=(0,)):
    # Never echo command output: doctor/config errors can include local secrets.
    result = subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=60)
    if result.returncode not in allowed:
        fd, diagnostic = tempfile.mkstemp(prefix="secweaver-learning-error-", suffix=".log")
        with os.fdopen(fd, "wb") as out:
            out.write((result.stdout + result.stderr)[-65536:])
        raise RuntimeError("Command failed: {} (exit {}); private diagnostic={}".format(argv[0], result.returncode, diagnostic))
    return result.stdout.decode("utf-8")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def sync_directory(path):
    # Directory entries need their own durability barrier, including new backup
    # directories; syncing file contents alone cannot preserve a crash backup.
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_copy(source, target):
    # Rename and directory fsync keep the old config valid until replacement is
    # durable; private temp permissions also apply to rollback copies.
    fd, name = tempfile.mkstemp(prefix=".relearn-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as out, source.open("rb") as src:
            shutil.copyfileobj(src, out)
            out.flush()
            os.fchmod(out.fileno(), 0o600)
            os.fsync(out.fileno())
        os.replace(name, str(target))
        sync_directory(target.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def status(binary, config):
    # Native doctor authenticates checkpoints. Ignore unrelated doctor warnings,
    # but a missing/invalid learning report cannot authorize a state reset.
    report = json.loads(run([binary, "doctor", "-config", config, "-json",
                             "-check-license=false"], allowed=(0, 1)))
    checks = {c["component"]: c.get("detail", "") for c in report["checks"]}
    detail = checks.get("learning/status", "")
    if not detail and "disabled" in checks.get("learning/config", ""):
        return {"mode": "disabled"}
    values = dict(re.findall(r"\b([a-z_]+)=([^\s;]+)", detail))
    if values.get("mode") not in ("learning", "enforcing", "degraded"):
        raise ValueError("Learning state unavailable/invalid; inspect doctor before recovery")
    return values


def pending(update_dir):
    # Recheck after stopping too: a detached update installer can outlive Agent.
    for name in ("update.lock", "health.pending", "activation.attempted"):
        if (update_dir / name).exists():
            raise ValueError("Finish the existing update transaction first: " + name)
    path = update_dir / "state.json"
    if path.exists() and read_json(path).get("health_pending"):
        raise ValueError("Update health confirmation is pending")


def copy_state(source, target):
    # A full stopped snapshot includes admission journals and the independent
    # file baseline. Never follow links or copy unbounded logs into the backup.
    size, count = 0, 0
    for directory, dirs, files in os.walk(str(source), followlinks=False):
        for name in dirs + files:
            count += 1
            if count > 10000:
                raise ValueError("Learning backup exceeds file-count budget")
            path = Path(directory) / name
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ValueError("Unsupported learning state entry: " + str(path))
            if path.is_file():
                size += path.stat().st_size
    if size > 512 << 20 or shutil.disk_usage(str(target.parent)).free < size * 2 + (32 << 20):
        raise ValueError("Learning backup exceeds budget or available disk space")
    shutil.copytree(str(source), str(target))
    # A successful backup must survive a crash before the new generation starts.
    for directory, dirs, files in os.walk(str(target), topdown=False):
        for name in files:
            with (Path(directory) / name).open("rb") as saved:
                os.fsync(saved.fileno())
        sync_directory(directory)
    sync_directory(target.parent)


def state_locks(state_dir):
    # systemctl stop is not proof that no standalone collector owns the same
    # state. Acquire the Agent's actual flock inodes before backup or rollback.
    descriptors = []
    try:
        for directory in (state_dir, state_dir / "file-operations"):
            if directory.exists():
                if directory.is_symlink() or not directory.is_dir():
                    raise ValueError("Invalid learning directory")
                fd = os.open(str(directory / "lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                descriptors.append(fd)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptors
    except Exception:
        release_locks(descriptors)
        raise


def release_locks(descriptors):
    # Close without deleting lock files, preserving a single ownership inode.
    while descriptors:
        os.close(descriptors.pop())


def recover(args):
    # This helper operates the standard layout only, avoiding guessing about
    # custom module flags/state roots and never changing enrollment or shipping.
    root = Path(args.root).resolve()
    config, supervisor = root / "etc/audit-port-execmon.json", root / "etc/config.json"
    binary = root / "bin/secweaver-agent"
    cfg, main = read_json(config), read_json(supervisor)
    module = main.get("modules", {}).get("audit-port-execmon", {})
    if not module.get("enabled") or module.get("args") != ["-config", str(config)]:
        raise ValueError("Expected enabled audit module with standard -config arguments")
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("Expected installed Agent binary")
    match = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", run([binary, "version"]))
    if not match or tuple(map(int, match.groups())) < (0, 3, 81):
        raise ValueError("Install Agent 0.3.81+ before relearning")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+", args.service):
        raise ValueError("Invalid systemd service name")
    command = run(["systemctl", "show", args.service, "--property=ExecStart"])
    if str(supervisor) not in command or str(binary) not in command:
        # The package launcher is equally valid and supervises the same binary.
        if str(supervisor) not in command or str(root / "bin/secweaver-agent-launch") not in command:
            raise ValueError("Service ExecStart does not match installation root")
    run(["systemctl", "is-active", "--quiet", args.service])
    before = status(binary, supervisor)
    policy = cfg.get("behavior_learning") or {}
    if not isinstance(policy, dict):
        raise ValueError("Expected behavior_learning object")
    state_dir = root / "data/behavior-learning"
    if (policy.get("state_dir") or str(state_dir)) != str(state_dir):
        raise ValueError("Custom state_dir needs its documented manual recovery procedure")
    if policy.get("event_types") and "exec" not in policy["event_types"]:
        raise ValueError("Exec is outside the configured learning scope")
    update_dir = Path(main.get("update", {}).get("state_dir") or str(root / "data/update"))
    pending(update_dir)
    # Healthy learning is not a defect. Preserve it, including empty baselines;
    # an explicit --relearn restarts only a baseline that has no active entries.
    file_detail = json.loads(run([binary, "doctor", "-config", supervisor, "-json",
                                  "-check-license=false"], allowed=(0, 1)))
    file_checks = [c.get("detail", "") for c in file_detail["checks"] if c["component"] == "file-learning/status"]
    entries = int(before.get("baseline_entries", "0"))
    file_active = any("filtering_active=true" in x for x in file_checks)
    if file_active or (entries > 0 and before["mode"] != "degraded"):
        return {"status": "skipped", "reason": "existing_baseline_preserved", "learning": before}
    if before["mode"] == "learning" and not args.relearn and not policy.get("shadow"):
        return {"status": "skipped", "reason": "already_learning", "learning": before}
    checkpoint = state_dir / "state.json"
    generation = policy.get("generation", 0)
    if type(generation) is not int or not 0 <= generation < (1 << 64) - 1:
        raise ValueError("Invalid or exhausted learning generation")
    if checkpoint.exists():
        saved_generation = read_json(checkpoint, 96 << 20)["state"]["generation"]
        if type(saved_generation) is not int:
            raise ValueError("Invalid checkpoint generation")
        generation = max(generation, saved_generation)
    if type(generation) is not int or not 0 <= generation < (1 << 64) - 1:
        raise ValueError("Invalid or exhausted learning generation")
    candidate = copy.deepcopy(cfg)
    candidate["behavior_learning"] = dict(policy, enabled=True, shadow=False, generation=generation + 1)
    result = {"status": "checked", "generation": generation + 1, "learning_before": before,
              "scope": "linux_exec_and_configured_file_op", "immediate_filtering_guaranteed": False}
    if not args.apply:
        return result
    hashes = [digest(p) for p in (config, supervisor, binary)]
    recovery_dir = root / "data/recovery"
    if recovery_dir.is_symlink():
        raise ValueError("Recovery directory must not be a symlink")
    recovery_dir.mkdir(mode=0o700, exist_ok=True)
    sync_directory(recovery_dir.parent)
    backup = Path(tempfile.mkdtemp(prefix="learning-", dir=str(recovery_dir)))
    sync_directory(recovery_dir)
    result["backup"] = str(backup)
    proposed = backup / "candidate.json"
    proposed.write_text(json.dumps(candidate, indent=2) + "\n")
    proposed.chmod(0o600)
    # Use the installed parser for policy validation before stopping collection.
    run([binary, "config", "set-learning-mode", "-config", proposed, "-mode", "enable"])
    stopped = False
    changed = False
    locks = []
    had_state = state_dir.exists()
    try:
        stopped = True
        run(["systemctl", "stop", args.service])
        pending(update_dir)
        if hashes != [digest(p) for p in (config, supervisor, binary)]:
            raise ValueError("Installation changed concurrently; recovery aborted")
        locks = state_locks(state_dir)
        atomic_copy(config, backup / "audit-port-execmon.json")
        if had_state:
            if state_dir.is_symlink():
                raise ValueError("Learning state directory must not be a symlink")
            copy_state(state_dir, backup / "state")
        atomic_copy(proposed, config)
        changed = True
        release_locks(locks)
        started = time.time()
        run(["systemctl", "start", args.service])
        deadline = time.monotonic() + args.health_timeout
        while time.monotonic() < deadline:
            # Startup may briefly expose the old checkpoint or no summary. Wait
            # for native authenticated status and a fresh healthy-time sample.
            try:
                observed = status(binary, supervisor)
                stamp = observed.get("updated_at", "")
                fresh = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
                checkpoint_state = read_json(checkpoint, 96 << 20)["state"]
                if (observed["mode"] == "learning" and fresh >= started - 1
                        and checkpoint.stat().st_mtime >= started
                        and checkpoint_state["generation"] == generation + 1
                        and checkpoint_state.get("healthy_seconds", 0) > 0):
                    run(["systemctl", "is-active", "--quiet", args.service])
                    result.update(status="relearning", learning_after=observed, observed_at=stamp)
                    return result
            except (OSError, ValueError, RuntimeError, KeyError):
                pass
            time.sleep(2)
        raise RuntimeError("New learning generation did not become healthy before timeout")
    except Exception as failure:
        release_locks(locks)
        try:
            if changed:
                run(["systemctl", "stop", args.service])
                pending(update_dir)
                if digest(config) != digest(proposed) or digest(binary) != hashes[2]:
                    raise RuntimeError("Concurrent change prevents rollback")
                locks = state_locks(state_dir)
                if state_dir.exists():
                    os.rename(str(state_dir), str(backup / "failed-state"))
                    sync_directory(state_dir.parent)
                    sync_directory(backup)
                if had_state:
                    copy_state(backup / "state", state_dir)
                atomic_copy(backup / "audit-port-execmon.json", config)
                release_locks(locks)
            if stopped:
                run(["systemctl", "start", args.service])
        except Exception as rollback_error:
            raise RuntimeError("Recovery/rollback failed: {}; inspect backup={}".format(rollback_error, backup))
        finally:
            release_locks(locks)
        raise RuntimeError("{}; original service restored; backup={}".format(failure, backup))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/opt/secweaver-agent")
    parser.add_argument("--service", default="secweaver-agent")
    parser.add_argument("--apply", action="store_true", help="back up, change generation and restart")
    parser.add_argument("--relearn", action="store_true", help="also restart healthy learning with an empty baseline")
    parser.add_argument("--health-timeout", type=int, default=180)
    args = parser.parse_args()
    try:
        if sys.platform != "linux" or os.geteuid() != 0 or not 30 <= args.health_timeout <= 600:
            raise ValueError("Requires Linux root and health-timeout between 30 and 600 seconds")
        # Do not remove the lock inode: another operator may already have it open.
        lock_path = Path(args.root) / "data/learning-recovery.lock"
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = recover(args)
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
