"""Read-only-to-host regression using old/new real Linux Agent binaries."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--old-binary", required=True)
    parser.add_argument("--new-binary", required=True)
    parser.add_argument("--profile", required=True)
    options = parser.parse_args()
    profile = json.loads(Path(options.profile).read_text())
    with tempfile.TemporaryDirectory(prefix="secweaver-native-probe-") as directory:
        root = Path(directory)
        config = root / "config.json"
        config.write_text(json.dumps({"enterprise_id": "TESTENTERPRISE01", "modules": {"host-process-snapshot": {"enabled": True}},
                                     "update": {"enabled": False, "ca_file": str(root / "missing.crt"), "state_dir": str(root / "state")}}))
        common = ["config", "set-update", "-config", str(config), "-manifest-url", profile["scheduled_manifest_url"]]
        broken = common + ["-auto-install", "true", "-require-server-policy", "true", "-public-key", profile["public_key"]]
        # Never print native output: only the assertion result is shared. Both
        # commands operate on a fresh fixture, not the installed configuration.
        old = subprocess.run([options.old_binary] + broken, capture_output=True, timeout=30)
        assert old.returncode == 0 and not json.loads(config.read_text())["update"].get("public_key"), "old truncation not reproduced"
        before = config.read_bytes()
        rejected = subprocess.run([options.new_binary] + broken, capture_output=True, timeout=30)
        assert rejected.returncode == 2 and config.read_bytes() == before, "bad argv was not rejected atomically"
        corrected = common + ["-auto-install=true", "-require-server-policy=true", "-public-key", profile["public_key"], "-use-system-ca"]
        new = subprocess.run([options.new_binary] + corrected, capture_output=True, timeout=30)
        assert new.returncode == 0, "corrected configuration failed"
        saved = json.loads(config.read_text())["update"]
        assert saved["public_key"] == profile["public_key"] and not saved.get("ca_file"), "trust was not persisted"
        check = subprocess.run([options.new_binary, "update", "check", "-manifest-url", profile["manifest_url"],
                                "-device-id", "swd_" + "a" * 52,
                                "-public-key", saved["public_key"], "-state-dir", str(root / "check-state"),
                                "-status-output", str(root / "check.json")], capture_output=True, timeout=60)
        status = json.loads((root / "check.json").read_text())
        assert status["latest_version"] == profile["version"], "wrong verified release"
        assert status.get("signer_key_id") == profile["key_id"], "real signature check failed"
        # The fixed test binary is 0.3.84 while the published target is 0.3.83.
        # Successful authentication must still refuse this unauthorized downgrade.
        assert check.returncode == 1 and status["reason"] == "rollback_not_authorized", "downgrade gate was not retained"
    print("PASS: old CLI truncation reproduced; new argv rejection, explicit system CA, key persistence and live signed manifest verified")


if __name__ == "__main__":
    main()
