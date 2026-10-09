"""Isolated filesystem/service-boundary tests; never touch installed services."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "packaging/recovery/recover-saas-update.py"
SPEC = importlib.util.spec_from_file_location("recovery", str(SOURCE))
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
PROFILE = json.loads(SOURCE.with_name("saas-0.3.83.json").read_text())


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        for name in ("etc", "data", "bin", "data/update"):
            (self.root / name).mkdir(exist_ok=True)
        self.config = self.root / "etc/config.json"
        self.binary = self.root / "bin/secweaver-agent"
        self.binary.write_bytes(b"old binary")
        self.binary.chmod(0o755)
        self.device = "swd_" + "a" * 52
        self.identity = self.root / "data/license-state.json"
        self.identity.write_text(json.dumps({"device_id": self.device}))
        (self.root / "data/device-ed25519.key").write_bytes(b"synthetic identity")
        (self.root / "data/learning.json").write_bytes(b"synthetic baseline")
        self.cfg = {"enterprise_id": "TESTENTERPRISE01", "deployment_mode": "sls_saas",
                    "license": {"server_url": PROFILE["server_url"]}, "modules": {"example": {"enabled": True}},
                    "update": {"enabled": True, "auto_install": True, "ca_file": "/opt/secweaver-agent/shipper/ca.crt"}}
        self.config.write_text(json.dumps(self.cfg))
        self.new_binary = b"new binary"
        manifest = {"latest": {"version": "0.3.83"}, "binaries": {"linux_amd64": {
            "url": "agent", "size": len(self.new_binary), "sha256": hashlib.sha256(self.new_binary).hexdigest()}}}
        self.envelope = json.dumps({"key_id": PROFILE["key_id"], "payload": base64.b64encode(json.dumps(manifest).encode()).decode()}).encode()
        profile = dict(PROFILE, manifest_sha256=hashlib.sha256(self.envelope).hexdigest())
        self.profile = self.root / "profile.json"
        self.profile.write_text(json.dumps(profile))
        self.args = SimpleNamespace(root=str(self.root), config=None, binary=None, profile=str(self.profile),
                                    service="synthetic.service", mode="migrate", apply=True, health_timeout=30)
        self.version = "0.3.64"
        self.calls = []

    def command(self, args, timeout=60):
        # Only OS service operations and process execution are simulated. The
        # recovery transaction performs its real reads, hashes, backups/renames.
        args = [str(a) for a in args]
        self.calls.append(args)
        if args[0] == "systemctl":
            if args[1] == "show":
                self.assertNotIn("--value", args)  # systemd 219 compatibility
                return "ExecStart={} run -config {}".format(self.binary, self.config)
            return ""
        if args[1] == "version":
            return "secweaver-agent " + (self.version if args[0] == str(self.binary) else "0.3.83") + "\n"
        if args[1:3] == ["update", "check"]:
            self.assertNotEqual(Path(args[args.index("-state-dir") + 1]), self.root / "data/update")
            Path(args[args.index("-status-output") + 1]).write_text(json.dumps({"status": "update_available", "latest_version": "0.3.83"}))
        return ""

    def download(self, url, path, origin, maximum):
        recovery.https_url(url, origin)
        path.write_bytes(self.envelope if url.endswith("update-manifest.json") else self.new_binary)

    def execute(self, health=None, downloader=None):
        with patch.object(recovery, "run", side_effect=self.command), patch.object(recovery, "download", side_effect=downloader or self.download), \
             patch.object(recovery.platform, "machine", return_value="x86_64"), \
             patch.object(recovery, "wait_health", side_effect=health or (lambda *a: "0.3.83")):
            return recovery.recover(self.args)

    def test_repair_and_both_legacy_versions_preserve_identity_baseline(self):
        for version in ("0.3.45", "0.3.64", "0.3.79"):
            with self.subTest(version=version):
                self.version = version
                self.args.mode = "repair" if version == "0.3.79" else "migrate"
                self.binary.write_bytes(b"old binary")
                self.config.write_text(json.dumps(self.cfg))
                before_identity = self.identity.read_bytes()
                result = self.execute()
                after = recovery.read_json(self.config)
                self.assertEqual(after["modules"], self.cfg["modules"])
                self.assertNotIn("ca_file", after["update"])
                self.assertEqual(after["update"]["public_key"], PROFILE["public_key"])
                self.assertEqual(self.identity.read_bytes(), before_identity)
                self.assertEqual((self.root / "data/learning.json").read_bytes(), b"synthetic baseline")
                self.assertEqual(self.binary.read_bytes(), b"old binary" if version == "0.3.79" else self.new_binary)
                self.assertEqual(result["status"], "recovered")
                self.assertEqual((Path(result["backup"]) / "config.json").stat().st_mode & 0o777, 0o600)

    def test_check_only_does_not_stop_service_or_write_config(self):
        self.args.apply = False
        before = self.config.read_bytes()
        self.assertEqual(self.execute()["status"], "checked")
        self.assertEqual(before, self.config.read_bytes())
        self.assertFalse(any(c[:2] == ["systemctl", "stop"] for c in self.calls))
        self.assertFalse((self.root / "data/recovery").exists())

    def test_health_failure_restores_config_and_binary(self):
        before = self.config.read_bytes()
        def unhealthy(*args):
            raise RuntimeError("synthetic health failure")
        with self.assertRaisesRegex(RuntimeError, "restoration attempted"):
            self.execute(health=unhealthy)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.binary.read_bytes(), b"old binary")
        self.assertEqual(self.calls[-1][:2], ["systemctl", "start"])

    def test_concurrent_upgrade_is_never_rolled_back(self):
        def concurrent(*args):
            self.binary.write_bytes(b"concurrent signed upgrade")
            raise RuntimeError("synthetic health failure")
        with self.assertRaisesRegex(RuntimeError, "Concurrent update"):
            self.execute(health=concurrent)
        self.assertEqual(self.binary.read_bytes(), b"concurrent signed upgrade")

    def test_hash_mismatch_prevents_execution_or_service_stop(self):
        def corrupt(url, path, origin, maximum):
            self.download(url, path, origin, maximum)
            if not url.endswith("update-manifest.json"):
                path.write_bytes(b"tampered executable")
        with self.assertRaisesRegex(ValueError, "binary hash"):
            self.execute(downloader=corrupt)
        self.assertFalse(any(c[:2] == ["systemctl", "stop"] for c in self.calls))
        self.assertFalse(any(c[0] != str(self.binary) and c[0] != "systemctl" for c in self.calls))

    def test_pending_transaction_is_not_removed(self):
        lock = self.root / "data/update/update.lock"
        lock.write_text("owned by updater")
        with self.assertRaisesRegex(ValueError, "Existing update transaction"):
            self.execute()
        self.assertTrue(lock.exists())

    def test_recovery_profile_cannot_downgrade_or_disable_https(self):
        original = recovery.read_json(self.profile)
        for field, value in (("version", "0.3.20"), ("scheduled_manifest_url", "http://untrusted.invalid/manifest.json")):
            self.profile.write_text(json.dumps(dict(original, **{field: value})))
            with self.assertRaises(ValueError):
                self.execute()
        self.assertFalse(self.calls)

    def test_private_ca_replacement_key_and_revocation_refused(self):
        for field, value in (("ca_file", "/private/es/ca.crt"), ("public_key", "other-key"), ("revoked_key_ids", [PROFILE["key_id"]])):
            cfg = copy.deepcopy(self.cfg)
            cfg["update"][field] = value
            with self.assertRaises(ValueError):
                recovery.prepare_config(cfg, PROFILE)
        cfg = copy.deepcopy(self.cfg)
        cfg["deployment_mode"] = "es_private"
        with self.assertRaises(ValueError):
            recovery.prepare_config(cfg, PROFILE)

    def test_explicit_update_disable_is_preserved(self):
        self.cfg["update"].update(enabled=False, auto_install=False)
        result = recovery.prepare_config(self.cfg, PROFILE)
        self.assertFalse(result["update"]["enabled"])
        self.assertFalse(result["update"]["auto_install"])


if __name__ == "__main__":
    unittest.main()
