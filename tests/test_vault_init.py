"""Quickstart Vault setup uses only disposable keys and synthetic credentials."""

from __future__ import annotations

import fcntl
import importlib.util
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tests.test_dataasset_ui_vault import local_tool

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("secweaver_vault_init", ROOT / "src/dataasset/credentials/init_vault.py")
assert spec and spec.loader
vault_init = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vault_init)


class VaultInitPreconditions(unittest.TestCase):
    def test_tool_timeout_terminates_descendants_without_exposing_stderr(self) -> None:
        # This standalone fake crypto tool needs no SOPS installation and models
        # a stuck key-service subprocess retaining the parent's output pipes.
        with TemporaryDirectory() as directory:
            child_file = Path(directory) / "child.pid"
            code = (
                "import subprocess, sys, time\nfrom pathlib import Path\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                f"Path({str(child_file)!r}).write_text(str(child.pid))\n"
                "print('SYNTHETIC_PRIVATE_DIAGNOSTIC', file=sys.stderr, flush=True)\n"
                "time.sleep(60)\n"
            )
            started = time.monotonic()
            # Match UI fixture startup headroom under whole-suite load; this
            # changes only the test budget, not the production timeout.
            with patch.object(vault_init, "TOOL_TIMEOUT_SECONDS", 2):
                with self.assertRaisesRegex(vault_init.VaultInitError, "timed out") as error:
                    vault_init.run_tool([sys.executable, "-c", code], env=dict(os.environ))
            self.assertNotIn("SYNTHETIC_PRIVATE_DIAGNOSTIC", str(error.exception))
            self.assertLess(time.monotonic() - started, 8)
            status = subprocess.run(["ps", "-o", "stat=", "-p", child_file.read_text()],
                                    text=True, capture_output=True, timeout=2).stdout.strip()
            self.assertTrue(not status or status.startswith("Z"), status)

    def test_invalid_explicit_tool_override_is_not_silently_ignored(self) -> None:
        with patch.dict(os.environ, SOPS_BIN="/missing/secweaver-test-sops"):
            with self.assertRaisesRegex(vault_init.VaultInitError, "SOPS_BIN"):
                vault_init.resolve_tool("sops", "SOPS_BIN")

    def test_missing_sops_creates_no_files(self) -> None:
        with TemporaryDirectory() as directory, patch.dict(os.environ, SOPS_BIN="/missing/secweaver-test-sops"):
            with self.assertRaises(vault_init.VaultInitError):
                vault_init.initialize_vault(Path(directory))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_custom_policy_with_placeholder_is_not_a_bundled_template(self) -> None:
        self.assertTrue(vault_init.is_shipped_placeholder(vault_init.policy_text(vault_init.PLACEHOLDER)))
        self.assertFalse(vault_init.is_shipped_placeholder("creation_rules:\n  - age: REPLACE_WITH_YOUR_AGE_PUBLIC_KEY\n"))


@unittest.skipUnless(local_tool("sops") and local_tool("age-keygen"), "native SOPS and age-keygen required")
class VaultInitCrypto(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "资产 root's"
        self.root.mkdir()
        self.vault = self.root / "credentials"
        self.policy = self.vault / ".sops.yaml"
        self.key = self.vault / ".age/key.txt"
        env = patch.dict(os.environ, DATAASSET_ROOT=str(self.root), SOPS_BIN=local_tool("sops"),
                         AGE_KEYGEN_BIN=local_tool("age-keygen"))
        env.start()
        self.addCleanup(env.stop)

    def test_first_init_and_repeat_preserve_key_policy_and_ciphertext(self) -> None:
        self.vault.mkdir()
        self.policy.write_text(vault_init.policy_text(vault_init.PLACEHOLDER), encoding="utf-8")
        self.assertIn("initialized", vault_init.initialize_vault(self.root))
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.vault / "secrets").exists())
        self.assertFalse((self.vault / "examples").exists())
        ciphertext = self.vault / "secrets/sls/query.enc.yaml"
        ciphertext.parent.mkdir(parents=True)
        ciphertext.write_bytes(b"SYNTHETIC_CIPHERTEXT_NOT_TO_BE_OPENED")
        before = self.key.read_bytes(), self.policy.read_bytes(), ciphertext.read_bytes()
        with patch.object(vault_init, "resolve_tool", wraps=vault_init.resolve_tool) as resolve:
            self.assertIn("preserved", vault_init.initialize_vault(self.root))
            self.assertEqual([call.args[0] for call in resolve.call_args_list], ["sops"])
        self.assertEqual(before, (self.key.read_bytes(), self.policy.read_bytes(), ciphertext.read_bytes()))
        self.assertEqual(list(self.key.parent.glob("init-*")), [])

    def test_fresh_checkout_needs_only_the_public_policy_example(self) -> None:
        """The runtime policy is absent from new clones and must be generated locally."""
        self.vault.mkdir()
        example = self.vault / ".sops.yaml.example"
        shipped = (ROOT / "dataasset/credentials/.sops.yaml.example").read_bytes()
        example.write_bytes(shipped)
        self.assertFalse(self.policy.exists())
        self.assertIn("initialized", vault_init.initialize_vault(self.root))
        self.assertTrue(self.policy.is_file())
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(example.read_bytes(), shipped)

    def test_missing_policy_with_existing_key_recovers_without_rotating(self) -> None:
        vault_init.initialize_vault(self.root)
        before = self.key.read_bytes()
        self.policy.unlink()
        vault_init.initialize_vault(self.root)
        self.assertEqual(self.key.read_bytes(), before)

    def test_missing_or_placeholder_policy_with_ciphertext_refuses_reinitialization(self) -> None:
        for placeholder in (False, True):
            with self.subTest(placeholder=placeholder), TemporaryDirectory() as directory:
                root = Path(directory)
                vault = root / "credentials"
                ciphertext = vault / "secrets/sls/query.enc.yaml"
                ciphertext.parent.mkdir(parents=True)
                ciphertext.write_bytes(b"SYNTHETIC_EXISTING")
                policy = vault / ".sops.yaml"
                if placeholder:
                    policy.write_text(vault_init.policy_text(vault_init.PLACEHOLDER))
                before = policy.read_bytes() if placeholder else None
                with self.assertRaisesRegex(vault_init.VaultInitError, "Refusing to reinitialize"):
                    vault_init.initialize_vault(root)
                self.assertFalse((vault / ".age/key.txt").exists())
                self.assertEqual(policy.read_bytes() if policy.exists() else None, before)
                self.assertEqual(ciphertext.read_bytes(), b"SYNTHETIC_EXISTING")

    def test_missing_original_key_fails_without_replacing_policy(self) -> None:
        vault_init.initialize_vault(self.root)
        policy = self.policy.read_bytes()
        self.key.unlink()
        # Exclude unrelated key discovery so this missing-key test is deterministic.
        with patch.dict(os.environ, SOPS_AGE_KEY="", SOPS_AGE_KEY_FILE=str(self.root / "missing-key"), SOPS_AGE_KEY_CMD=""):
            with self.assertRaisesRegex(vault_init.VaultInitError, "restore the original"):
                vault_init.initialize_vault(self.root)
        self.assertFalse(self.key.exists())
        self.assertEqual(self.policy.read_bytes(), policy)

    def test_external_key_and_restricted_policy_are_preserved(self) -> None:
        vault_init.initialize_vault(self.root)
        external = self.root / "external-key.txt"
        self.key.rename(external)
        self.policy.write_text(self.policy.read_text().replace("secrets/.*", "secrets/es/.*"))
        before = self.policy.read_bytes(), external.read_bytes()
        with patch.dict(os.environ, SOPS_AGE_KEY_FILE=str(external)):
            self.assertIn("preserved", vault_init.initialize_vault(self.root, check_ref="vault://es/private-query"))
        self.assertFalse(self.key.exists())
        self.assertEqual(before, (self.policy.read_bytes(), external.read_bytes()))

    def test_crypto_failure_does_not_publish_candidate_key_or_policy(self) -> None:
        self.vault.mkdir()
        self.policy.write_text(vault_init.policy_text(vault_init.PLACEHOLDER))
        before = self.policy.read_bytes()
        with patch.object(vault_init, "check_policy", side_effect=vault_init.VaultInitError("synthetic crypto failure")):
            with self.assertRaisesRegex(vault_init.VaultInitError, "synthetic crypto failure"):
                vault_init.initialize_vault(self.root)
        self.assertFalse(self.key.exists())
        self.assertEqual(self.policy.read_bytes(), before)
        self.assertEqual(list(self.key.parent.glob("init-*")), [])

    def test_custom_placeholder_policy_is_not_overwritten(self) -> None:
        self.vault.mkdir()
        self.policy.write_text("creation_rules:\n  - age: REPLACE_WITH_YOUR_AGE_PUBLIC_KEY\n")
        before = self.policy.read_bytes()
        with self.assertRaisesRegex(vault_init.VaultInitError, "Custom Vault policy"):
            vault_init.initialize_vault(self.root)
        self.assertEqual(self.policy.read_bytes(), before)
        self.assertFalse(self.key.exists())

    def test_key_publish_interruption_can_be_retried_without_rotating(self) -> None:
        # Simulate policy publication failing after the durable key rename. The
        # next init must derive its recipient from that key, not create another.
        publish = vault_init.publish_file

        def interrupted_publish(source, destination):
            if destination == self.policy.resolve():
                raise OSError("synthetic policy publication interruption")
            publish(source, destination)

        with patch.object(vault_init, "publish_file", side_effect=interrupted_publish):
            with self.assertRaisesRegex(OSError, "publication interruption"):
                vault_init.initialize_vault(self.root)
        before = self.key.read_bytes()
        self.assertFalse(self.policy.exists())
        vault_init.initialize_vault(self.root)
        self.assertEqual(self.key.read_bytes(), before)

    def test_unmatched_rule_and_bad_reference_leave_existing_material_unchanged(self) -> None:
        vault_init.initialize_vault(self.root)
        before = self.policy.read_bytes(), self.key.read_bytes()
        for ref in ("vault://sls/../other", "vault://sls//other"):
            with self.subTest(ref=ref), self.assertRaisesRegex(vault_init.VaultInitError, "without empty or dot"):
                vault_init.initialize_vault(self.root, check_ref=ref)
            self.assertEqual(before, (self.policy.read_bytes(), self.key.read_bytes()))
        self.policy.write_text(self.policy.read_text().replace("secrets/.*", "secrets/es/.*"))
        before = self.policy.read_bytes(), self.key.read_bytes()
        with self.assertRaisesRegex(vault_init.VaultInitError, "policy/key check failed"):
            vault_init.initialize_vault(self.root)
        self.assertEqual(before, (self.policy.read_bytes(), self.key.read_bytes()))

    def test_another_initializer_holds_the_lock(self) -> None:
        self.key.parent.mkdir(parents=True)
        with (self.key.parent / "init.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(vault_init.VaultInitError, "already running"):
                vault_init.initialize_vault(self.root)
        self.assertFalse(self.key.exists())
        self.assertFalse(self.policy.exists())

    def test_shell_init_uses_selected_root_and_supports_macos_bash(self) -> None:
        result = subprocess.run(["/bin/bash", str(ROOT / "src/dataasset/credentials/sops-vault.sh"), "init"],
                                cwd=ROOT, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[OK] Vault", result.stdout)
        self.assertTrue(self.key.exists())
        self.assertNotIn("AGE-SECRET-KEY", result.stdout + result.stderr)
        self.assertFalse((ROOT / "credentials").exists())


if __name__ == "__main__":
    unittest.main()
