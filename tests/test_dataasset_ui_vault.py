"""Vault save preconditions use isolated policies, never the user's credentials."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tests.test_dataasset_ui import load_server_module


def local_tool(name: str) -> str | None:
    """Mirror the documented PATH/Homebrew tool locations for optional crypto tests."""
    return shutil.which(name) or next((
        str(path) for base in ("/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin")
        if (path := Path(base) / name).is_file() and os.access(path, os.X_OK)
    ), None)


class TestCredentialVaultPreflight(unittest.TestCase):
    def setUp(self) -> None:
        load_server_module()
        from dataasset_ui_services import credentials

        self.credentials = credentials

    def test_uninitialized_vault_rejects_save_without_writing_plaintext(self) -> None:
        # Both an absent policy and the shipped placeholder must be rejected
        # before real credential data reaches any filesystem or SOPS process.
        for policy in (None, "creation_rules:\n  - age: REPLACE_WITH_YOUR_AGE_PUBLIC_KEY\n"):
            with self.subTest(policy=policy), TemporaryDirectory() as directory:
                root = Path(directory) / "credentials"
                root.mkdir()
                if policy is not None:
                    (root / ".sops.yaml").write_text(policy, encoding="utf-8")
                before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
                with patch.object(self.credentials, "CREDENTIALS_DIR", root), patch.object(
                    self.credentials, "NamedTemporaryFile"
                ) as temporary, patch.object(self.credentials, "encrypt_credential") as encrypt:
                    with self.assertRaisesRegex(ValueError, "Vault 未初始化"):
                        self.credentials.save_credential({
                            "credential_id": "vault://sls/sls-proxy-query",
                            "content": "type: aliyun_ram\naccess_key_secret: SYNTHETIC_ONLY\n",
                        })
                temporary.assert_not_called()
                encrypt.assert_not_called()
                after = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
                self.assertEqual(before, after)
                self.assertFalse((root / "secrets").exists())
                self.assertFalse((root / ".age").exists())

    def test_timeout_is_actionable_and_does_not_write(self) -> None:
        with TemporaryDirectory() as directory, patch.object(
            self.credentials, "CREDENTIALS_DIR", Path(directory) / "credentials"
        ), patch.object(self.credentials.subprocess, "Popen") as start, patch.object(self.credentials.os, "killpg") as kill:
            process = start.return_value.__enter__.return_value
            process.pid = 1234
            process.communicate.side_effect = [subprocess.TimeoutExpired("check", 30), ("", "")]
            with self.assertRaisesRegex(TimeoutError, "Vault.*超时"):
                self.credentials.save_credential({"credential_id": "vault://sls/query", "content": "type: aliyun_ram\n"})
            self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertTrue(start.call_args.kwargs["start_new_session"])
            kill.assert_called_once_with(1234, signal.SIGKILL)
            self.assertEqual(process.communicate.call_count, 2)


@unittest.skipUnless(local_tool("sops") and local_tool("age-keygen"), "SOPS and age-keygen are required for crypto integration")
class TestCredentialVaultCrypto(unittest.TestCase):
    def setUp(self) -> None:
        # Every key and credential here is disposable. Patch both the UI paths
        # and CLI environment so subprocesses cannot write into the real Vault.
        load_server_module()
        from dataasset_ui_services import credentials

        self.credentials = credentials
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "资产 root's"
        self.vault = self.root / "credentials"
        self.key = self.vault / ".age" / "key.txt"
        self.key.parent.mkdir(parents=True)
        self.env = dict(os.environ, DATAASSET_ROOT=str(self.root), SOPS_BIN=local_tool("sops"))
        for target, value in (("CREDENTIALS_DIR", self.vault), ("subprocess_env", lambda: self.env.copy())):
            mock = patch.object(self.credentials, target, value)
            mock.start()
            self.addCleanup(mock.stop)
        self.generate_key(self.key)
        self.recipient = subprocess.run(
            [local_tool("age-keygen"), "-y", str(self.key)], check=True, capture_output=True, text=True, timeout=10
        ).stdout.strip()
        self.policy = self.vault / ".sops.yaml"
        self.policy.write_text(json.dumps({"creation_rules": [{
            "path_regex": r"secrets/.*\.enc\.yaml$", "encrypted_regex": "^(access_key_secret|password|token)$",
            "age": self.recipient,
        }]}), encoding="utf-8")

    def generate_key(self, path: Path) -> None:
        """Let age create test keys; never print or synthesize private key material."""
        subprocess.run([local_tool("age-keygen"), "-o", str(path)], check=True, capture_output=True, timeout=10)
        path.chmod(0o600)

    def test_native_probe_and_save_succeed_without_changing_policy_or_key(self) -> None:
        before = self.policy.read_bytes(), self.key.read_bytes()
        self.credentials.ensure_vault_ready("vault://sls/sls-proxy-query")
        self.assertFalse((self.vault / "secrets").exists())
        self.assertFalse((self.vault / "examples").exists())
        encrypted, ref = self.credentials.save_credential({
            "credential_id": "vault://sls/sls-proxy-query",
            "content": "type: aliyun_ram\naccess_key_secret: SYNTHETIC_ONLY\n",
        })
        self.assertEqual(ref, "vault://sls/sls-proxy-query")
        self.assertIn("ENC[", encrypted.read_text(encoding="utf-8"))
        self.assertNotIn("SYNTHETIC_ONLY", encrypted.read_text(encoding="utf-8"))
        self.assertEqual(encrypted.stat().st_mode & 0o777, 0o600)
        self.assertEqual(before, (self.policy.read_bytes(), self.key.read_bytes()))
        self.assertEqual(list(self.vault.glob(".credential-*")), [])

    def test_missing_key_and_wrong_key_reject_save_and_preserve_existing_files(self) -> None:
        example = self.vault / "examples" / "sls" / "query.yaml"
        encrypted = self.vault / "secrets" / "sls" / "query.enc.yaml"
        example.parent.mkdir(parents=True)
        encrypted.parent.mkdir(parents=True)
        example.write_text('type: aliyun_ram\naccess_key_secret: "REPLACE_ME"\n', encoding="utf-8")
        encrypted.write_text("SYNTHETIC_EXISTING_CIPHERTEXT", encoding="utf-8")
        before = example.read_bytes(), encrypted.read_bytes(), self.policy.read_bytes()
        self.key.unlink()
        for wrong_key in (False, True):
            with self.subTest(wrong_key=wrong_key):
                if wrong_key:
                    self.generate_key(self.key)
                with patch.object(self.credentials, "NamedTemporaryFile") as temporary:
                    with self.assertRaisesRegex(ValueError, "Vault 密钥不可用") as error:
                        self.credentials.save_credential({
                            "credential_id": "vault://sls/query",
                            "content": "type: aliyun_ram\naccess_key_secret: SYNTHETIC_NEW_SECRET\n",
                        })
                self.assertIn("不要重新生成密钥", str(error.exception))
                temporary.assert_not_called()
                self.assertEqual(before, (example.read_bytes(), encrypted.read_bytes(), self.policy.read_bytes()))

    def test_external_age_key_remains_supported(self) -> None:
        external = self.root / "external-key.txt"
        self.key.rename(external)
        self.env["SOPS_AGE_KEY_FILE"] = str(external)
        self.credentials.ensure_vault_ready("vault://sls/query")
        self.assertFalse(self.key.exists())

    def test_invalid_or_unmatched_policy_returns_generic_diagnostic(self) -> None:
        for policy in ("creation_rules: [\nSYNTHETIC_PRIVATE_MARKER", "{}", '{"creation_rules": [{"path_regex": "^other/", "age": "invalid"}]}'):
            with self.subTest(policy=policy):
                self.policy.write_text(policy, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Vault 策略不可用") as error:
                    self.credentials.ensure_vault_ready("vault://sls/query")
                self.assertNotIn("SYNTHETIC_PRIVATE_MARKER", str(error.exception))
                self.assertFalse((self.vault / "secrets").exists())

    def test_key_groups_are_parsed_by_native_sops(self) -> None:
        self.policy.write_text(json.dumps({"creation_rules": [{
            "path_regex": r"secrets/.*\.enc\.yaml$", "key_groups": [{"age": [self.recipient]}],
        }]}), encoding="utf-8")
        self.credentials.ensure_vault_ready("vault://sls/query")

    def test_missing_sops_has_an_actionable_message(self) -> None:
        self.env["SOPS_BIN"] = str(self.root / "missing-sops")
        with self.assertRaisesRegex(ValueError, "未找到可执行的 SOPS") as error:
            self.credentials.ensure_vault_ready("vault://sls/query")
        self.assertIn("SOPS_BIN", str(error.exception))
        self.assertFalse((self.vault / "secrets").exists())

    def test_placeholder_hint_preserves_unicode_spaces_and_shell_metacharacters(self) -> None:
        self.policy.write_text("creation_rules:\n  - age: REPLACE_WITH_YOUR_AGE_PUBLIC_KEY\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Vault 未初始化") as error:
            self.credentials.ensure_vault_ready("vault://sls/query")
        self.assertIn("DATAASSET_ROOT=", str(error.exception))
        self.assertIn("资产 root", str(error.exception))
        self.assertIn("仅对空 Vault", str(error.exception))

    def test_timeout_kills_sops_descendants_and_returns_promptly(self) -> None:
        # This fake local tool models a blocked external key service with a
        # grandchild holding inherited pipes. Killing only Bash hangs this test.
        child_file = self.root / "child.pid"
        tool = self.root / "blocked-sops"
        tool.write_text(
            f"#!{sys.executable}\nimport subprocess, sys, time\nfrom pathlib import Path\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            f"Path({str(child_file)!r}).write_text(str(child.pid))\n"
            "time.sleep(60)\n", encoding="utf-8"
        )
        tool.chmod(0o700)
        self.env["SOPS_BIN"] = str(tool)
        started = time.monotonic()
        # Full-suite load can delay Bash/Python startup beyond half a second.
        # Leave fixture startup headroom while still asserting a bounded kill of
        # the tool and grandchild, far below the production 30-second timeout.
        with patch.object(self.credentials, "VAULT_CHECK_TIMEOUT_SECONDS", 2):
            with self.assertRaisesRegex(TimeoutError, "Vault.*超时"):
                self.credentials.ensure_vault_ready("vault://sls/query")
        self.assertLess(time.monotonic() - started, 8)
        self.assertTrue(child_file.exists())
        child_pid = child_file.read_text(encoding="utf-8")
        # An orphan may briefly be a zombie awaiting the OS reaper, but must no
        # longer execute. Accept that state rather than depending on reaper timing.
        status = subprocess.run(["ps", "-o", "stat=", "-p", child_pid], capture_output=True, text=True, timeout=2).stdout.strip()
        self.assertTrue(not status or status.startswith("Z"), status)


if __name__ == "__main__":
    unittest.main()
