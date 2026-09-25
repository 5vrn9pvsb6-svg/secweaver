"""A channel changes only after all platform checksums pass; no real installers."""
import hashlib
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_channel", ROOT / "src/tools/secweaver-agent/scripts/publish-release-channel.py")
channel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(channel)


class ReleaseChannelTests(unittest.TestCase):
    def test_promotion_is_all_platforms_or_nothing(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o755)
            version = "0.3.21"
            (root / version).mkdir()
            pointer = root / "latest-version.txt"
            pointer.write_text("0.3.19\n")
            archives = []
            for platform in ("linux_amd64", "linux_arm64", "linux_loong64", "windows_amd64", "windows_arm64"):
                ext = ".tar.gz" if platform.startswith("linux") else ".zip"
                p = root / version / f"secweaver-agent_{version}_{platform}{ext}"
                p.write_bytes(platform.encode())
                Path(str(p) + ".sha256").write_text(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n")
                archives.append(p)
            archives[-1].write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                channel.promote(root, version)
            self.assertEqual(pointer.read_text(), "0.3.19\n")
            archives[-1].write_bytes(b"windows_arm64")
            # Restrictive umasks must fail before changing the public pointer,
            # including when the publisher itself can read every archive.
            for path, mode, restore in ((root / version, 0o700, 0o755), (archives[0], 0o600, 0o644)):
                path.chmod(mode)
                with self.assertRaises(ValueError):
                    channel.promote(root, version)
                self.assertEqual(pointer.read_text(), "0.3.19\n")
                path.chmod(restore)
            with mock.patch.object(channel.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "runuser")):
                with self.assertRaisesRegex(ValueError, "runtime-user"):
                    channel.promote(root, version, "gateway-test")
            self.assertEqual(pointer.read_text(), "0.3.19\n")
            channel.promote(root, version)
            self.assertEqual(pointer.read_text(), version + "\n")
            archives[0].unlink()
            archives[0].symlink_to(archives[1])
            with self.assertRaises(ValueError):
                channel.promote(root, version)
            self.assertEqual(pointer.read_text(), version + "\n")

    def test_invalid_versions_and_unpinned_templates(self):
        for version in ("../escape", "1.2.3\n", "latest", "1" * 66):
            with self.assertRaises(ValueError):
                channel.promote(Path("/unused"), version)
        for path in ("packaging/bootstrap-install.sh", "packaging/windows/bootstrap-install.ps1"):
            script = (ROOT / "src/tools/secweaver-agent" / path).read_text()
            self.assertIn("latest-version.txt", script)
            self.assertNotIn("EMBEDDED_AGENT_VERSION", script)
            self.assertNotIn("EmbeddedAgentVersion", script)
