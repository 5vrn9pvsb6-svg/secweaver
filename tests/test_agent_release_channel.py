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
            self.assertEqual((root / "latest-linux-version.txt").read_text(), version + "\n")
            self.assertEqual((root / "latest-windows-version.txt").read_text(), version + "\n")
            archives[0].unlink()
            archives[0].symlink_to(archives[1])
            with self.assertRaises(ValueError):
                channel.promote(root, version)
            self.assertEqual(pointer.read_text(), version + "\n")

    def test_linux_and_windows_can_advance_independently(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o755)
            legacy = "0.3.74"
            linux = "0.3.75"
            (root / legacy).mkdir()
            (root / linux).mkdir()
            (root / legacy).chmod(0o755)
            (root / linux).chmod(0o755)

            def add_archive(version, platform):
                ext = ".tar.gz" if platform.startswith("linux") else ".zip"
                archive = root / version / f"secweaver-agent_{version}_{platform}{ext}"
                archive.write_bytes(f"{version}:{platform}".encode())
                Path(str(archive) + ".sha256").write_text(
                    hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n"
                )

            # The legacy pointer must remain a complete five-platform release;
            # the newer Linux pointer only needs the three Linux artifacts.
            for platform in ("linux_amd64", "linux_arm64", "linux_loong64", "windows_amd64", "windows_arm64"):
                add_archive(legacy, platform)
            for platform in ("linux_amd64", "linux_arm64", "linux_loong64"):
                add_archive(linux, platform)
            (root / "latest-version.txt").write_text("0.3.73\n")
            (root / "latest-linux-version.txt").write_text("0.3.73\n")
            (root / "latest-windows-version.txt").write_text("0.3.73\n")

            channel.promote(root, legacy, linux_version=linux)

            self.assertEqual((root / "latest-version.txt").read_text(), legacy + "\n")
            self.assertEqual((root / "latest-linux-version.txt").read_text(), linux + "\n")
            self.assertEqual((root / "latest-windows-version.txt").read_text(), legacy + "\n")

    def test_invalid_versions_and_unpinned_templates(self):
        for version in ("../escape", "1.2.3\n", "latest", "1" * 66):
            with self.assertRaises(ValueError):
                channel.promote(Path("/unused"), version)
        for path in ("packaging/bootstrap-install.sh", "packaging/windows/bootstrap-install.ps1"):
            script = (ROOT / "src/tools/secweaver-agent" / path).read_text()
            self.assertIn("latest-version.txt", script)
            self.assertNotIn("EMBEDDED_AGENT_VERSION", script)
            self.assertNotIn("EmbeddedAgentVersion", script)
