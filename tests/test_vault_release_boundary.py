"""Git and archive boundaries use disposable placeholder Vault files only."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tests.test_release_scan import load_release_scan


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("git"), "Git required for release-boundary fixtures")
class TestVaultReleaseBoundary(unittest.TestCase):
    def setUp(self) -> None:
        # Never use the developer's Git index or actual Vault. A nested fixture
        # reproduces ignore precedence and force-add behavior in isolation.
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.scan = load_release_scan()
        self.git("init", "--quiet")
        for path in (".gitignore", ".gitattributes", "dataasset/credentials/.gitignore"):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / path, target)

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Bound native Git calls to a temporary fixture, with no remote access."""
        return subprocess.run(
            ["git", *args], cwd=self.root, text=True, capture_output=True,
            check=True, timeout=10,
        )

    def exporter(self):
        """Load the real exporter while containing its scanner import."""
        spec = importlib.util.spec_from_file_location(
            "vault_boundary_exporter", ROOT / "src/scripts/export_open_source.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, release_scan=self.scan):
            spec.loader.exec_module(module)
        return module

    def write_fixture(self, path: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("SYNTHETIC_PLACEHOLDER\n", encoding="utf-8")

    def test_runtime_files_are_ignored_but_force_add_is_rejected(self) -> None:
        paths = [
            "dataasset/credentials/.sops.yaml",
            "dataasset/credentials/.age/key.txt",
            "dataasset/credentials/secrets/sls/query.enc.yaml",
            "selected-dataasset/credentials/.sops.yaml",
            "selected-dataasset/credentials/.age/init.lock",
            "selected-dataasset/credentials/secrets/sls/query.enc.yaml",
        ]
        for path in paths:
            self.write_fixture(path)
            with self.subTest(path=path):
                self.git("check-ignore", "--quiet", path)
        with patch.object(self.scan, "REPO_ROOT", self.root):
            self.assertTrue(set(paths).isdisjoint(self.scan.collect_candidate_paths()))
        self.git("add", "--force", "--", *paths)
        with patch.object(self.scan, "REPO_ROOT", self.root):
            candidates = self.scan.collect_candidate_paths(include_untracked=False)
            self.assertTrue(set(paths).issubset(candidates))
            self.assertEqual({issue.path for issue in self.scan.check_private_paths(candidates)}, set(paths))

    def test_native_archive_excludes_runtime_material_but_keeps_templates(self) -> None:
        private = [
            "dataasset/credentials/.sops.yaml",
            "dataasset/credentials/.age/key.txt",
            "dataasset/credentials/.age/init-test/probe.yaml",
            "dataasset/credentials/secrets/sls/query.enc.yaml",
            "selected-dataasset/credentials/.sops.yaml",
            "selected-dataasset/credentials/.age/key.txt",
            "selected-dataasset/credentials/secrets/sls/query.enc.yaml",
            ".age/key.txt",
        ]
        public = [
            "dataasset/credentials/.sops.yaml.example",
            "dataasset/credentials/examples/sls.yaml",
            "selected-dataasset/credentials/.sops.yaml.example",
        ]
        for path in private + public:
            self.write_fixture(path)
        self.git("add", "--force", "--", *private, *public, ".gitattributes")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.com",
                 "commit", "--quiet", "-m", "Synthetic archive fixture")
        archive = self.root / "source.tar.gz"
        self.git("archive", "--worktree-attributes", "--format=tar.gz",
                 f"--output={archive}", "HEAD")
        exporter = self.exporter()
        members = exporter.archive_members(archive)
        self.assertTrue(set(public).issubset(members))
        self.assertTrue(set(private).isdisjoint(members))
        self.assertEqual(exporter.private_members(members), [])
        self.assertEqual(exporter.private_members(private + public), sorted(private))

    def test_archive_member_normalization_preserves_hidden_directory_names(self) -> None:
        """Strip only the ./ prefix: lstrip('./') would hide a root .age leak."""
        archive = self.root / "malformed.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            handle.addfile(tarfile.TarInfo("./.age/key.txt"))
        exporter = self.exporter()
        members = exporter.archive_members(archive)
        self.assertEqual(members, [".age/key.txt"])
        self.assertEqual(exporter.private_members(members), members)


if __name__ == "__main__":
    unittest.main()
