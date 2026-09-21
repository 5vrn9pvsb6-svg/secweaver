"""Archive-membership tests: the Attack Lab must stay in the public export.

These tests run a real ``git archive --worktree-attributes`` from HEAD and
assert both directions of the export policy:
  - executable Attack Lab sources (including README.md) are present;
  - captured internal reports (PDFs, internal analysis) are absent.

They fail on a case-insensitive checkout if the tracked filename casing and
the policy casing drift apart, which is exactly the class of regression that
silently drops or leaks files on Linux builds.

The history-free Community archive intentionally has no ``.git`` directory.
Its export boundary is checked by ``export_open_source.py`` before extraction,
so this source-repository-only test class is skipped in the extracted archive.
"""

from __future__ import annotations

import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_ARCHIVE_MEMBERS = {
    "attack_test/README.md",
    "attack_test/environmentDeployment/README.md",
    "attack_test/environmentDeployment/deploy-nginx-base.sh",
    "attack_test/environmentDeployment/teardown-lab.sh",
    "attack_test/environmentDeployment/lib/lab-safety.sh",
    "attack_test/environmentDeployment/case1-sqlInjectionAlertConfirm/attack.sh",
    "attack_test/environmentDeployment/case2-cmdInjectionC2/attack.sh",
    "attack_test/environmentDeployment/case3-dataExfilC2/attack.sh",
    "attack_test/environmentDeployment/case4-webPenetrateToSSH/attack.sh",
}

FORBIDDEN_ARCHIVE_MEMBERS = {
    "attack_test/environmentDeployment/Case1-SQLi-LFI-Alert-Confirmation.pdf",
    "attack_test/environmentDeployment/Case2-CmdI-MemoryWebshell.pdf",
    "attack_test/environmentDeployment/Case3-DataExfil-Fileless.pdf",
    "attack_test/environmentDeployment/Case4-Web-SSH-Lateral.pdf",
    "attack_test/environmentDeployment/SecWeaver-AI-Native-Security-Practice.pdf",
    "attack_test/environmentDeployment/attack-case-skill-analysis.md",
    "attack_test/environmentDeployment/attack-timeline-2026-07-05.md",
}


def git_archive_members() -> set[str]:
    with tempfile.NamedTemporaryFile(prefix="secweaver-archive-test-", suffix=".tar", delete=False) as handle:
        temporary = Path(handle.name)
    try:
        result = subprocess.run(
            [
                "git",
                "archive",
                "--worktree-attributes",
                "--format=tar",
                f"--output={temporary}",
                "HEAD",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(
                "git archive failed: " + result.stderr.decode("utf-8", errors="replace")
            )
        with tarfile.open(temporary, "r:") as archive:
            return {member.name.lstrip("./") for member in archive.getmembers() if member.isfile()}
    finally:
        temporary.unlink(missing_ok=True)


class TestAttackLabArchiveMembership(unittest.TestCase):
    """Guard the public archive boundary for the Attack Lab."""

    @classmethod
    def setUpClass(cls) -> None:
        """Skip source-only Git assertions in the history-free export tree."""
        super().setUpClass()
        if not (REPO_ROOT / ".git").exists():
            raise unittest.SkipTest("archive-membership checks require a Git source checkout")

    def test_attack_lab_readme_is_exported(self) -> None:
        """The exact-case attack_test/README.md must be an archive member."""
        members = git_archive_members()
        missing = REQUIRED_ARCHIVE_MEMBERS - members
        self.assertEqual(
            missing,
            set(),
            f"Attack Lab files missing from git archive export: {sorted(missing)}",
        )

    def test_internal_reports_are_not_exported(self) -> None:
        """Captured internal evidence must never appear in the archive."""
        members = git_archive_members()
        leaked = FORBIDDEN_ARCHIVE_MEMBERS & members
        self.assertEqual(
            leaked,
            set(),
            f"internal report files leaked into git archive export: {sorted(leaked)}",
        )

    def test_private_roots_are_not_exported(self) -> None:
        """Company-private roots stay excluded even with attack_test public."""
        members = git_archive_members()
        private_prefixes = (
            "dataasset_my/",
            "dataasset_es/",
            "dataasset_sls_proxy/",
            "docs_my/",
            "src/server/",
            "book/",
            "portable/",
            "src/es-operator/",
            "tmp/",
            "testdatasets/",
        )
        leaked = sorted(
            member for member in members if member.startswith(private_prefixes)
        )
        self.assertEqual(leaked, [], f"private roots leaked into git archive: {leaked[:10]}")


if __name__ == "__main__":
    unittest.main()
