"""Regression tests for the public Attack Lab safety boundary."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LAB_ROOT = REPO_ROOT / "attack_test" / "environmentDeployment"
SAFETY_LIBRARY = LAB_ROOT / "lib" / "lab-safety.sh"


class TestAttackLabSafety(unittest.TestCase):
    """Keep destructive entrypoints fail-closed and ownership-aware."""

    def run_bash(self, command: str, *arguments: Path, backup_dir: Path) -> subprocess.CompletedProcess[str]:
        """Run helper functions with an isolated state directory, never host state."""
        environment = os.environ.copy()
        environment["LAB_BACKUP_DIR"] = str(backup_dir)
        return subprocess.run(
            ["bash", "-c", command, "test", str(SAFETY_LIBRARY), *(str(path) for path in arguments)],
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_file_snapshots_restore_content_and_original_absence(self) -> None:
        """Teardown semantics restore files and remove only newly created files."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "backup"
            existing = root / "existing.conf"
            created = root / "created.conf"
            existing.write_text("original\n", encoding="utf-8")
            result = self.run_bash(
                'source "$1"; lab_backup_file "$2"; lab_backup_file "$3"; '
                'printf "changed\\n" > "$2"; printf "new\\n" > "$3"; lab_restore_all_files',
                existing,
                created,
                backup_dir=backup,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(existing.read_text(encoding="utf-8"), "original\n")
            self.assertFalse(created.exists())

    def test_waf_variants_consume_documented_cookie(self) -> None:
        """Every WAF entrypoint must honor the documented cookie variable."""
        scripts = sorted(LAB_ROOT.glob("case*/attack-domain-waf.sh"))
        self.assertEqual(len(scripts), 4)
        for script in scripts:
            with self.subTest(script=script):
                content = script.read_text(encoding="utf-8")
                self.assertIn('COOKIE="${WISID_COOKIE:-}"', content)

    def test_teardown_never_removes_whole_root_crontab(self) -> None:
        """Cleanup may remove marked web-user jobs but never root's cron file."""
        content = (LAB_ROOT / "teardown-lab.sh").read_text(encoding="utf-8")
        self.assertNotIn("/var/spool/cron/root", content)
        self.assertNotIn("crontab -r", content)
        self.assertIn("lab_remove_marked_cron", content)

    def test_teardown_consumes_active_ownership_state(self) -> None:
        """A repeated teardown must not reuse stale resource ownership markers."""
        content = (LAB_ROOT / "teardown-lab.sh").read_text(encoding="utf-8")
        self.assertIn('mv -- "${BACKUP_DIR}" "${ARCHIVED_BACKUP_DIR}"', content)
        self.assertIn(".restored-", content)

    def test_persistence_entries_have_cleanup_marker(self) -> None:
        """Every simulated cron beacon must be individually removable."""
        scripts = [
            LAB_ROOT / "case2-cmdInjectionC2" / "attack.sh",
            LAB_ROOT / "case2-cmdInjectionC2" / "attack-domain-waf.sh",
        ]
        for script in scripts:
            with self.subTest(script=script):
                self.assertIn("# secweaver-attack-lab", script.read_text(encoding="utf-8"))

    def test_shared_database_tables_have_matching_contracts(self) -> None:
        """Co-hosted Case 1 and Case 3 deployments must work in either order."""
        case1 = (LAB_ROOT / "case1-sqlInjectionAlertConfirm" / "deploy-92.sh").read_text(encoding="utf-8")
        case3 = (LAB_ROOT / "case3-dataExfilC2" / "deploy-92.sh").read_text(encoding="utf-8")

        def columns(script: str, table: str) -> list[str]:
            match = re.search(rf"CREATE TABLE IF NOT EXISTS {table} \((.*?)\n\);", script, re.DOTALL)
            self.assertIsNotNone(match, f"missing {table} table")
            assert match is not None
            return [line.strip().split()[0] for line in match.group(1).splitlines() if line.strip()]

        for table in ("users", "payment_cards"):
            with self.subTest(table=table):
                self.assertEqual(columns(case1, table), columns(case3, table))

    def test_waf_variants_use_the_documented_database(self) -> None:
        """WAF attack paths must not reference an undeployed legacy database."""
        for script in sorted(LAB_ROOT.glob("case*/attack-domain-waf.sh")):
            with self.subTest(script=script):
                content = script.read_text(encoding="utf-8")
                self.assertNotIn("shop_db", content)
                self.assertNotIn("shop_user", content)
                self.assertNotIn("ShopPass123", content)


if __name__ == "__main__":
    unittest.main()
