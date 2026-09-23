"""Regression tests for the open-source release hygiene scanner."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_SCAN = REPO_ROOT / "src" / "scripts" / "release_scan.py"


def load_release_scan():
    spec = importlib.util.spec_from_file_location("release_scan", RELEASE_SCAN)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {RELEASE_SCAN}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestReleaseScan(unittest.TestCase):
    def setUp(self) -> None:
        self.release_scan = load_release_scan()

    def test_published_reports_reject_home_paths_but_accept_relative_paths(self) -> None:
        for value in ("/Users/" + "test/project/rules.json", "/home/" + "test/project/rules.json", "C:" + "\\\\Users\\\\test\\\\rules.json"):
            with self.subTest(value=value), patch.object(self.release_scan, "read_text", return_value=value):
                self.assertTrue(self.release_scan.check_private_markers(["examples/reports/demo.json"]))
        with patch.object(self.release_scan, "read_text", return_value="src/skills/rules.json"):
            self.assertEqual(self.release_scan.check_private_markers(["examples/reports/demo.json"]), [])

    def test_public_text_rejects_local_workspaces_but_allows_operational_home_paths(self) -> None:
        """Block contributor checkout paths without breaking host path examples."""
        path = "src/tools/secweaver-agent/verify.sh"
        # Assemble blocked paths so the scanner does not flag its own fixture source.
        for value in ("/Users/" + "test/Desktop/secweaver", "/home/" + "test/work/secweaver"):
            with self.subTest(value=value), patch.object(self.release_scan, "read_text", return_value=value):
                issues = self.release_scan.check_private_markers([path])
                self.assertEqual(len(issues), 1)
                self.assertIn("developer workspace", issues[0].message)
        with patch.object(self.release_scan, "read_text", return_value="/home/www/.ssh/authorized_keys"):
            self.assertEqual(self.release_scan.check_private_markers(["docs_user/host.md"]), [])

    def test_private_markers_are_detected_in_any_text_path(self) -> None:
        issues = self.release_scan.check_private_markers(["dataasset/connectors/conn-sls-waf-prod.json"])
        self.assertEqual(issues, [])
        temp = REPO_ROOT / "tmp" / "release-scan-private-marker.test"
        temp.parent.mkdir(parents=True, exist_ok=True)
        # Exercise a retained private marker, not public onboarding resources.
        temp.write_text("tenant_id=" + "28", encoding="utf-8")
        try:
            issues = self.release_scan.check_private_markers([temp.relative_to(REPO_ROOT).as_posix()])
            self.assertGreaterEqual(len(issues), 1)
            self.assertIn("private marker", issues[0].message)
        finally:
            temp.unlink(missing_ok=True)

    def test_public_resource_names_do_not_bypass_other_content_checks(self) -> None:
        """Public names may coexist with secrets; never exempt their whole file."""
        resource = json.dumps({"project": "wis-log", "logstore": "gateway_plugin_log"})
        for path in ("docs_user/onboarding.md", "dataasset/connectors/public.json", "tests/example.py"):
            with self.subTest(path=path), patch.object(self.release_scan, "read_text", return_value=resource):
                self.assertEqual(self.release_scan.check_private_markers([path]), [])
                self.assertEqual(self.release_scan.check_dataasset_private_content([path]), [])
                self.assertEqual(self.release_scan.check_secret_patterns([path]), [])
        path = "docs_user/onboarding.md"
        with patch.object(self.release_scan, "read_text", return_value=resource + " tenant_id=" + "28"):
            self.assertEqual(len(self.release_scan.check_private_markers([path])), 1)
        # Assemble a nonfunctional key-shaped fixture without publishing a key literal.
        with patch.object(self.release_scan, "read_text", return_value=resource + " AKIA" + "A" * 16):
            self.assertEqual(len(self.release_scan.check_secret_patterns([path])), 1)

    def test_untracked_files_are_candidates_by_default(self) -> None:
        # Use a suffix that is not intentionally ignored as a compiled Go test
        # artifact; this assertion is about publishable untracked source files.
        temp = REPO_ROOT / "release-scan-untracked.txt"
        temp.write_text("temporary", encoding="utf-8")
        try:
            paths = self.release_scan.collect_candidate_paths(include_untracked=True)
            self.assertIn(temp.relative_to(REPO_ROOT).as_posix(), paths)
        finally:
            temp.unlink(missing_ok=True)

    def test_private_paths_block_zip_when_not_ignored(self) -> None:
        issues = self.release_scan.check_private_paths(["local-export.zip"])
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, "error")

    def test_required_legal_and_sbom_files_are_enforced(self) -> None:
        issues = self.release_scan.check_required_public_files(["LICENSE"])
        self.assertEqual(
            {issue.path for issue in issues},
            {
                "THIRD_PARTY_NOTICES.md",
                "attack_test/README.md",
                "sbom/secweaver-source.cdx.json",
            },
        )

    def test_community_release_versions_are_consistent(self) -> None:
        self.assertEqual(self.release_scan.check_community_version_consistency(), [])

    def test_community_release_version_drift_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "sbom").mkdir()
            (root / "CHANGELOG.md").write_text("## [2.0.0] - 2026-09-01\n", encoding="utf-8")
            (root / "pyproject.toml").write_text('version = "1.0.0"\n', encoding="utf-8")
            (root / "src/secweaver.py").write_text(
                'parser.add_argument("--version", version="SecWeaver CLI 2.0.0")\n',
                encoding="utf-8",
            )
            (root / "sbom/secweaver-source.cdx.json").write_text(
                json.dumps({"metadata": {"component": {"version": "2.0.0"}}}),
                encoding="utf-8",
            )

            issues = self.release_scan.check_community_version_consistency(root)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].path, "pyproject.toml")
        self.assertIn("does not match", issues[0].message)

    def test_component_release_heading_does_not_replace_community_version(self) -> None:
        """An independently versioned Operator entry must not become the Community identity."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "sbom").mkdir()
            (root / "CHANGELOG.md").write_text(
                "## [ES Operator 9.0.0] - 2026-09-04\n\n## [2.0.0] - 2026-09-01\n",
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text('version = "2.0.0"\n', encoding="utf-8")
            (root / "src/secweaver.py").write_text(
                'parser.add_argument("--version", version="SecWeaver CLI 2.0.0")\n',
                encoding="utf-8",
            )
            (root / "sbom/secweaver-source.cdx.json").write_text(
                json.dumps({"metadata": {"component": {"version": "2.0.0"}}}),
                encoding="utf-8",
            )

            issues = self.release_scan.check_community_version_consistency(root)

        self.assertEqual(issues, [])

    def test_company_private_roots_are_blocked(self) -> None:
        private_paths = [
            "dataasset_my/assets/private.json",
            "dataasset_es/connectors/private.json",
            "dataasset_sls_proxy/connectors/private.json",
            "docs_my/internal.md",
            "src/server/sls_proxy/main.py",
            "book/internal.md",
            "portable/install.sh",
            "src/es-operator/cmd/secweaver-portable/main.go",
        ]
        issues = self.release_scan.check_private_paths(private_paths)
        self.assertEqual({issue.path for issue in issues}, set(private_paths))
        self.assertTrue(all(issue.severity == "error" for issue in issues))

    def test_company_private_roots_are_export_excluded(self) -> None:
        roots = {
            "dataasset_my",
            "dataasset_es",
            "dataasset_sls_proxy",
            "docs_my",
            "src/server",
            "book",
            "portable",
            "src/es-operator",
        }
        attributes = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
        for root in roots:
            self.assertIn(f"/{root}/ export-ignore", attributes)
            self.assertIn(f"/{root}/** export-ignore", attributes)

    def test_community_agent_is_exported(self) -> None:
        agent_path = "src/tools/secweaver-agent/main.go"
        self.assertEqual(self.release_scan.check_private_paths([agent_path]), [])
        attributes = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertNotIn("/src/tools/secweaver-agent/ export-ignore", attributes)

    def test_attack_lab_is_exported_but_internal_reports_are_not(self) -> None:
        """Keep executable lab sources public while excluding captured internal evidence."""
        public_path = "attack_test/environmentDeployment/case1-sqlInjectionAlertConfirm/attack.sh"
        self.assertEqual(self.release_scan.check_private_paths([public_path]), [])
        attributes = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertNotIn("/attack_test/ export-ignore", attributes)
        self.assertNotIn("/attack_test/** export-ignore", attributes)
        self.assertIn("/attack_test/environmentDeployment/*.pdf export-ignore", attributes)
        self.assertIn(
            "/attack_test/environmentDeployment/attack-case-skill-analysis.md export-ignore",
            attributes,
        )

    def test_public_dataasset_rejects_rfc1918_addresses(self) -> None:
        temp = REPO_ROOT / "dataasset" / "release-scan-private-ip.test"
        temp.write_text(json.dumps({"host": "10.23.4.5", "cidr": "172.20.0.0/16"}), encoding="utf-8")
        try:
            issues = self.release_scan.check_dataasset_private_content(
                [temp.relative_to(REPO_ROOT).as_posix()]
            )
            self.assertEqual(len(issues), 2)
            self.assertTrue(all("RFC1918" in issue.message for issue in issues))
        finally:
            temp.unlink(missing_ok=True)

    def test_public_dataasset_allows_documentation_addresses(self) -> None:
        temp = REPO_ROOT / "dataasset" / "release-scan-documentation-ip.test"
        temp.write_text(
            json.dumps({"hosts": ["192.0.2.5", "198.51.100.10", "203.0.113.24"]}),
            encoding="utf-8",
        )
        try:
            issues = self.release_scan.check_dataasset_private_content(
                [temp.relative_to(REPO_ROOT).as_posix()]
            )
            self.assertEqual(issues, [])
        finally:
            temp.unlink(missing_ok=True)

    def test_known_internal_acceptance_range_is_blocked_in_all_public_text(self) -> None:
        """A former live acceptance address must fail outside DataAsset too."""
        private_address = "10.0." + "6.91"
        for path in ("docs_user/example.md", "examples/demo.json", "src/skills/example/SKILL.md"):
            with self.subTest(path=path), patch.object(
                self.release_scan,
                "read_text",
                return_value=f"host={private_address}",
            ):
                issues = self.release_scan.check_known_internal_acceptance_networks([path])
                self.assertEqual(len(issues), 1)
                self.assertIn("known internal acceptance address", issues[0].message)

    def test_known_internal_acceptance_scan_allows_documentation_ranges(self) -> None:
        with patch.object(
            self.release_scan,
            "read_text",
            return_value="hosts=192.0.2.91,192.0.2.92",
        ):
            self.assertEqual(
                self.release_scan.check_known_internal_acceptance_networks(["docs_user/example.md"]),
                [],
            )

    def test_ci_and_export_rescan_after_demo_generation(self) -> None:
        """Generated public reports must be scanned, not only their inputs."""
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertRegex(makefile, r"(?m)^ci:.*\bdemo\s+ci-final-release-scan$")

        exporter = (REPO_ROOT / "src/scripts/export_open_source.py").read_text(encoding="utf-8")
        demo_index = exporter.index('[python, "src/secweaver.py", "demo", "all"')
        final_scan_index = exporter.rindex('[python, "src/scripts/release_scan.py"]')
        self.assertGreater(final_scan_index, demo_index)

    def test_public_dataasset_rejects_environment_markers(self) -> None:
        temp = REPO_ROOT / "dataasset" / "release-scan-private-name.test"
        temp.write_text(json.dumps({"project": "tiger" + "sec-uni-log"}), encoding="utf-8")
        try:
            issues = self.release_scan.check_dataasset_private_content(
                [temp.relative_to(REPO_ROOT).as_posix()]
            )
            self.assertEqual(len(issues), 1)
            self.assertIn("private environment marker", issues[0].message)
        finally:
            temp.unlink(missing_ok=True)

    def test_public_dataasset_accepts_only_exact_public_logstore_names(self) -> None:
        approved = json.dumps(
            {
                "logstores": [
                    "tigersec-host-exec",
                    "tigersec-sys-messages",
                    "tigersec-tsin-access",
                ]
            }
        )
        path = "dataasset/onboarding/examples/sls-proxy.json"
        with patch.object(self.release_scan, "read_text", return_value=approved):
            self.assertEqual(self.release_scan.check_dataasset_private_content([path]), [])

        for value in ("tigersec-uni-log", "prefix-tigersec-host-exec", "tigersec-tsin-access-backup"):
            with self.subTest(value=value), patch.object(
                self.release_scan,
                "read_text",
                return_value=json.dumps({"logstore": value}),
            ):
                issues = self.release_scan.check_dataasset_private_content([path])
                self.assertGreaterEqual(len(issues), 1)
                self.assertIn("private environment marker", issues[0].message)

    def test_public_dataasset_rejects_age_recipient_fingerprint(self) -> None:
        temp = REPO_ROOT / "dataasset" / "release-scan-age-recipient.test"
        recipient = "age1" + ("a" * 56)
        temp.write_text(json.dumps({"age": recipient}), encoding="utf-8")
        try:
            issues = self.release_scan.check_dataasset_private_content(
                [temp.relative_to(REPO_ROOT).as_posix()]
            )
            self.assertEqual(len(issues), 1)
            self.assertIn("private environment marker", issues[0].message)
        finally:
            temp.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
