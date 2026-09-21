"""Regression tests for local Markdown link checks."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECK_DOCS_LINKS = REPO_ROOT / "src" / "scripts" / "check_docs_links.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_docs_links", CHECK_DOCS_LINKS)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CHECK_DOCS_LINKS}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestDocsLinks(unittest.TestCase):
    def setUp(self) -> None:
        self.checker = load_checker()

    def test_missing_local_link_is_reported(self) -> None:
        temp = REPO_ROOT / "tmp" / "docs-link-check.test.md"
        temp.parent.mkdir(parents=True, exist_ok=True)
        temp.write_text("[missing](missing-file.md)\n[external](https://example.com)\n", encoding="utf-8")
        try:
            issues = self.checker.check_file(temp)
            self.assertEqual(len(issues), 1)
            self.assertEqual(issues[0].target, "missing-file.md")
        finally:
            temp.unlink(missing_ok=True)

    def test_same_page_heading_and_explicit_anchors_are_checked(self) -> None:
        temp = REPO_ROOT / "tmp" / "docs-link-anchors.test.md"
        temp.parent.mkdir(parents=True, exist_ok=True)
        temp.write_text(
            "# 文档标题\n\n"
            "[中文标题](#文档标题)\n"
            "[显式锚点](#stable-section)\n"
            "[缺失锚点](#missing-section)\n\n"
            '<a id="stable-section"></a>\n\n'
            "## D1 ↔ D2\n",
            encoding="utf-8",
        )
        try:
            issues = self.checker.check_file(temp)
            self.assertEqual([(issue.target, issue.message) for issue in issues], [
                ("#missing-section", "local Markdown anchor does not exist")
            ])
            self.assertIn("d1--d2", self.checker.markdown_anchors(temp))
        finally:
            temp.unlink(missing_ok=True)

    def test_cross_file_and_duplicate_heading_anchors_are_checked(self) -> None:
        source = REPO_ROOT / "tmp" / "docs-link-source.test.md"
        target = REPO_ROOT / "tmp" / "docs-link-target.test.md"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "[first](docs-link-target.test.md#repeated)\n"
            "[second](docs-link-target.test.md#repeated-1)\n"
            "[missing](docs-link-target.test.md#repeated-2)\n",
            encoding="utf-8",
        )
        target.write_text("## Repeated\n\n```markdown\n## Repeated\n```\n\n## Repeated\n", encoding="utf-8")
        try:
            issues = self.checker.check_file(source)
            self.assertEqual(len(issues), 1)
            self.assertEqual(issues[0].target, "docs-link-target.test.md#repeated-2")
            self.assertEqual(issues[0].message, "local Markdown anchor does not exist")
        finally:
            source.unlink(missing_ok=True)
            target.unlink(missing_ok=True)

    def test_ignored_private_and_generated_dirs_are_not_scanned(self) -> None:
        files = self.checker.markdown_files(
            [
                "dataasset_my",
                "dataasset_es",
                "dataasset_sls_proxy",
                "docs_my",
                "book",
                "src/server",
                "src/es-operator",
                "src/portable",
                "src/tools/secweaver-agent/dist",
            ]
        )
        self.assertEqual(files, [])

    def test_tmp_ancestor_does_not_hide_extracted_archive_docs(self) -> None:
        original_root = self.checker.REPO_ROOT
        with tempfile.TemporaryDirectory(prefix="secweaver-docs-") as directory:
            archive_root = Path(directory)
            readme = archive_root / "README.md"
            readme.write_text("# Extracted archive\n", encoding="utf-8")
            self.checker.REPO_ROOT = archive_root
            try:
                self.assertEqual(self.checker.markdown_files([]), [readme])
            finally:
                self.checker.REPO_ROOT = original_root


if __name__ == "__main__":
    unittest.main()
