"""Keep required prompt-risk-analysis workflow steps aligned across locales."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = REPO_ROOT / "src" / "skills" / "prompt-risk-analysis"


def numbered_steps(path: Path, heading: str) -> list[str]:
    text = path.read_text(encoding="utf-8")
    section = text.split(heading, 1)[1].split("\n## ", 1)[0]
    return re.findall(r"^\d+\.\s+(.+)$", section, flags=re.MULTILINE)


class TestPromptRiskAnalysisSkillParity(unittest.TestCase):
    def test_required_workflow_steps_stay_aligned(self) -> None:
        english_path = SKILL_DIR / "SKILL.md"
        chinese_path = SKILL_DIR / "SKILL.zh-CN.md"
        english = numbered_steps(english_path, "## Agent workflow")
        chinese = numbered_steps(chinese_path, "## Agent 工作流")

        self.assertEqual(len(english), 7)
        self.assertEqual(len(chinese), 7)

        required_markers = (
            ("evidence-fetch",),
            ("PROMPT",),
            ("analysis-contract", "correlation-cheatsheet"),
            ("evidence_bundles", "policy-lite"),
            ("fetch_summary",),
            ("chain_coverage", "join_refs", "fetch_next"),
            ("examples/prompt-risk-analysis",),
        )
        for index, markers in enumerate(required_markers):
            for marker in markers:
                self.assertIn(marker, english[index], f"English workflow step {index + 1}")
                self.assertIn(marker, chinese[index], f"Chinese workflow step {index + 1}")

        self.assertIn("Report `fetch_summary` first", english[4])
        self.assertIn("先输出 `fetch_summary`", chinese[4])

    def test_english_skill_is_declared_as_normative_source(self) -> None:
        english = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        chinese = (SKILL_DIR / "SKILL.zh-CN.md").read_text(encoding="utf-8")

        self.assertIn("normative workflow source", english)
        self.assertIn("工作流规范源", chinese)

    def test_analysis_contract_key_terms_stay_aligned(self) -> None:
        english = (SKILL_DIR / "analysis-contract.md").read_text(encoding="utf-8")
        chinese = (SKILL_DIR / "analysis-contract.zh-CN.md").read_text(encoding="utf-8")
        markers = (
            "S4_alert_confirmation",
            "attacker_ip",
            "time_start",
            "attack_status",
            "confirmed_success",
            "raw_count",
            "retained_count",
            "waf_coverage",
            "confirmed_bypass_count",
            "evidence_id",
            "redacted: true",
        )
        for marker in markers:
            self.assertIn(marker, english)
            self.assertIn(marker, chinese)


if __name__ == "__main__":
    unittest.main()
