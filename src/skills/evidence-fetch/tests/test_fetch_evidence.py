#!/usr/bin/env python3
"""Tests for evidence-fetch skill."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
DATA_ACCESS = ROOT.parents[1] / "_shared" / "data-access"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(DATA_ACCESS))

from fetch_evidence import markdown_report, run_fetch  # noqa: E402
from fetch_summary import summarize_fetch  # noqa: E402
from skill_input import build_evidence_fetch_payload, resolve_payload_from_cli  # noqa: E402


class TestEvidenceFetch(unittest.TestCase):
    def test_plan_only_payload(self) -> None:
        payload = build_evidence_fetch_payload(
            {"attacker_ip": "203.0.113.10", "time_start": "2026-06-21T08:00:00+08:00", "time_end": "2026-06-21T20:00:00+08:00"},
            bundle_id="bundle-incident-trace-default",
            fetch_live=False,
        )
        self.assertEqual(payload.get("skill"), "evidence-fetch")
        self.assertIn("data_access", payload)
        self.assertEqual(payload["data_access"].get("fetch_mode"), "plan_only")

    def test_summarize_empty_bundles(self) -> None:
        summary = summarize_fetch({"evidence_bundles": {}, "data_access": {"fetch_mode": "plan_only"}})
        self.assertEqual(summary["total_events"], 0)

    def test_run_fetch_idempotent(self) -> None:
        payload = {
            "evidence_bundles": {"host_exec": [{"evidence_id": "e1"}]},
            "data_access": {"fetch_mode": "live", "fetch_strategy": "asset_list"},
        }
        out = run_fetch(payload)
        self.assertEqual(len(out["evidence_bundles"]["host_exec"]), 1)
        self.assertIn("fetch_summary", out)

    def test_run_fetch_idempotent_without_events(self) -> None:
        payload = {
            "evidence_bundles": {},
            "data_access": {
                "fetch_mode": "live",
                "fetch_strategy": "s4_bootstrap",
                "declared_asset_ids": ["asset-waf-prod-01", "asset-secweaver-host-connect"],
                "fetch_asset_ids": ["asset-waf-prod-01"],
                "executed_asset_ids": ["asset-waf-prod-01"],
                "skipped_assets": [
                    {
                        "asset_id": "asset-secweaver-host-connect",
                        "reason": "not_selected_by_s4_bootstrap",
                    }
                ],
            },
        }
        out = run_fetch(payload)
        self.assertEqual(out["fetch_summary"]["total_events"], 0)
        self.assertEqual(out["fetch_summary"]["skipped_asset_count"], 1)

    def test_offline_fixture_replay_preserves_evidence_and_original_counts(self) -> None:
        fixture = json.loads(
            (ROOT.parents[2] / "examples/prompt-risk-analysis/fetch-exec-syslog-mini.json")
            .read_text(encoding="utf-8")
        )
        with patch("fetch_evidence.build_evidence_fetch_payload", side_effect=AssertionError("unexpected live fetch")):
            result = run_fetch(fixture)
        self.assertEqual(result["fetch_summary"]["total_events"], 8)
        self.assertEqual(len(result["evidence_bundles"]["host_exec"]), 6)

    def test_explicit_fetch_replans_saved_offline_evidence(self) -> None:
        payload = {
            "bundle_id": "bundle-host-risk-default",
            "params": {"host": "192.0.2.91"},
            "evidence_bundles": {"host_exec": [{"evidence_id": "old"}]},
            "fetch_summary": {"total_events": 1},
            "data_access": {"fetch_mode": "offline"},
            "_explicit_fetch": True,
        }
        fresh = {"evidence_bundles": {}, "data_access": {"fetch_mode": "live"}}
        with patch("fetch_evidence.build_evidence_fetch_payload", return_value=fresh) as builder:
            result = run_fetch(payload)
        builder.assert_called_once()
        self.assertEqual(result["fetch_summary"]["total_events"], 0)

    def test_markdown_report(self) -> None:
        md = markdown_report(
            {
                "investigation_intent": "test",
                "bundle_id": "bundle-host-risk-default",
                "fetch_summary": {"total_events": 3, "by_asset_type": {"host_exec": 3}, "fetch_mode": "live"},
                "evidence_bundles": {},
            }
        )
        self.assertIn("证据取数报告", md)
        self.assertIn("host_exec", md)

    def test_resolve_cli_asset_id_without_from_bundle(self) -> None:
        from argparse import Namespace

        args = Namespace(
            from_bundle=False,
            bundle=None,
            params='{"hosts":["192.0.2.91"],"time_start":"2026-07-01T17:00:00+08:00","time_end":"2026-07-01T18:00:00+08:00"}',
            params_file=None,
            intent=None,
            plan_only=True,
            dry_run=False,
            include_completeness=False,
            anchor_pattern=None,
            asset_ids=["asset-secweaver-host-exec"],
        )
        payload = resolve_payload_from_cli(args, "fetch", build_evidence_fetch_payload)
        self.assertIsNotNone(payload)
        self.assertEqual(payload.get("asset_ids"), ["asset-secweaver-host-exec"])
        self.assertEqual(payload["data_access"].get("fetch_mode"), "plan_only")


if __name__ == "__main__":
    unittest.main()
