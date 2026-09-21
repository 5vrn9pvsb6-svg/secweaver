"""Tests for coverage hint matching (方案 B)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from check import (  # noqa: E402
    assess,
    assets_by_type,
    can_confirm_breach,
    correlation_key_score,
    evaluate_requirement,
    infer_scenarios,
    load_scenarios,
    match_coverage_hint,
    normalize_asset_coverage,
)


def asset(*, zones=None, hosts=None, flat=None):
    if flat is not None:
        return {"coverage": flat}
    return {"coverage_detail": {"zones": zones or [], "apps": [], "hosts": hosts or []}}


class TestNormalizeCoverage(unittest.TestCase):
    def test_flat_list_hosts(self) -> None:
        cov = normalize_asset_coverage({"coverage": ["web-01", "web_zone"]})
        self.assertIn("web-01", cov["hosts"])
        self.assertIn("web_zone", cov["zones"])

    def test_structured(self) -> None:
        cov = normalize_asset_coverage(
            {"coverage_detail": {"zones": ["internal"], "hosts": ["db-01"], "apps": []}}
        )
        self.assertEqual(cov["zones"], {"internal"})
        self.assertEqual(cov["hosts"], {"db-01"})


class TestMatchCoverageHint(unittest.TestCase):
    def test_web_zone_full(self) -> None:
        self.assertEqual(
            match_coverage_hint("web_zone", asset(zones=["web_zone"]), {}),
            "full",
        )

    def test_web_hosts_only_zone_partial(self) -> None:
        self.assertEqual(
            match_coverage_hint("web_hosts", asset(zones=["web_zone"]), {}),
            "partial",
        )

    def test_web_hosts_zone_and_host_full(self) -> None:
        a = asset(zones=["web_zone"], hosts=["web-01"])
        self.assertEqual(
            match_coverage_hint("web_hosts", a, {"hosts": ["web-01"]}),
            "full",
        )

    def test_web_hosts_flat_host_list(self) -> None:
        self.assertEqual(
            match_coverage_hint("web_hosts", asset(flat=["web-01"]), {"hosts": ["web-01"]}),
            "full",
        )

    def test_web_zone_host_only_is_partial_not_none(self) -> None:
        self.assertEqual(
            match_coverage_hint("web_zone", asset(hosts=["192.0.2.10"]), {}),
            "partial",
        )

    def test_web_zone_token_remains_full_when_hosts_are_also_listed(self) -> None:
        self.assertEqual(
            match_coverage_hint(
                "web_zone",
                asset(zones=["web_zone"], hosts=["192.0.2.10"]),
                {},
            ),
            "full",
        )

    def test_internal_ssh(self) -> None:
        self.assertEqual(
            match_coverage_hint("internal_ssh", asset(zones=["internal"]), {}),
            "full",
        )

    def test_internal_ssh_hosts_cover_investigation(self) -> None:
        self.assertEqual(
            match_coverage_hint("internal_ssh", asset(hosts=["192.0.2.91"]), {"hosts": ["192.0.2.91"]}),
            "full",
        )

    def test_host_exec_style_coverage_satisfies_web_and_jump_hosts(self) -> None:
        monitored = asset(
            zones=["web_hosts", "internal"],
            hosts=["10.0.1.5", "192.0.2.91", "192.0.2.92"],
        )
        self.assertEqual(match_coverage_hint("web_hosts", monitored, {}), "full")
        self.assertEqual(match_coverage_hint("jump_hosts", monitored, {}), "full")
        self.assertEqual(
            match_coverage_hint("target_hosts", monitored, {"hosts": ["192.0.2.92"]}),
            "full",
        )

    def test_explicit_target_hosts_use_set_coverage_not_zone_claims(self) -> None:
        # This models the public SaaS asset after onboarding, including the
        # runtime's coverage_detail adapter and a legacy flat host list.
        for coverage in ({"coverage": {"hosts": ["192.0.2.91"]}},
                         asset(hosts=["192.0.2.91"]),
                         asset(flat=["192.0.2.91"]),
                         asset(zones=["internal", "target_hosts"], hosts=["192.0.2.91"])):
            for targets, expected in ((["192.0.2.91"], "full"),
                                      (["192.0.2.91", "192.0.2.92"], "partial"),
                                      (["192.0.2.92"], "none")):
                with self.subTest(coverage=coverage, targets=targets):
                    self.assertEqual(match_coverage_hint("target_hosts", coverage, {"hosts": targets}), expected)

    def test_partial_internal(self) -> None:
        self.assertEqual(
            match_coverage_hint("internal_ssh", asset(zones=["partial_internal"]), {}),
            "partial",
        )

    def test_dmz_to_internal_partial(self) -> None:
        self.assertEqual(
            match_coverage_hint("dmz_to_internal", asset(zones=["dmz"]), {}),
            "partial",
        )

    def test_dmz_to_internal_full(self) -> None:
        self.assertEqual(
            match_coverage_hint("dmz_to_internal", asset(zones=["dmz_to_internal"]), {}),
            "full",
        )

    def test_mismatch_internal_for_web(self) -> None:
        self.assertEqual(
            match_coverage_hint("web_hosts", asset(zones=["internal"]), {}),
            "none",
        )

    def test_any_nonempty(self) -> None:
        self.assertEqual(match_coverage_hint("any", asset(zones=["dmz"]), {}), "full")

    def test_any_empty(self) -> None:
        self.assertEqual(match_coverage_hint("any", asset(zones=[]), {}), "none")

    def test_full_hint(self) -> None:
        self.assertEqual(match_coverage_hint("full", asset(zones=["full"]), {}), "full")
        self.assertEqual(match_coverage_hint("full", asset(zones=["web_zone"]), {}), "none")


def syslog_risk_asset():
    return {
        "asset_id": "asset-secweaver-sys-risk-alert",
        "type": "syslog_risk_alert",
        "covers_asset_types": ["ssh_auth"],
        "status": "registered",
        "fields": ["timestamp", "host_name", "src_ip", "user", "event_type", "__source__"],
        "field_aliases": {"__source__": "host_ip"},
        "coverage": ["internal"],
        "retention_days": 30,
        "correlation_keys": ["src_ip", "host", "timestamp", "user"],
    }


class TestCoveredAssetTypes(unittest.TestCase):
    def test_syslog_risk_indexes_as_ssh_auth_cover(self) -> None:
        by_type = assets_by_type([syslog_risk_asset()])
        self.assertIn("syslog_risk_alert", by_type)
        self.assertIn("ssh_auth", by_type)
        self.assertEqual(by_type["ssh_auth"][0]["asset_id"], "asset-secweaver-sys-risk-alert")

    def test_syslog_risk_satisfies_ssh_auth_requirement(self) -> None:
        req = {
            "id": "S3-P0-ssh",
            "priority": "P0",
            "asset_types": ["syslog_risk_alert", "ssh_auth"],
            "match": "any",
            "required_fields": {
                "syslog_risk_alert": ["host_ip", "src_ip", "user", "event_type", "timestamp"],
                "ssh_auth": ["host", "src_ip", "user", "result", "timestamp"],
            },
            "coverage": "internal_ssh",
            "label": "SSH/syslog 认证日志",
        }
        result = evaluate_requirement(req, assets_by_type([syslog_risk_asset()]), {})
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["asset_type"], "syslog_risk_alert")

    def test_syslog_risk_contributes_correlation_keys(self) -> None:
        score = correlation_key_score(assets_by_type([syslog_risk_asset()]), {})
        self.assertEqual(score, 1.0)


class TestScenarioCapabilities(unittest.TestCase):
    def test_s5_host_data_does_not_claim_breach_confirmation(self) -> None:
        by_type = {"host_exec": [{"asset_id": "host-exec"}]}
        self.assertFalse(can_confirm_breach(["S5"], by_type, "partial_traceable"))

    def test_s4_requires_both_d1_and_d2_for_breach_confirmation(self) -> None:
        d1_only = {"waf_alert": [{"asset_id": "waf"}]}
        self.assertFalse(can_confirm_breach(["S4"], d1_only, "full_traceable"))

        d1_d2 = {
            "waf_alert": [{"asset_id": "waf"}],
            "host_exec": [{"asset_id": "host-exec"}],
        }
        self.assertTrue(can_confirm_breach(["S4"], d1_d2, "partial_traceable"))

    def test_s8_c2_data_does_not_claim_breach_confirmation(self) -> None:
        by_type = {"host_connect": [{"asset_id": "host-connect"}]}
        self.assertFalse(can_confirm_breach(["S8"], by_type, "partial_traceable"))

    def test_dns_does_not_replace_network_session_sources(self) -> None:
        catalog = load_scenarios(SCRIPTS.parent / "scenarios.json")
        registered = [
            {
                "asset_id": "host-connect",
                "type": "host_connect",
                "status": "registered",
                "fields": ["host", "dst_ip", "dst_port", "timestamp"],
                "coverage": ["any"],
                "retention_days": 30,
                "correlation_keys": ["host", "timestamp"],
            },
            {
                "asset_id": "host-exec",
                "type": "host_exec",
                "status": "registered",
                "fields": ["host", "command", "timestamp"],
                "coverage": ["any"],
                "retention_days": 30,
                "correlation_keys": ["host", "timestamp"],
            },
            {
                "asset_id": "dns",
                "type": "dns_log",
                "status": "registered",
                "fields": ["client_ip", "query", "timestamp"],
                "coverage": ["any"],
                "retention_days": 30,
                "correlation_keys": ["host", "timestamp"],
            },
        ]
        result = assess(
            {
                "scenarios": ["S8"],
                "params": {},
                "registered_assets": registered,
            },
            catalog,
        )
        self.assertEqual(result["overall_verdict"], "partial_traceable")
        self.assertTrue(any(note["type"] == "dns_boundary" for note in result["capability_notes"]))
        self.assertTrue(
            any(note["type"] == "partial_traceability_boundary" for note in result["capability_notes"])
        )


class TestScenarioInference(unittest.TestCase):
    def test_c2_keywords_infer_s8(self) -> None:
        catalog = load_scenarios(SCRIPTS.parent / "scenarios.json")
        self.assertEqual(infer_scenarios("检测这台主机是否存在 C2 beacon 回连", catalog), ["S8"])


class TestScenarioBundles(unittest.TestCase):
    def test_s7_default_bundle_contains_required_host_evidence(self) -> None:
        repo_root = Path(__file__).resolve().parents[5]
        bundle_path = repo_root / "dataasset" / "bundles" / "bundle-data-exfiltration-default.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))

        self.assertIn("asset-secweaver-host-file-op", bundle["asset_ids"])
        self.assertIn("asset-secweaver-host-exec", bundle["asset_ids"])

    def test_s8_default_bundle_contains_required_c2_evidence(self) -> None:
        repo_root = Path(__file__).resolve().parents[5]
        bundle_path = repo_root / "dataasset" / "bundles" / "bundle-c2-detection-default.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))

        self.assertEqual(bundle["status"], "active")
        self.assertEqual(bundle["investigation_scenarios"], ["S8"])
        self.assertIn("asset-secweaver-host-connect", bundle["asset_ids"])
        self.assertIn("asset-secweaver-host-exec", bundle["asset_ids"])


if __name__ == "__main__":
    unittest.main()
