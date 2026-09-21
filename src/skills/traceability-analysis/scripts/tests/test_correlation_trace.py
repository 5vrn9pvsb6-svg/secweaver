#!/usr/bin/env python3
"""Tests for traceability correlation contract (anchor-patterns + correlation-matrix)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from correlation_trace import (  # noqa: E402
    anchor_patterns_for_trace,
    build_stages_from_join_edges,
    compute_join_coverage,
    correlate_for_trace,
    merge_attack_stages,
    resolve_trace_contract,
)
from correlate import analyze, index_evidence, load_json  # noqa: E402
from risk_rules_bridge import load_trace_patterns  # noqa: E402

EXAMPLE = SCRIPTS / "input.example.json"
PATTERNS = load_trace_patterns()


class CorrelationTraceTests(unittest.TestCase):
    def test_anchor_patterns_s1_s3_merged(self) -> None:
        pids = anchor_patterns_for_trace(["S1", "S3"])
        self.assertIn("S1_external_ip_trace", pids)
        self.assertIn("S3_lateral_movement", pids)

    def test_anchor_pattern_s8_c2_detection(self) -> None:
        pids = anchor_patterns_for_trace(["S8"])
        self.assertEqual(pids, ["S8_c2_detection"])

    def test_resolve_trace_contract_fills_time_window(self) -> None:
        contract = resolve_trace_contract(
            {
                "scenarios": ["S1"],
                "params": {"alert_time": "2026-06-21T10:00:00+08:00", "attacker_ip": "203.0.113.10"},
            }
        )
        params = contract["params"]
        self.assertTrue(params.get("time_start"))
        self.assertTrue(params.get("time_end"))
        self.assertEqual(contract["correlation_anchor_pattern"], "S1_external_ip_trace")
        self.assertIn("correlation_contract", contract)
        metadata = contract["correlation_contract"]
        self.assertFalse(Path(metadata["anchor_patterns_path"]).is_absolute())
        self.assertFalse(Path(metadata["correlation_matrix_path"]).is_absolute())

    def test_correlate_for_trace_with_waf_web_exec(self) -> None:
        bundles = {
            "waf_alert": [
                {
                    "evidence_id": "waf-001",
                    "src_ip": "203.0.113.55",
                    "timestamp": "2026-06-22T09:08:05+08:00",
                }
            ],
            "web_access_log": [
                {
                    "evidence_id": "web-001",
                    "src_ip": "203.0.113.55",
                    "host": "web-01",
                    "target_ip": "10.0.1.5",
                    "timestamp": "2026-06-22T09:07:55+08:00",
                }
            ],
            "host_exec": [
                {
                    "evidence_id": "exec-001",
                    "host_ip": "10.0.1.5",
                    "host_name": "web-01",
                    "timestamp": "2026-06-22T09:10:00+08:00",
                    "command": "whoami",
                }
            ],
        }
        result = correlate_for_trace(
            bundles,
            scenarios=["S1"],
            params={"attacker_ip": "203.0.113.55", "alert_time": "2026-06-22T09:08:05+08:00"},
        )
        join_ids = {e["join_id"] for e in result["join_edges"]}
        self.assertIn("waf_to_web_access_by_ip", join_ids)
        self.assertIn("web_access_to_host_exec", join_ids)
        self.assertGreaterEqual(result["join_coverage"]["matched_join_count"], 2)

    def test_build_stages_from_join_edges(self) -> None:
        bundles = {
            "waf_alert": [{"evidence_id": "waf-001", "src_ip": "1.2.3.4", "host": "web-01", "timestamp": "2026-06-22T09:08:05+08:00"}],
            "web_access_log": [
                {
                    "evidence_id": "web-001",
                    "src_ip": "1.2.3.4",
                    "host": "192.168.101.24",
                    "http_host": "portal.example.com",
                    "target_ip": "10.0.1.5",
                    "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
                    "timestamp": "2026-06-22T09:07:55+08:00",
                }
            ],
            "host_exec": [
                {
                    "evidence_id": "exec-001",
                    "host_ip": "10.0.1.5",
                    "host_name": "web-01",
                    "timestamp": "2026-06-22T09:10:00+08:00",
                    "command": "id",
                }
            ],
        }
        correlation = correlate_for_trace(bundles, scenarios=["S1"], params={"attacker_ip": "1.2.3.4"})
        index, _ = index_evidence(bundles)
        patterns = PATTERNS
        initial, stages = build_stages_from_join_edges(correlation["join_edges"], index, patterns)
        self.assertIsNotNone(initial)
        self.assertEqual(initial["host"], "10.0.1.5")
        self.assertEqual(initial["url"], "http://portal.example.com/cmdi/diag.php?tool=ping&host=127.0.0.1;id")
        self.assertTrue(any(s["stage"] == "execution" for s in stages))

    def test_analyze_example_includes_join_coverage(self) -> None:
        payload = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        patterns = PATTERNS
        result = analyze(payload, patterns)
        self.assertFalse(result["blocked"])
        self.assertIn("join_coverage", result)
        self.assertIn("correlation_anchor_pattern", result)
        self.assertIn("correlation_contract", result)
        self.assertTrue(result["attack_chain"])
        for stage in result["attack_chain"]:
            self.assertTrue(stage.get("evidence_refs"))

    def test_s8_dns_join_retains_context_without_claiming_c2(self) -> None:
        payload = {
            "scenarios": ["S8"],
            "params": {
                "host": "192.0.2.91",
                "host_ip": "192.0.2.91",
                "time_start": "2026-07-01T10:00:00+08:00",
                "time_end": "2026-07-01T10:10:00+08:00",
            },
            "completeness_precheck": {
                "overall_verdict": "partial_traceable",
                "confidence": 0.8,
                "next_skill_blocked": False,
                "data_gaps": [],
            },
            "evidence_bundles": {
                "host_connect": [
                    {
                        "evidence_id": "conn-1",
                        "host": "192.0.2.91",
                        "host_ip": "192.0.2.91",
                        "timestamp": "2026-07-01T10:00:30+08:00",
                        "listener_pid": 234,
                        "dst_ip": "203.0.113.50",
                        "dst_port": 443,
                    }
                ],
                "dns_log": [
                    {
                        "evidence_id": "dns-1",
                        "client_ip": "192.0.2.91",
                        "timestamp": "2026-07-01T10:00:20+08:00",
                        "query": "c2.example.xyz",
                        "response": ["203.0.113.50"],
                        "rcode": "NOERROR",
                    }
                ],
            },
        }

        result = analyze(payload, PATTERNS)

        self.assertTrue(
            any(
                stage.get("stage") == "network_activity"
                and not stage.get("mitre_id")
                and stage.get("dns_query") == "c2.example.xyz"
                for stage in result["attack_chain"]
            )
        )
        self.assertTrue(any(step.get("evidence_refs") == ["dns-1"] for step in result["timeline"]))
        self.assertTrue(any(edge.get("protocol") == "DNS" for edge in result["lateral_movement_graph"]["edges"]))

    def test_default_showcase_does_not_claim_exfiltration(self) -> None:
        # Check the complete public newcomer path, not only overall verdict:
        # generic network tags can leak into timeline, summary and ATT&CK output.
        root = SCRIPTS.parents[3]
        payload = load_json(root / "examples/traceability/s1-web-shell-to-ssh-lateral.json")
        result = analyze(payload, PATTERNS)
        self.assertEqual(result["overall_verdict"], "confirmed_intrusion_chain")
        for field in ("timeline", "attack_chain"):
            self.assertFalse(any(x.get("stage") == "exfiltration" for x in result[field]))
        self.assertFalse(any(t.startswith("T1048") for t in result["mitre_attack"]["technique_ids"]))
        self.assertNotIn("无 WAF/WEB", result["initial_access"].get("inference_note", ""))
        self.assertEqual(result["initial_access"]["first_compromise_point_status"], "unresolved")
        self.assertTrue(any("dns-001" in x.get("evidence_refs", []) and x["stage"] == "network_activity" for x in result["timeline"]))

    def test_analyze_empty_dry_run_payload_without_initial_access(self) -> None:
        payload = {
            "scenarios": ["S1", "S3"],
            "params": {
                "target_ip": "192.0.2.91",
                "hosts": ["192.0.2.91"],
                "time_start": "2026-07-06T07:25:00+08:00",
                "time_end": "2026-07-06T07:27:34+08:00",
            },
            "completeness_precheck": {
                "overall_verdict": "partial_traceable",
                "confidence": 0.5,
                "next_skill_blocked": False,
                "data_gaps": ["completeness skipped"],
            },
            "evidence_bundles": {
                "web_access_log": [],
                "waf_alert": [],
            },
            "data_access": {
                "fetch_mode": "dry_run",
                "fetch_strategy": "trace_d1_bootstrap+asset_list",
                "trace_d1_bootstrap": {
                    "target_ip": "192.0.2.91",
                    "attacker_ips": [],
                    "web_access_event_count": 0,
                    "waf_event_count": 0,
                    "d1_asset_ids": ["asset-waf-prod-01", "asset-secweaver-gateway-access"],
                },
            },
        }

        result = analyze(payload, PATTERNS)

        self.assertEqual(result["overall_verdict"], "insufficient_evidence")
        self.assertIsNone(result["initial_access"])
        self.assertEqual(result["attack_chain"], [])
        self.assertEqual(result["host_high_risk_summary"], {})
        self.assertEqual(result["data_access"]["fetch_strategy"], "trace_d1_bootstrap+asset_list")

    def test_s5_no_match_marks_missing_asset_types_not_evaluated(self) -> None:
        payload = {
            "scenarios": ["S5"],
            "correlation_anchor_pattern": "S5_host_risk",
            "params": {
                "time_start": "2026-07-06T13:47:00+08:00",
                "time_end": "2026-07-06T13:50:34+08:00",
            },
            "completeness_precheck": {
                "overall_verdict": "partial_traceable",
                "confidence": 0.7,
                "next_skill_blocked": False,
                "data_gaps": ["completeness skipped"],
            },
            "evidence_bundles": {
                "host_exec": [
                    {
                        "evidence_id": "exec-1",
                        "host_ip": "192.0.2.91",
                        "host": "192.0.2.91",
                        "timestamp": "2026-07-06T13:49:24+08:00",
                        "command": "cat /etc/shadow",
                    }
                ]
            },
            "data_access": {
                "fetch_strategy": "asset_list",
                "executed_asset_ids": ["asset-secweaver-host-exec"],
            },
        }

        result = analyze(payload, PATTERNS)

        self.assertIn("data_access", result)
        self.assertTrue(
            any(gap.startswith("not_evaluated:d2_exec_connect_same_listener") for gap in result["data_gaps_impact"])
        )
        self.assertTrue(
            any(gap.startswith("not_evaluated:d2_exec_file_same_host") for gap in result["data_gaps_impact"])
        )

    def test_join_coverage_ratio(self) -> None:
        cov = compute_join_coverage(
            ["a", "b", "c"],
            [{"join_id": "a", "left_ref": "1", "right_ref": "2"}],
            ["no_match:b (test)"],
        )
        self.assertEqual(cov["matched_join_count"], 1)
        self.assertEqual(cov["per_join"]["a"], "matched")
        self.assertEqual(cov["per_join"]["b"], "no_match")

    def test_merge_attack_stages_prefers_matrix(self) -> None:
        matrix = [
            {
                "stage": "execution",
                "evidence_refs": ["exec-001"],
                "confidence": 0.9,
                "timestamp": "t1",
                "correlation_source": "matrix",
            }
        ]
        heur = [{"stage": "execution", "evidence_refs": ["exec-001"], "confidence": 0.85, "timestamp": "t1"}]
        merged = merge_attack_stages(matrix, heur)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["correlation_source"], "matrix")


if __name__ == "__main__":
    unittest.main()
