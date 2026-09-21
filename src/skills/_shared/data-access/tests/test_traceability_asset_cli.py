"""Tests for traceability correlate.py --asset-id CLI support."""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

DATA_ACCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DATA_ACCESS))

from skill_input import (  # noqa: E402
    _coalesce_trace_tasks,
    add_bundle_arguments,
    build_evidence_fetch_payload,
    build_traceability_payload,
    fetch_scenario_evidence,
    resolve_payload_from_cli,
)
from trace_d1_bootstrap import infer_d1_targets_from_host_exec  # noqa: E402
from s4_gateway_bootstrap import resolve_s4_gateway_asset_id  # noqa: E402
from registry import host_registry_to_registered_asset  # noqa: E402


def _has_compat_asset(asset_ids: list[str] | set[str], *candidates: str) -> bool:
    """Accept public compatibility ids and private-root TigerSec ids in the same test."""
    return bool(set(asset_ids).intersection(candidates))


class TraceabilityAssetCliTests(unittest.TestCase):
    @patch("trace_d1_bootstrap.fetch_trace_d1_bootstrap")
    @patch("fetch.fetch_bundle_evidence")
    def test_host_risk_queries_all_declared_assets_without_d1_dependency(self, fetch_bundle, bootstrap):
        # The bundle must still be queried when D1 is empty, fails, or is irrelevant.
        fetch_bundle.return_value = {"host_exec": [{"evidence_id": "exec-regression"}]}
        evidence, meta = fetch_scenario_evidence(
            "bundle-host-risk-default",
            {"hosts": ["203.0.113.10"], "time_start": "2026-09-18T00:00:00+08:00",
             "time_end": "2026-09-18T01:00:00+08:00"},
            scenarios=["S5"], resolve_secrets=False,
        )
        bootstrap.assert_not_called()
        self.assertEqual(evidence["host_exec"][0]["evidence_id"], "exec-regression")
        self.assertEqual(fetch_bundle.call_args.args[0], meta["declared_asset_ids"])
        self.assertEqual(meta["executed_asset_ids"], meta["declared_asset_ids"])
        self.assertEqual(meta["skipped_assets"], [])
        self.assertFalse(fetch_bundle.call_args.kwargs["resolve_secrets"])

    @patch("scenario_fetch.load_templates", return_value={"templates": {}})
    @patch("correlation_engine.plan_fetch", return_value=[])
    @patch("trace_d1_bootstrap.fetch_trace_d1_bootstrap")
    @patch("fetch.fetch_bundle_evidence")
    def test_empty_trace_bootstrap_does_not_suppress_bundle_fallback(self, fetch_bundle, bootstrap, *_):
        fetch_bundle.return_value = {"host_exec": [{"evidence_id": "exec-fallback"}]}
        # Empty successful source arrays used to make the evidence container
        # truthy, skipping all declared host queries after a failed gateway read.
        bootstrap.return_value = ({"waf_alert": []}, {"trace_d1_bootstrap": {"attacker_ips": []}})
        evidence, _meta = fetch_scenario_evidence(
            "bundle-incident-trace-default",
            {"hosts": ["203.0.113.10"], "time_start": "2026-09-18T00:00:00+08:00",
             "time_end": "2026-09-18T01:00:00+08:00"},
            scenarios=["S1", "S3"], resolve_secrets=False,
        )
        bootstrap.assert_called_once()
        fetch_bundle.assert_called_once()
        self.assertEqual(evidence["host_exec"][0]["evidence_id"], "exec-fallback")

    def test_hosts_registry_is_exposed_as_cmdb_inventory(self) -> None:
        registered = host_registry_to_registered_asset(
            [
                {
                    "host_id": "host-91",
                    "hostname": "web-91",
                    "host_ip": "192.0.2.91",
                    "aliases": ["web"],
                    "status": "active",
                },
                {
                    "host_id": "host-disabled",
                    "host_ip": "192.0.2.99",
                    "status": "disabled",
                },
            ]
        )

        self.assertEqual(registered["type"], "asset_inventory")
        self.assertEqual(registered["registry_source"], "dataasset/hosts")
        self.assertEqual(registered["record_count"], 1)
        self.assertIn("full", registered["coverage_detail"]["zones"])
        self.assertIn("192.0.2.91", registered["coverage_detail"]["hosts"])
        self.assertNotIn("192.0.2.99", registered["coverage_detail"]["hosts"])

    def test_coalesces_persistence_alias_queries_for_same_host(self) -> None:
        tasks = [
            {
                "join_id": "web_to_persist",
                "asset_id": "persist-asset",
                "asset_type": "host_persistence",
                "template_id": "host_persistence_by_host_time",
                "params": {"host": "192.0.2.91", "time_start": "t0", "time_end": "t1"},
            },
            {
                "join_id": "waf_to_persist",
                "asset_id": "persist-asset",
                "asset_type": "host_persistence",
                "template_id": "host_persistence_by_host_ip_time",
                "params": {"host_ip": "192.0.2.91", "time_start": "t0", "time_end": "t1"},
            },
        ]

        retained, reused = _coalesce_trace_tasks(tasks, {})

        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0]["template_id"], "host_persistence_by_host_ip_time")
        self.assertEqual(reused[0]["fetch_disposition"], "reused_equivalent_asset_query")

    def test_coalesces_syslog_queries_only_for_narrow_window(self) -> None:
        tasks = [
            {
                "join_id": "attacker_ssh",
                "asset_id": "syslog-asset",
                "asset_type": "syslog_risk_alert",
                "template_id": "ssh_auth_by_src_ip_time",
                "params": {
                    "src_ip": "218.74.11.194",
                    "time_start": "2026-07-11T12:29:41+08:00",
                    "time_end": "2026-07-11T12:41:04+08:00",
                },
            },
            {
                "join_id": "source_lateral_ssh",
                "asset_id": "syslog-asset",
                "asset_type": "syslog_risk_alert",
                "template_id": "ssh_auth_by_src_ip_time",
                "params": {
                    "src_ip": "192.0.2.91",
                    "time_start": "2026-07-11T12:29:41+08:00",
                    "time_end": "2026-07-11T12:41:04+08:00",
                },
            },
            {
                "join_id": "lateral_ssh",
                "asset_id": "syslog-asset",
                "asset_type": "syslog_risk_alert",
                "template_id": "ssh_auth_by_host_time",
                "params": {
                    "host": "192.0.2.91",
                    "time_start": "2026-07-11T12:29:41+08:00",
                    "time_end": "2026-07-11T12:41:04+08:00",
                },
            },
        ]
        templates = {
            "syslog_risk_by_time": {
                "params": ["time_start", "time_end", "limit"],
            },
            "syslog_risk_by_host_ip_time": {
                "params": ["host_ip", "time_start", "time_end", "limit"],
            },
        }

        retained, reused = _coalesce_trace_tasks(tasks, templates)

        self.assertEqual(len(retained), 3)
        self.assertEqual(
            {task["template_id"] for task in retained},
            {
                "ssh_auth_by_src_ip_time",
                "ssh_auth_by_host_time",
                "syslog_risk_by_host_ip_time",
            },
        )
        self.assertEqual(retained[0]["params"]["src_ip"], "192.0.2.91")
        self.assertEqual(len(reused), 1)
        self.assertEqual(
            {item["fetch_disposition"] for item in reused},
            {"reused_complementary_syslog_queries"},
        )
    def test_correlate_parser_exposes_asset_id(self) -> None:
        parser = argparse.ArgumentParser()
        add_bundle_arguments(parser, "traceability")
        args = parser.parse_args(
            [
                "--asset-id",
                "asset-secweaver-host-exec",
                "--asset-id",
                "asset-secweaver-sys-risk-alert",
                "--params",
                '{"hosts":["192.0.2.91"],"time_start":"2026-07-06T07:25:00+08:00","time_end":"2026-07-06T07:27:34+08:00"}',
            ]
        )
        self.assertEqual(
            args.asset_ids,
            ["asset-secweaver-host-exec", "asset-secweaver-sys-risk-alert"],
        )

    def test_correlate_parser_exposes_full_impact_fetch(self) -> None:
        parser = argparse.ArgumentParser()
        add_bundle_arguments(parser, "traceability")
        args = parser.parse_args(
            [
                "--from-bundle",
                "--fetch",
                "--skip-completeness",
                "--full-impact-fetch",
                "--params",
                '{"attacker_ip":"203.0.113.8","time_start":"2026-07-11T00:00:00+08:00","time_end":"2026-07-11T23:59:59+08:00"}',
            ]
        )
        self.assertTrue(args.full_impact_fetch)

    def test_resolve_payload_asset_list_without_bundle(self) -> None:
        parser = argparse.ArgumentParser()
        add_bundle_arguments(parser, "traceability")
        args = parser.parse_args(
            [
                "--asset-id",
                "asset-secweaver-host-exec",
                "--dry-run",
                "--skip-completeness",
                "--params",
                '{"hosts":["192.0.2.91"],"target_ip":"192.0.2.91","time_start":"2026-07-06T07:25:00+08:00","time_end":"2026-07-06T07:27:34+08:00"}',
            ]
        )
        payload = resolve_payload_from_cli(args, "traceability", build_traceability_payload)
        assert payload is not None
        self.assertNotIn("bundle_id", payload)
        self.assertEqual(payload["asset_ids"], ["asset-secweaver-host-exec"])
        self.assertIn("asset_list", payload["data_access"]["fetch_strategy"])
        self.assertIn("trace_d1_bootstrap", payload["data_access"])

    def test_build_traceability_payload_keeps_bundle_when_from_bundle(self) -> None:
        payload = build_traceability_payload(
            "bundle-incident-trace-default",
            {"time_start": "2026-07-06T07:25:00+08:00", "time_end": "2026-07-06T07:27:34+08:00"},
            skip_completeness=True,
        )
        self.assertEqual(payload["bundle_id"], "bundle-incident-trace-default")
        self.assertNotIn("asset_ids", payload)

    @patch("skill_input.run_completeness_assess")
    def test_traceability_payload_runs_completeness_by_default(self, completeness_mock) -> None:
        completeness_mock.return_value = {
            "overall_verdict": "full_traceable",
            "confidence": 0.88,
            "next_skill_blocked": False,
        }

        payload = build_traceability_payload(
            "bundle-incident-trace-default",
            {"time_start": "2026-07-06T07:25:00+08:00", "time_end": "2026-07-06T07:27:34+08:00"},
        )

        completeness_mock.assert_called_once()
        self.assertEqual(payload["completeness_precheck"]["overall_verdict"], "full_traceable")

    def test_traceability_anchor_pattern_sets_scenario(self) -> None:
        payload = build_traceability_payload(
            None,
            {"time_start": "2026-07-06T13:47:00+08:00", "time_end": "2026-07-06T13:50:34+08:00"},
            skip_completeness=True,
            asset_ids=["asset-secweaver-host-exec"],
            anchor_pattern_id="S5_host_risk",
        )

        self.assertEqual(payload["scenarios"], ["S5"])
        self.assertEqual(payload["scenario"], "S5")
        self.assertEqual(payload["correlation_anchor_pattern"], "S5_host_risk")

    @patch("fetch.fetch_correlation_plan_evidence")
    @patch("s4_fetch_bootstrap.fetch_s4_bootstrap")
    def test_s1_external_ip_bootstrap_enriches_target_before_replanning(
        self,
        fetch_s4_mock,
        fetch_plan_mock,
    ) -> None:
        fetch_s4_mock.return_value = (
            {
                "waf_alert": [{"evidence_id": "waf-1", "src_ip": "203.0.113.8"}],
                "web_access_log": [
                    {
                        "evidence_id": "web-1",
                        "src_ip": "203.0.113.8",
                        "target_ip": "192.0.2.91",
                    }
                ],
                "host_exec": [{"evidence_id": "exec-1", "host_ip": "192.0.2.91"}],
                "host_file_op": [],
                "host_persistence": [],
            },
            {
                "fetch_strategy": "s4_bootstrap",
                "correlation_fetch_plan": [
                    {
                        "join_id": "waf_to_host_file_op_direct",
                        "asset_id": "asset-secweaver-host-file-op",
                        "template_id": "host_file_op_by_host_ip_time",
                        "params": {"host_ip": "192.0.2.91"},
                    }
                ],
                "s4_bootstrap": {
                    "attacker_ips": ["203.0.113.8"],
                    "target_ips": ["192.0.2.91"],
                },
                "enriched_params": {
                    "attacker_ip": "203.0.113.8",
                    "target_ip": "192.0.2.91",
                    "target_ips": ["192.0.2.91"],
                },
            },
        )
        fetch_plan_mock.return_value = {"syslog_risk_alert": []}

        evidence, meta = fetch_scenario_evidence(
            "bundle-incident-trace-default",
            {
                "attacker_ip": "203.0.113.8",
                "time_start": "2026-07-11T00:00:00+08:00",
                "time_end": "2026-07-11T23:59:59+08:00",
            },
            scenarios=["S1", "S3"],
            anchor_pattern_ids=["S1_external_ip_trace", "S3_lateral_movement"],
            resolve_secrets=False,
        )

        tasks = fetch_plan_mock.call_args.args[0]
        lateral_tasks = [task for task in tasks if task.get("join_id") == "host_ip_to_ssh_auth_lateral"]
        self.assertTrue(lateral_tasks)
        self.assertIn(
            "192.0.2.91",
            {str(task.get("params", {}).get("src_ip")) for task in lateral_tasks},
        )
        self.assertIn("host_exec", evidence)
        self.assertIn("trace_external_ip_impact_bootstrap", meta)
        self.assertEqual(meta["enriched_params"]["host_ip"], "192.0.2.91")

    @patch("fetch.fetch_bundle_evidence")
    @patch("fetch.fetch_correlation_plan_evidence")
    def test_full_impact_fetch_executes_declared_bundle_assets(
        self,
        fetch_plan_mock,
        fetch_bundle_mock,
    ) -> None:
        fetch_plan_mock.return_value = {"host_exec": []}
        fetch_bundle_mock.return_value = {"host_file_op": [{"evidence_id": "file-1"}]}

        payload = build_traceability_payload(
            "bundle-incident-trace-default",
            {
                "attacker_ip": "203.0.113.8",
                "target_ip": "192.0.2.91",
                "time_start": "2026-07-11T12:34:40+08:00",
                "time_end": "2026-07-11T12:36:40+08:00",
            },
            fetch_live=True,
            skip_completeness=True,
            full_impact_fetch=True,
        )

        self.assertIn("bundle_full_impact", payload["data_access"]["fetch_strategy"])
        self.assertEqual(payload["fetch_summary"]["skipped_assets"], [])
        self.assertTrue(
            _has_compat_asset(
                payload["fetch_summary"]["executed_asset_ids"],
                "asset-secweaver-host-file-op",
                "asset-tigersec-host-file-op",
            )
        )
        self.assertIn("host_file_op", payload["evidence_bundles"])

    @patch("fetch.fetch_bundle_evidence")
    @patch("fetch.fetch_correlation_plan_evidence")
    def test_full_impact_fetch_narrows_window_from_attacker_seen_range(
        self,
        fetch_plan_mock,
        fetch_bundle_mock,
    ) -> None:
        fetch_plan_mock.return_value = {
            "web_access_log": [
                {
                    "evidence_id": "web-1",
                    "src_ip": "203.0.113.8",
                    "timestamp": "2026-07-11T12:34:41+08:00",
                },
                {
                    "evidence_id": "web-2",
                    "src_ip": "203.0.113.8",
                    "timestamp": "2026-07-11T12:36:04+08:00",
                },
            ]
        }
        fetch_bundle_mock.return_value = {"host_exec": []}

        _evidence, meta = fetch_scenario_evidence(
            "bundle-incident-trace-default",
            {
                "attacker_ip": "203.0.113.8",
                "target_ip": "192.0.2.91",
                "time_start": "2026-07-11T00:00:00+08:00",
                "time_end": "2026-07-11T23:59:59+08:00",
            },
            scenarios=["S1", "S3"],
            anchor_pattern_ids=["S1_external_ip_trace", "S3_lateral_movement"],
            resolve_secrets=False,
            full_impact_fetch=True,
        )

        impact_params = fetch_bundle_mock.call_args.args[1]
        self.assertEqual(impact_params["time_start"], "2026-07-11T12:29:41+08:00")
        self.assertEqual(impact_params["time_end"], "2026-07-11T12:41:04+08:00")
        self.assertEqual(
            meta["attacker_ip_window_narrowing"]["original_time_start"],
            "2026-07-11T00:00:00+08:00",
        )
        self.assertEqual(meta["enriched_params"]["time_start"], "2026-07-11T12:29:41+08:00")

    @patch("fetch.fetch_bundle_evidence")
    @patch("fetch.fetch_correlation_plan_evidence")
    def test_default_fetch_narrows_window_before_second_hop_impact(
        self,
        fetch_plan_mock,
        fetch_bundle_mock,
    ) -> None:
        fetch_plan_mock.return_value = {
            "web_access_log": [
                {
                    "evidence_id": "web-1",
                    "src_ip": "203.0.113.8",
                    "target_ip": "192.0.2.91",
                    "timestamp": "2026-07-11T12:34:41+08:00",
                    "url": "/webshell/uploads/s.phtml?c=id",
                },
                {
                    "evidence_id": "web-2",
                    "src_ip": "203.0.113.8",
                    "target_ip": "192.0.2.91",
                    "timestamp": "2026-07-11T12:36:04+08:00",
                    "url": "/webshell/uploads/s.phtml?c=sshpass+-p+ubuntu+ssh+devops@192.0.2.92",
                },
            ],
            "host_exec": [
                {
                    "evidence_id": "old-exec",
                    "host_ip": "192.0.2.91",
                    "timestamp": "2026-07-11T09:21:00+08:00",
                    "command": "systemctl stop syslog-risk-json",
                },
                {
                    "evidence_id": "attack-exec",
                    "host_ip": "192.0.2.91",
                    "timestamp": "2026-07-11T12:35:10+08:00",
                    "command": "sshpass -p ubuntu ssh devops@192.0.2.92",
                },
                {
                    "evidence_id": "truncated-exec",
                    "host_ip": "192.0.2.91",
                    "timestamp": "2026-07-11T12:35:19+08:00",
                    "command": (
                        "sh -c sshpass -p password123 ssh -o ConnectTimeout=5 "
                        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                        "devops@192.0.2.9"
                    ),
                },
            ],
        }
        fetch_bundle_mock.return_value = {
            "host_exec": [{"evidence_id": "target-exec", "host_ip": "192.0.2.92"}],
        }

        evidence, meta = fetch_scenario_evidence(
            "bundle-incident-trace-default",
            {
                "attacker_ip": "203.0.113.8",
                "target_ip": "192.0.2.91",
                "hosts": ["192.0.2.91"],
                "time_start": "2026-07-11T00:00:00+08:00",
                "time_end": "2026-07-11T23:59:59+08:00",
            },
            scenarios=["S1", "S3"],
            anchor_pattern_ids=["S1_external_ip_trace", "S3_lateral_movement"],
            resolve_secrets=False,
        )

        self.assertEqual(fetch_bundle_mock.call_count, 1)
        second_hop_params = fetch_bundle_mock.call_args.args[1]
        self.assertEqual(second_hop_params["time_start"], "2026-07-11T12:29:41+08:00")
        self.assertEqual(second_hop_params["time_end"], "2026-07-11T12:41:04+08:00")
        self.assertEqual(second_hop_params["hosts"], ["192.0.2.92"])
        self.assertEqual(meta["enriched_params"]["time_start"], "2026-07-11T12:29:41+08:00")
        self.assertEqual(
            meta["attacker_ip_window_narrowing"]["evidence_filter"]["dropped_by_asset_type"],
            {"host_exec": 1},
        )
        evidence_ids = {event["evidence_id"] for event in evidence["host_exec"]}
        self.assertNotIn("old-exec", evidence_ids)
        self.assertIn("attack-exec", evidence_ids)
        self.assertIn("target-exec", evidence_ids)

    @patch("fetch.fetch_bundle_evidence")
    @patch("fetch.fetch_correlation_plan_evidence")
    def test_full_impact_fetch_adds_second_hop_target_impact(
        self,
        fetch_plan_mock,
        fetch_bundle_mock,
    ) -> None:
        fetch_plan_mock.return_value = {
            "syslog_risk_alert": [
                {
                    "evidence_id": "sys-1",
                    "timestamp": "2026-07-11T12:35:43+08:00",
                    "event_type": "ssh_login_success",
                    "src_ip": "192.0.2.91",
                    "host_ip": "192.0.2.92",
                    "host": "192.0.2.92",
                    "user": "devops",
                    "message": "Accepted password for devops from 192.0.2.91 port 46232 ssh2",
                }
            ]
        }
        fetch_bundle_mock.side_effect = [
            {"host_exec": [{"evidence_id": "entry-exec", "host_ip": "192.0.2.91"}]},
            {
                "host_exec": [{"evidence_id": "target-exec", "host_ip": "192.0.2.92"}],
                "host_file_op": [{"evidence_id": "target-file", "host_ip": "192.0.2.92"}],
            },
        ]

        evidence, meta = fetch_scenario_evidence(
            "bundle-incident-trace-default",
            {
                "attacker_ip": "203.0.113.8",
                "target_ip": "192.0.2.91",
                "hosts": ["192.0.2.91"],
                "time_start": "2026-07-11T12:34:40+08:00",
                "time_end": "2026-07-11T12:36:40+08:00",
            },
            scenarios=["S1", "S3"],
            anchor_pattern_ids=["S1_external_ip_trace", "S3_lateral_movement"],
            resolve_secrets=False,
            full_impact_fetch=True,
        )

        self.assertEqual(fetch_bundle_mock.call_count, 2)
        second_hop_assets = set(fetch_bundle_mock.call_args_list[1].args[0])
        self.assertTrue(
            _has_compat_asset(
                second_hop_assets,
                "asset-secweaver-host-exec",
                "asset-tigersec-host-exec",
            )
        )
        self.assertTrue(
            _has_compat_asset(
                second_hop_assets,
                "asset-secweaver-host-file-op",
                "asset-tigersec-host-file-op",
            )
        )
        self.assertNotIn("asset-waf-prod-01", second_hop_assets)
        second_hop_params = fetch_bundle_mock.call_args_list[1].args[1]
        self.assertEqual(second_hop_params["hosts"], ["192.0.2.92"])
        self.assertEqual(meta["second_hop_impact_fetch"]["target_hosts"], ["192.0.2.92"])
        self.assertIn("second_hop_impact", meta["fetch_strategy"])
        self.assertIn("target-exec", {ev["evidence_id"] for ev in evidence["host_exec"]})
        self.assertIn("target-file", {ev["evidence_id"] for ev in evidence["host_file_op"]})

    @patch("fetch.fetch_bundle_evidence")
    @patch("fetch.fetch_correlation_plan_evidence")
    def test_lateral_hint_adds_target_impact_before_ssh_accepted(
        self,
        fetch_plan_mock,
        fetch_bundle_mock,
    ) -> None:
        fetch_plan_mock.return_value = {
            "web_access_log": [
                {
                    "evidence_id": "web-sshpass",
                    "timestamp": "2026-07-11T12:35:41+08:00",
                    "target_ip": "192.0.2.91",
                    "url": (
                        "http://test1.u.yinshendun.com:30443/webshell/uploads/s.phtml"
                        "?c=sshpass+-p+ubuntu+ssh+devops@192.0.2.92+echo+AUTH_SUCCESS"
                    ),
                }
            ],
            "syslog_risk_alert": [],
        }
        fetch_bundle_mock.return_value = {
            "host_exec": [{"evidence_id": "target-exec", "host_ip": "192.0.2.92"}],
            "host_file_op": [{"evidence_id": "target-file", "host_ip": "192.0.2.92"}],
        }

        evidence, meta = fetch_scenario_evidence(
            "bundle-incident-trace-default",
            {
                "attacker_ip": "203.0.113.8",
                "target_ip": "192.0.2.91",
                "hosts": ["192.0.2.91"],
                "time_start": "2026-07-11T12:34:40+08:00",
                "time_end": "2026-07-11T12:36:40+08:00",
            },
            scenarios=["S1", "S3"],
            anchor_pattern_ids=["S1_external_ip_trace", "S3_lateral_movement"],
            resolve_secrets=False,
        )

        self.assertEqual(fetch_bundle_mock.call_count, 1)
        second_hop_params = fetch_bundle_mock.call_args.args[1]
        self.assertEqual(second_hop_params["hosts"], ["192.0.2.92"])
        self.assertEqual(meta["second_hop_impact_fetch"]["source"], "exec_or_web_lateral_hint")
        self.assertEqual(meta["second_hop_impact_fetch"]["target_hosts"], ["192.0.2.92"])
        self.assertIn("second_hop_impact", meta["fetch_strategy"])
        self.assertIn("target-exec", {ev["evidence_id"] for ev in evidence["host_exec"]})
        self.assertIn("target-file", {ev["evidence_id"] for ev in evidence["host_file_op"]})

    @patch("fetch.fetch_correlation_plan_evidence")
    @patch("fetch.fetch_bundle_evidence")
    def test_asset_list_discovers_source_ssh_and_fetches_target_impact(
        self,
        fetch_bundle_mock,
        fetch_plan_mock,
    ) -> None:
        """Asset-list traceability must not stop at the entry host query."""
        fetch_bundle_mock.return_value = {
            "host_exec": [
                {
                    "evidence_id": "entry-exec",
                    "host_ip": "192.0.2.91",
                    "command": "webshell command completed",
                }
            ],
            "syslog_risk_alert": [],
        }
        accepted = {
            "evidence_id": "accepted-92",
            "timestamp": "2026-08-20T14:53:25+08:00",
            "event_type": "ssh_login_success",
            "rule_id": "secure_ssh_login_success",
            "src_ip": "192.0.2.91",
            "host_ip": "192.0.2.92",
            "__source__": "192.0.2.92",
            "message": "Accepted password for devops from 192.0.2.91 port 52844 ssh2",
            "user": "devops",
        }

        def plan_side_effect(tasks, *, resolve_secrets=True):
            template_ids = {task["template_id"] for task in tasks}
            if "ssh_auth_by_src_ip_time" in template_ids:
                self.assertEqual(
                    {task["params"].get("src_ip") for task in tasks},
                    {"192.0.2.91"},
                )
                return {"syslog_risk_alert": [accepted]}
            self.assertIn("ssh_auth_by_host_ip_time", template_ids)
            self.assertIn(
                "192.0.2.92",
                {task["params"].get("host_ip") for task in tasks},
            )
            return {
                "syslog_risk_alert": [accepted],
                "host_exec": [
                    {
                        "evidence_id": "target-exec",
                        "host_ip": "192.0.2.92",
                        "command": "/usr/sbin/sshd -D -R",
                    }
                ],
            }

        fetch_plan_mock.side_effect = plan_side_effect
        payload = build_evidence_fetch_payload(
            {
                "target_ip": "192.0.2.91",
                "hosts": ["192.0.2.91"],
                "resolve_attacker_ip": False,
                "time_start": "2026-08-20T14:42:00+08:00",
                "time_end": "2026-08-20T15:02:00+08:00",
            },
            asset_ids=[
                "asset-secweaver-host-exec",
                "asset-secweaver-sys-risk-alert",
            ],
            scenarios=[],
            fetch_live=True,
            include_completeness=False,
        )

        self.assertIn("second_hop_impact_fetch", payload["data_access"])
        self.assertEqual(
            payload["data_access"]["second_hop_impact_fetch"]["target_hosts"],
            ["192.0.2.92"],
        )
        self.assertIn(
            "target-exec",
            {event["evidence_id"] for event in payload["evidence_bundles"]["host_exec"]},
        )

    @patch("fetch.fetch_correlation_plan_evidence")
    @patch("fetch.fetch_bundle_evidence")
    def test_asset_list_retries_waf_by_source_ip_when_upstream_query_is_empty(
        self,
        fetch_bundle_mock,
        fetch_plan_mock,
    ) -> None:
        """An empty upstream match must retry WAF by the correlated source IP."""
        fetch_bundle_mock.return_value = {
            "waf_alert": [],
            "web_access_log": [
                {
                    "evidence_id": "web-91",
                    "timestamp": "2026-08-20T14:52:03+08:00",
                    "src_ip": "8.8.8.8",
                    "target_ip": "192.0.2.91",
                    "url": "https://test.example/cmdi/diag.php?tool=ping",
                }
            ],
            "host_exec": [],
            "syslog_risk_alert": [],
        }

        def plan_side_effect(tasks, *, resolve_secrets=True):
            template_ids = {task["template_id"] for task in tasks}
            if "waf_gateway_plugin_by_ip_time" in template_ids:
                return {
                    "waf_alert": [
                        {
                            "evidence_id": "waf-fallback",
                            "timestamp": "2026-08-20T14:52:04+08:00",
                            "src_ip": "8.8.8.8",
                            "upstream_addr": "192.0.2.91:80",
                            "url": "https://test.example/.env",
                        }
                    ]
                }
            return {}

        fetch_plan_mock.side_effect = plan_side_effect
        payload = build_evidence_fetch_payload(
            {
                "target_ip": "192.0.2.91",
                "hosts": ["192.0.2.91"],
                "resolve_attacker_ip": False,
                "time_start": "2026-08-20T14:42:00+08:00",
                "time_end": "2026-08-20T15:02:00+08:00",
            },
            asset_ids=[
                "asset-secweaver-host-exec",
                "asset-secweaver-sys-risk-alert",
                "asset-waf-prod-01",
                "asset-secweaver-gateway-access",
            ],
            scenarios=[],
            fetch_live=True,
            include_completeness=False,
        )

        self.assertIn(
            "waf-fallback",
            {event["evidence_id"] for event in payload["evidence_bundles"]["waf_alert"]},
        )
        fallback = payload["data_access"]["waf_target_fallback"]
        self.assertEqual(fallback["fallback_mode"], "attacker_ip_time")
        self.assertEqual(fallback["matched_event_count"], 1)
        self.assertEqual(fallback["attacker_ips"], ["8.8.8.8"])
        self.assertIn("waf_gateway_plugin_by_ip_time", fallback["fallback_template_ids"])

    @patch("fetch.fetch_correlation_plan_evidence")
    @patch("fetch.fetch_bundle_evidence")
    def test_asset_list_filters_time_only_waf_fallback_by_host_and_path(
        self,
        fetch_bundle_mock,
        fetch_plan_mock,
    ) -> None:
        """Time-only WAF fallback must not merge unrelated hosts in the same window."""
        fetch_bundle_mock.return_value = {
            "waf_alert": [],
            "web_access_log": [
                {
                    "evidence_id": "web-91",
                    "timestamp": "2026-08-20T14:52:03+08:00",
                    "target_ip": "192.0.2.91",
                    "url": "https://test.example/webshell/upload.php",
                }
            ],
            "host_exec": [],
            "syslog_risk_alert": [],
        }

        def plan_side_effect(tasks, *, resolve_secrets=True):
            template_ids = {task["template_id"] for task in tasks}
            if "waf_gateway_plugin_by_time" in template_ids:
                return {
                    "waf_alert": [
                        {
                            "evidence_id": "waf-matched",
                            "timestamp": "2026-08-20T14:52:04+08:00",
                            "url": "https://test.example/webshell/upload.php",
                        },
                        {
                            "evidence_id": "waf-unrelated",
                            "timestamp": "2026-08-20T14:52:04+08:00",
                            "url": "https://other.example/admin/upload.php",
                        },
                    ]
                }
            return {}

        fetch_plan_mock.side_effect = plan_side_effect
        payload = build_evidence_fetch_payload(
            {
                "target_ip": "192.0.2.91",
                "hosts": ["192.0.2.91"],
                "resolve_attacker_ip": False,
                "time_start": "2026-08-20T14:42:00+08:00",
                "time_end": "2026-08-20T15:02:00+08:00",
            },
            asset_ids=[
                "asset-secweaver-host-exec",
                "asset-secweaver-sys-risk-alert",
                "asset-waf-prod-01",
                "asset-secweaver-gateway-access",
            ],
            scenarios=[],
            fetch_live=True,
            include_completeness=False,
        )

        waf_ids = {event["evidence_id"] for event in payload["evidence_bundles"]["waf_alert"]}
        self.assertEqual(waf_ids, {"waf-matched"})
        fallback = payload["data_access"]["waf_target_fallback"]
        self.assertEqual(fallback["fallback_mode"], "time_window_scope_filter")
        self.assertEqual(fallback["candidate_event_count"], 2)
        self.assertEqual(fallback["matched_event_count"], 1)

    def test_infer_d1_target_from_web_listener_high_risk_exec(self) -> None:
        candidates = infer_d1_targets_from_host_exec(
            {
                "host_exec": [
                    {
                        "evidence_id": "exec-1",
                        "timestamp": "2026-07-06T13:49:25+08:00",
                        "host": "192.0.2.91",
                        "host_ip": "192.0.2.91",
                        "listener_process": "nginx",
                        "listener_port": "80",
                        "command": '["sh","-c","cat /etc/shadow"]',
                        "tty": "(none)",
                        "has_tty": "false",
                    }
                ]
            }
        )

        self.assertEqual(candidates[0]["target_ip"], "192.0.2.91")
        self.assertEqual(candidates[0]["web_exec_refs"], ["exec-1"])
        self.assertEqual(candidates[0]["high_risk_refs"], ["exec-1"])

    @patch("trace_d1_bootstrap.fetch_trace_d1_bootstrap")
    @patch("fetch.fetch_bundle_evidence")
    def test_asset_list_infers_target_then_runs_d1_bootstrap(
        self,
        fetch_bundle_mock,
        fetch_d1_mock,
    ) -> None:
        fetch_bundle_mock.return_value = {
            "host_exec": [
                {
                    "evidence_id": "exec-1",
                    "timestamp": "2026-07-06T13:49:25+08:00",
                    "host": "192.0.2.91",
                    "host_ip": "192.0.2.91",
                    "listener_process": "nginx",
                    "listener_port": "80",
                    "command": '["sh","-c","cat /etc/shadow"]',
                    "tty": "(none)",
                    "has_tty": "false",
                }
            ]
        }
        fetch_d1_mock.return_value = (
            {"waf_alert": [{"evidence_id": "waf-1", "src_ip": "203.0.113.8"}]},
            {
                "correlation_fetch_plan": [{"asset_id": "asset-waf-prod-01"}],
                "trace_d1_bootstrap": {
                    "target_ip": "192.0.2.91",
                    "attacker_ips": ["203.0.113.8"],
                },
                "enriched_params": {
                    "target_ip": "192.0.2.91",
                    "hosts": ["192.0.2.91"],
                    "attacker_ip": "203.0.113.8",
                },
            },
        )

        payload = build_evidence_fetch_payload(
            {
                "time_start": "2026-07-06T13:47:00+08:00",
                "time_end": "2026-07-06T13:50:34+08:00",
            },
            asset_ids=["asset-secweaver-host-exec", "asset-secweaver-sys-risk-alert"],
            fetch_live=True,
        )

        d1_params = fetch_d1_mock.call_args.args[1]
        self.assertEqual(d1_params["target_ip"], "192.0.2.91")
        self.assertIn("waf_alert", payload["evidence_bundles"])
        self.assertEqual(payload["params"]["attacker_ip"], "203.0.113.8")
        self.assertIn("trace_d1_bootstrap", payload["data_access"])
        self.assertEqual(payload["data_access"]["trace_d1_inferred_targets"][0]["target_ip"], "192.0.2.91")

    @patch("fetch.fetch_bundle_evidence")
    def test_asset_list_anchor_appends_chain_assets(self, fetch_bundle_mock) -> None:
        fetch_bundle_mock.return_value = {"host_exec": []}

        payload = build_evidence_fetch_payload(
            {
                "time_start": "2026-07-06T13:47:00+08:00",
                "time_end": "2026-07-06T13:50:34+08:00",
            },
            asset_ids=["asset-secweaver-host-exec", "asset-secweaver-sys-risk-alert"],
            anchor_pattern_id="S5_host_risk",
            fetch_live=True,
        )

        fetched_assets = fetch_bundle_mock.call_args.args[0]
        self.assertTrue(
            _has_compat_asset(
                fetched_assets,
                "asset-secweaver-host-connect",
                "asset-tigersec-host-connect",
            )
        )
        self.assertTrue(
            _has_compat_asset(
                fetched_assets,
                "asset-secweaver-host-file-op",
                "asset-tigersec-host-file-op",
            )
        )
        appended = payload["data_access"]["trace_chain_appended_assets"]
        self.assertTrue(
            {"host_connect", "host_file_op"}
            <= {item["asset_type"] for item in appended}
        )
        self.assertTrue(
            _has_compat_asset(
                payload["fetch_summary"]["fetch_asset_ids"],
                "asset-secweaver-host-connect",
                "asset-tigersec-host-connect",
            )
        )

    @patch("s4_fetch_bootstrap.fetch_s4_bootstrap")
    @patch("fetch.fetch_bundle_evidence")
    def test_waf_only_asset_uses_field_correlated_bootstrap_without_scenario(
        self,
        fetch_bundle_mock,
        fetch_s4_mock,
    ) -> None:
        fetch_s4_mock.return_value = (
            {
                "waf_alert": [{"alert_id": "waf-1", "src_ip": "192.168.99.61"}],
                "web_access_log": [
                    {
                        "evidence_id": "web-1",
                        "src_ip": "192.168.99.61",
                        "upstream_addr": "192.0.2.91:80",
                    }
                ],
                "host_exec": [{"evidence_id": "exec-1", "host_ip": "192.0.2.91"}],
                "host_connect": [],
                "host_file_op": [],
            },
            {
                "source": "dataasset",
                "fetch_strategy": "s4_bootstrap",
                "correlation_fetch_plan": [
                    {
                        "join_id": "s4_bootstrap_waf",
                        "asset_id": "asset-waf-prod-01",
                        "template_id": "waf_gateway_plugin_by_time",
                    },
                    {
                        "join_id": "waf_to_web_access_by_ip",
                        "asset_id": "asset-secweaver-gateway-access",
                        "template_id": "web_access_by_remote_addr_time",
                        "params": {"src_ip": "192.168.99.61"},
                    },
                    {
                        "join_id": "waf_to_host_exec_direct",
                        "asset_id": "asset-secweaver-host-exec",
                        "template_id": "host_exec_by_host_ip_time",
                        "params": {"host_ip": "192.0.2.91"},
                    },
                    {
                        "join_id": "waf_to_host_connect_direct",
                        "asset_id": "asset-secweaver-host-connect",
                        "template_id": "host_connect_by_host_ip_time",
                        "params": {"host_ip": "192.0.2.91"},
                    },
                    {
                        "join_id": "waf_to_host_file_op_direct",
                        "asset_id": "asset-secweaver-host-file-op",
                        "template_id": "host_file_op_by_host_ip_time",
                        "params": {"host_ip": "192.0.2.91"},
                    },
                ],
                "executed_asset_ids": [
                    "asset-waf-prod-01",
                    "asset-secweaver-gateway-access",
                    "asset-secweaver-host-exec",
                    "asset-secweaver-host-connect",
                    "asset-secweaver-host-file-op",
                ],
                "enriched_params": {
                    "target_ip": "192.0.2.91",
                    "attacker_ip": "192.168.99.61",
                    "src_ip": "192.168.99.61",
                },
            },
        )

        payload = build_evidence_fetch_payload(
            {
                "time_start": "2026-07-06T13:47:00+08:00",
                "time_end": "2026-07-06T13:50:34+08:00",
            },
            asset_ids=["asset-waf-prod-01"],
            fetch_live=True,
        )

        fetch_bundle_mock.assert_not_called()
        fetch_s4_mock.assert_called_once()
        self.assertEqual(
            fetch_s4_mock.call_args.args[0],
            [
                "asset-waf-prod-01",
                resolve_s4_gateway_asset_id(),
                "asset-secweaver-host-exec",
                "asset-secweaver-host-connect",
                "asset-secweaver-host-file-op",
            ],
        )
        self.assertEqual(payload["data_access"]["fetch_strategy"], "s4_gateway_bootstrap+s4_bootstrap")
        self.assertEqual(payload["params"]["target_ip"], "192.0.2.91")
        plan = payload["correlation_fetch_plan"]
        self.assertIn("waf_to_web_access_by_ip", {task.get("join_id") for task in plan})
        self.assertIn("waf_to_host_file_op_direct", {task.get("join_id") for task in plan})
        self.assertIn("asset-secweaver-host-file-op", payload["fetch_summary"]["executed_asset_ids"])

    @patch("s4_fetch_bootstrap.fetch_s4_bootstrap")
    @patch("fetch.fetch_bundle_evidence")
    def test_waf_only_alert_anchor_prefers_s4_bootstrap_before_chain_append(
        self,
        fetch_bundle_mock,
        fetch_s4_mock,
    ) -> None:
        fetch_s4_mock.return_value = (
            {
                "waf_alert": [{"alert_id": "waf-1", "src_ip": "192.168.99.16"}],
                "web_access_log": [{"evidence_id": "web-1", "src_ip": "192.168.99.16"}],
                "host_exec": [{"evidence_id": "exec-1", "host_ip": "192.0.2.91"}],
            },
            {
                "source": "dataasset",
                "fetch_strategy": "s4_bootstrap",
                "correlation_fetch_plan": [
                    {
                        "join_id": "s4_bootstrap_waf",
                        "asset_id": "asset-waf-prod-01",
                    },
                    {
                        "join_id": "waf_to_web_access_by_ip",
                        "asset_id": "asset-secweaver-gateway-access",
                    },
                    {
                        "join_id": "waf_to_host_exec_direct",
                        "asset_id": "asset-secweaver-host-exec",
                    },
                ],
                "executed_asset_ids": [
                    "asset-waf-prod-01",
                    "asset-secweaver-gateway-access",
                    "asset-secweaver-host-exec",
                ],
                "enriched_params": {
                    "attacker_ip": "192.168.99.16",
                    "target_ip": "192.0.2.91",
                },
            },
        )

        payload = build_evidence_fetch_payload(
            {
                "time_start": "2026-07-10T17:42:10+08:00",
                "time_end": "2026-07-10T17:44:00+08:00",
            },
            asset_ids=["asset-waf-prod-01"],
            scenarios=["S4"],
            anchor_pattern_id="S4_alert_confirmation",
            fetch_live=True,
        )

        fetch_bundle_mock.assert_not_called()
        fetch_s4_mock.assert_called_once()
        self.assertEqual(payload["data_access"]["fetch_strategy"], "s4_gateway_bootstrap+s4_bootstrap")
        self.assertIn("waf_to_web_access_by_ip", {task.get("join_id") for task in payload["correlation_fetch_plan"]})
        self.assertNotIn("trace_chain_appended_assets", payload["data_access"])

    @patch("s4_fetch_bootstrap.fetch_s4_bootstrap")
    @patch("fetch.fetch_bundle_evidence")
    def test_waf_only_attacker_ip_uses_s4_bootstrap_and_skips_uncorrelated_hosts(
        self,
        fetch_bundle_mock,
        fetch_s4_mock,
    ) -> None:
        fetch_s4_mock.return_value = (
            {
                "waf_alert": [
                    {
                        "alert_id": "waf-1",
                        "src_ip": "115.194.3.17",
                        "target_ip": "-",
                    }
                ],
                "web_access_log": [
                    {
                        "evidence_id": "web-1",
                        "src_ip": "115.194.3.17",
                        "target_ip": "-",
                        "upstream_addr": "-",
                        "upstream_status": "-",
                        "status": "480",
                    }
                ],
            },
            {
                "source": "dataasset",
                "fetch_strategy": "s4_bootstrap",
                "correlation_fetch_plan": [
                    {
                        "join_id": "s4_bootstrap_waf",
                        "asset_id": "asset-waf-prod-01",
                        "template_id": "waf_gateway_plugin_by_ip_time",
                        "params": {"src_ip": "115.194.3.17"},
                    },
                    {
                        "join_id": "waf_to_web_access_by_ip",
                        "asset_id": "asset-secweaver-gateway-access",
                    },
                ],
                "executed_asset_ids": [
                    "asset-waf-prod-01",
                    "asset-secweaver-gateway-access",
                ],
                "s4_bootstrap": {
                    "target_ips": [],
                    "host_side_fetch_skipped": True,
                    "host_side_skip_reason": "no_valid_target_ip_from_waf_or_gateway",
                },
                "enriched_params": {
                    "attacker_ip": "115.194.3.17",
                    "src_ip": "115.194.3.17",
                },
            },
        )

        payload = build_evidence_fetch_payload(
            {
                "attacker_ip": "115.194.3.17",
                "time_start": "2026-07-10T00:00:00+08:00",
                "time_end": "2026-07-10T23:59:59+08:00",
            },
            asset_ids=["asset-waf-prod-01"],
            scenarios=["S4"],
            anchor_pattern_id="S4_alert_confirmation",
            fetch_live=True,
        )

        fetch_bundle_mock.assert_not_called()
        fetch_s4_mock.assert_called_once()
        self.assertEqual(payload["data_access"]["fetch_strategy"], "s4_gateway_bootstrap+s4_bootstrap")
        self.assertEqual(
            payload["data_access"]["s4_bootstrap"]["host_side_skip_reason"],
            "no_valid_target_ip_from_waf_or_gateway",
        )
        self.assertNotIn("asset-secweaver-host-exec", payload["fetch_summary"]["executed_asset_ids"])


if __name__ == "__main__":
    unittest.main()
