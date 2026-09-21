#!/usr/bin/env python3
"""Tests for traceability host normalization and exec-inferred entry."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from correlate import (  # noqa: E402
    analyze,
    d1_reverse_lookup_gap,
    find_initial_access_from_exec,
    find_initial_access_from_victim,
    find_lateral_from_exec,
    index_evidence,
    load_json,
)
from host_normalize import (  # noqa: E402
    canonicalize_event_host,
    extract_ssh_lateral_targets,
    inject_registered_hosts,
    normalize_bundles_for_trace,
    remote_execution_context,
    victim_host_from_event,
)

from risk_rules_bridge import load_trace_patterns  # noqa: E402
from traceability_analysis.initial_access import classify_web_vector, find_initial_access  # noqa: E402
from traceability_analysis.execution import find_execution_chain  # noqa: E402

PATTERNS = load_trace_patterns()


class HostNormalizeTests(unittest.TestCase):
    def test_classify_web_vector_distinguishes_sqli_from_webshell(self) -> None:
        patterns = PATTERNS.get("webshell_url_patterns") or []
        self.assertEqual(
            classify_web_vector("/sqli/search.php?q='+UNION+SELECT+1,version(),user()--+-", patterns),
            "web_exploit:sqli",
        )
        self.assertEqual(
            classify_web_vector("/uploads/s.phtml?cmd=id", patterns),
            "webshell",
        )

    def test_victim_host_from_localhost_exec(self) -> None:
        ev = {
            "host_name": "localhost.localdomain",
            "host_ip": "192.0.2.91",
            "__source__": "192.0.2.91",
        }
        self.assertEqual(victim_host_from_event(ev), "192.0.2.91")
        canon = canonicalize_event_host(ev)
        self.assertEqual(canon["host"], "192.0.2.91")

    def test_extract_ssh_lateral_targets(self) -> None:
        text = '["sh","-c","sshpass -p 123456 ssh devops@192.0.2.92 echo ok"]'
        pairs = extract_ssh_lateral_targets(text)
        self.assertTrue(any(ip == "192.0.2.92" for _, ip in pairs))

    def test_remote_execution_stage_records_target_host(self) -> None:
        bundles = {
            "host_exec": [
                {
                    "evidence_id": "exec-remote-1",
                    "host_ip": "192.0.2.91",
                    "timestamp": "2026-07-11T12:35:49+08:00",
                    "command": "sshpass -p redacted ssh devops@192.0.2.92 hostname",
                }
            ]
        }
        index, _ = index_evidence(bundles)

        stages = find_execution_chain("192.0.2.91", index, None, PATTERNS, None)

        self.assertEqual(stages[0]["execution_target_host"], "192.0.2.92")
        self.assertEqual(stages[0]["execution_target_hosts"], ["192.0.2.92"])
        self.assertEqual(stages[0]["execution_remote_user"], "devops")
        self.assertEqual(
            remote_execution_context("ssh devops@192.0.2.92 id", "192.0.2.91")["execution_target_host"],
            "192.0.2.92",
        )

    def test_find_initial_access_from_exec(self) -> None:
        bundles = {
            "host_exec": [
                {
                    "evidence_id": "exec-ws-1",
                    "host_name": "localhost.localdomain",
                    "host_ip": "192.0.2.91",
                    "timestamp": "2026-07-01T17:56:49+08:00",
                    "listener_process": "nginx",
                    "listener_port": "80",
                    "has_tty": False,
                    "tty": "(none)",
                    "command": '["sh","-c","id"]',
                }
            ]
        }
        normalized = normalize_bundles_for_trace(bundles, {"host_ips": {"192.0.2.91": "192.0.2.91"}})
        index, _ = index_evidence(normalized)
        patterns = PATTERNS
        initial = find_initial_access_from_exec(
            index,
            patterns,
            None,
            None,
            {"192.0.2.91": "192.0.2.91"},
        )
        self.assertIsNotNone(initial)
        self.assertEqual(initial["host"], "192.0.2.91")
        self.assertEqual(initial["correlation_source"], "exec_inferred")
        self.assertEqual((initial.get("session_signals") or {}).get("non_interactive"), True)

    def test_find_initial_access_prefers_no_tty_over_earlier_ssh_tty(self) -> None:
        bundles = {
            "host_exec": [
                {
                    "evidence_id": "exec-ssh-ops",
                    "host_ip": "192.0.2.91",
                    "timestamp": "2026-07-01T15:00:00+08:00",
                    "listener_process": "sshd",
                    "listener_port": "22",
                    "has_tty": True,
                    "tty": "pts/0",
                    "command": '["curl","http://127.0.0.1/uploads/s.phtml?c=id"]',
                },
                {
                    "evidence_id": "exec-ws-no-tty",
                    "host_ip": "192.0.2.91",
                    "timestamp": "2026-07-01T15:10:00+08:00",
                    "listener_process": "nginx",
                    "listener_port": "80",
                    "has_tty": False,
                    "tty": "(none)",
                    "command": '["sh","-c","id"]',
                },
            ]
        }
        index, _ = index_evidence(bundles)
        patterns = PATTERNS
        initial = find_initial_access_from_exec(index, patterns, None, None, {"192.0.2.91": "192.0.2.91"})
        self.assertIsNotNone(initial)
        self.assertEqual(initial["evidence_refs"], ["exec-ws-no-tty"])
        self.assertIn("has_tty=false", initial.get("inference_note", ""))

    def test_find_initial_access_from_victim_waf(self) -> None:
        bundles = {
            "waf_alert": [
                {
                    "evidence_id": "waf-v1",
                    "target_ip": "192.0.2.91",
                    "src_ip": '"203.0.113.77',
                    "timestamp": "2026-07-01T15:51:10+08:00",
                    "url": "https://web/uploads/s.phtml",
                }
            ],
            "host_exec": [
                {
                    "evidence_id": "exec-1",
                    "host_ip": "192.0.2.91",
                    "timestamp": "2026-07-01T15:51:21+08:00",
                    "command": '["sh","-c","id"]',
                }
            ],
        }
        index, _ = index_evidence(bundles)
        initial = find_initial_access_from_victim(index, "192.0.2.91", PATTERNS, None, None)
        self.assertIsNotNone(initial)
        self.assertEqual(initial["attacker_ip"], "203.0.113.77")
        self.assertEqual(initial["correlation_source"], "victim_target_ip")

    def test_find_initial_access_from_victim_filters_with_normalized_attacker_ip(self) -> None:
        bundles = {
            "web_access_log": [
                {
                    "evidence_id": "web-quoted-source",
                    "target_ip": "192.0.2.91",
                    "src_ip": '"203.0.113.77',
                    "timestamp": "2026-07-10T13:04:11+08:00",
                    "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
                }
            ]
        }
        index, _ = index_evidence(bundles)
        initial = find_initial_access_from_victim(
            index,
            "192.0.2.91",
            PATTERNS,
            None,
            None,
            attacker_ip="203.0.113.77",
        )
        self.assertIsNotNone(initial)
        self.assertEqual(initial["attacker_ip"], "203.0.113.77")

    def test_find_initial_access_from_victim_builds_full_url_from_http_host(self) -> None:
        bundles = {
            "web_access_log": [
                {
                    "evidence_id": "web-v1",
                    "target_ip": "192.0.2.91",
                    "http_host": "portal.example.com",
                    "src_ip": "203.0.113.77",
                    "timestamp": "2026-07-10T13:04:11+08:00",
                    "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
                }
            ]
        }
        index, _ = index_evidence(bundles)
        initial = find_initial_access_from_victim(index, "192.0.2.91", PATTERNS, None, None)
        self.assertIsNotNone(initial)
        self.assertEqual(
            initial["url"],
            "http://portal.example.com/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
        )
        self.assertIn("http://portal.example.com/cmdi/diag.php", initial.get("inference_note", ""))

    def test_successful_webshell_outranks_blocked_waf_probe(self) -> None:
        bundles = {
            "waf_alert": [
                {
                    "evidence_id": "waf-blocked-env",
                    "target_ip": "192.0.2.91",
                    "src_ip": "218.74.11.194",
                    "timestamp": "2026-07-11T12:34:44+08:00",
                    "url": "https://gateway.example:30443/.env",
                    "action": "block",
                }
            ],
            "web_access_log": [
                {
                    "evidence_id": "web-success-shell",
                    "target_ip": "192.0.2.91",
                    "src_ip": "218.74.11.194",
                    "timestamp": "2026-07-11T12:34:41+08:00",
                    "http_host": "gateway.example:30443",
                    "request_uri": "/webshell/",
                    "status": 200,
                }
            ],
        }
        index, _ = index_evidence(bundles)

        initial = find_initial_access_from_victim(index, "192.0.2.91", PATTERNS, None, None)

        self.assertEqual(initial["evidence_refs"], ["web-success-shell"])
        self.assertEqual(initial["primary_evidence_refs"], ["web-success-shell"])
        self.assertEqual(initial["supporting_evidence_refs"], [])
        self.assertEqual(initial["request_outcome"], "success")
        self.assertEqual(initial["host"], "192.0.2.91")
        self.assertEqual(initial["gateway_host"], "gateway.example:30443")
        self.assertEqual(initial["entry_point_role"], "observed_control_point")
        self.assertEqual(initial["first_compromise_point_status"], "unresolved")

    def test_successful_rce_is_first_compromise_point_not_webshell_landing(self) -> None:
        bundles = {
            "web_access_log": [
                {
                    "evidence_id": "web-shell-landing",
                    "target_ip": "192.0.2.91",
                    "src_ip": "218.74.11.194",
                    "timestamp": "2026-07-11T12:34:41+08:00",
                    "http_host": "gateway.example:30443",
                    "request_uri": "/webshell/",
                    "status": 200,
                },
                {
                    "evidence_id": "web-rce-trigger",
                    "target_ip": "192.0.2.91",
                    "src_ip": "218.74.11.194",
                    "timestamp": "2026-07-11T12:34:41+08:00",
                    "http_host": "gateway.example:30443",
                    "request_uri": "/cmdi/diag.php?tool=ping&host=127.0.0.1;date",
                    "status": 200,
                },
            ]
        }
        index, _ = index_evidence(bundles)

        initial = find_initial_access(
            bundles,
            index,
            "218.74.11.194",
            PATTERNS,
            None,
            None,
            target_ip="192.0.2.91",
        )

        self.assertEqual(
            initial["url"],
            "http://gateway.example:30443/cmdi/diag.php?tool=ping&host=127.0.0.1;date",
        )
        self.assertEqual(initial["vector"], "web_exploit:rce")
        self.assertEqual(initial["primary_evidence_refs"], ["web-rce-trigger"])
        self.assertEqual(initial["entry_point_role"], "compromise_trigger")
        self.assertEqual(initial["first_compromise_point_status"], "supported")
        self.assertEqual(
            initial["first_observed_control_url"],
            "http://gateway.example:30443/webshell/",
        )
        self.assertEqual(initial["first_observed_control_evidence_refs"], ["web-shell-landing"])

    def test_attack_graph_uses_gateway_backend_and_lateral_target(self) -> None:
        payload = {
            "scenarios": ["S2", "S3"],
            "params": {
                "attacker_ip": "218.74.11.194",
                "target_ip": "192.0.2.91",
                "hosts": ["192.0.2.91", "192.0.2.92"],
                "host_ips": {"192.0.2.91": "192.0.2.91", "192.0.2.92": "192.0.2.92"},
                "time_start": "2026-07-11T12:29:41+08:00",
                "time_end": "2026-07-11T12:41:04+08:00",
            },
            "completeness_precheck": {
                "overall_verdict": "partial_traceable",
                "confidence": 0.76,
                "next_skill_blocked": False,
                "data_gaps": [],
            },
            "evidence_bundles": {
                "waf_alert": [
                    {
                        "evidence_id": "waf-blocked-env",
                        "target_ip": "192.0.2.91",
                        "src_ip": "218.74.11.194",
                        "timestamp": "2026-07-11T12:34:44+08:00",
                        "url": "https://gateway.example:30443/.env",
                        "action": "block",
                    }
                ],
                "web_access_log": [
                    {
                        "evidence_id": "web-success-shell",
                        "target_ip": "192.0.2.91",
                        "src_ip": "218.74.11.194",
                        "timestamp": "2026-07-11T12:34:41+08:00",
                        "http_host": "gateway.example:30443",
                        "request_uri": "/webshell/",
                        "status": 200,
                    }
                ],
                "host_exec": [
                    {
                        "evidence_id": "exec-web",
                        "host_ip": "192.0.2.91",
                        "timestamp": "2026-07-11T12:34:50+08:00",
                        "listener_process": "nginx",
                        "listener_port": "80",
                        "has_tty": False,
                        "command": '["sh","-c","id"]',
                    }
                ],
                "ssh_auth": [
                    {
                        "evidence_id": "ssh-accepted",
                        "host_ip": "192.0.2.92",
                        "timestamp": "2026-07-11T12:35:43+08:00",
                        "src_ip": "192.0.2.91",
                        "user": "devops",
                        "result": "Accepted",
                    }
                ],
            },
        }

        result = analyze(payload, PATTERNS)
        edges = {
            (edge.get("from"), edge.get("to"), edge.get("stage"))
            for edge in result["lateral_movement_graph"]["edges"]
        }

        self.assertEqual(result["initial_access"]["host"], "192.0.2.91")
        self.assertEqual(result["initial_access"]["evidence_refs"][0], "web-success-shell")
        self.assertEqual(result["initial_access"]["primary_evidence_refs"], ["web-success-shell"])
        self.assertIn("waf-blocked-env", result["initial_access"]["supporting_evidence_refs"])
        self.assertIn(("attacker", "gateway.example:30443", "initial_access"), edges)
        self.assertIn(("gateway.example:30443", "192.0.2.91", "initial_access"), edges)
        self.assertIn(("192.0.2.91", "192.0.2.92", "lateral_movement"), edges)

    def test_d1_reverse_lookup_gap_when_no_d1(self) -> None:
        index, _ = index_evidence(
            {
                "host_exec": [
                    {
                        "evidence_id": "exec-1",
                        "host_ip": "192.0.2.91",
                        "timestamp": "2026-07-01T15:51:21+08:00",
                    }
                ]
            }
        )
        gap = d1_reverse_lookup_gap("192.0.2.91", index)
        self.assertIsNotNone(gap)
        self.assertIn("192.0.2.91", gap)

    def test_analyze_tigersec_shape_without_waf(self) -> None:
        payload = {
            "scenarios": ["S2", "S3"],
            "params": {
                "seed_hosts": ["192.0.2.91"],
                "hosts": ["192.0.2.91", "192.0.2.92"],
                "host_ips": {"192.0.2.91": "192.0.2.91", "192.0.2.92": "192.0.2.92"},
                "alert_time": "2026-07-01T18:00:06+08:00",
            },
            "completeness_precheck": {
                "overall_verdict": "partial_traceable",
                "confidence": 0.72,
                "next_skill_blocked": False,
                "data_gaps": ["missing:web_access_log"],
            },
            "evidence_bundles": {
                "host_exec": [
                    {
                        "evidence_id": "exec-1",
                        "host_name": "localhost.localdomain",
                        "host_ip": "192.0.2.91",
                        "timestamp": "2026-07-01T17:56:49+08:00",
                        "listener_process": "nginx",
                        "listener_port": "80",
                        "command": '["sh","-c","id"]',
                    },
                    {
                        "evidence_id": "exec-2",
                        "host_name": "localhost.localdomain",
                        "host_ip": "192.0.2.91",
                        "timestamp": "2026-07-01T17:22:50+08:00",
                        "listener_process": "nginx",
                        "listener_port": "80",
                        "command": '["sh","-c","sshpass -p 123456 ssh devops@192.0.2.92 echo"]',
                    },
                ],
                "ssh_auth": [
                    {
                        "evidence_id": "ssh-1",
                        "host_name": "localhost.localdomain",
                        "host_ip": "192.0.2.92",
                        "__source__": "192.0.2.92",
                        "timestamp": "2026-07-01T17:08:00+08:00",
                        "src_ip": "192.0.2.91",
                        "user": "devops",
                        "result": "Failed",
                    }
                ],
            },
        }
        result = analyze(payload, PATTERNS)
        self.assertIsNotNone(result.get("initial_access"))
        self.assertEqual(result["initial_access"]["host"], "192.0.2.91")
        gaps = result.get("data_gaps_impact") or []
        self.assertTrue(any("d1_reverse_lookup" in g for g in gaps))
        exec_hosts = [s for s in result["attack_chain"] if s["stage"] == "execution" and s["host"] == "192.0.2.91"]
        self.assertTrue(exec_hosts)
        lateral = [s for s in result["attack_chain"] if s["stage"] == "lateral_movement"]
        self.assertTrue(any(s.get("host") == "192.0.2.92" for s in lateral))
        self.assertEqual(result.get("matched_pattern"), "web_shell_to_ssh_lateral")

    def test_inject_registered_hosts_for_web01(self) -> None:
        bundles, injected = inject_registered_hosts(
            {"host_exec": []},
            {"hosts": ["192.0.2.5"], "host_ips": {"web-01": "192.0.2.5"}},
        )
        self.assertIn("host-web-01", injected)
        inv = bundles["asset_inventory"]
        self.assertTrue(any(r.get("ip") == "192.0.2.5" for r in inv))
        self.assertTrue(any(r.get("network_id") == "net-prod-web" for r in inv))

    def test_analyze_injects_host_to_cmdb(self) -> None:
        payload = {
            "scenarios": ["S2", "S3"],
            "params": {
                "hosts": ["192.0.2.5"],
                "host_ips": {"192.0.2.5": "192.0.2.5", "web-01": "192.0.2.5"},
                "alert_time": "2026-07-01T18:00:06+08:00",
            },
            "completeness_precheck": {
                "overall_verdict": "partial_traceable",
                "confidence": 0.72,
                "next_skill_blocked": False,
                "data_gaps": [],
            },
            "evidence_bundles": {
                "host_exec": [
                    {
                        "evidence_id": "exec-1",
                        "host_ip": "192.0.2.5",
                        "host": "192.0.2.5",
                        "timestamp": "2026-07-01T17:56:49+08:00",
                        "listener_process": "nginx",
                        "listener_port": "80",
                        "command": '["sh","-c","id"]',
                    }
                ],
            },
        }
        result = analyze(payload, PATTERNS)
        self.assertIn("host-web-01", result["host_registry"]["injected_host_ids"])
        per_join = result["join_coverage"]["per_join"]
        self.assertEqual(per_join.get("host_to_cmdb"), "matched")
        impacted = result["impacted_assets"][0]
        self.assertEqual(impacted.get("host_id"), "host-web-01")
        self.assertEqual(impacted.get("network_id"), "net-prod-web")


if __name__ == "__main__":
    unittest.main()
