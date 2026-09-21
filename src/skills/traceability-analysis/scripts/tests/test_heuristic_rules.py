#!/usr/bin/env python3
"""Tests for heuristic-rules.json loader and config-driven behavior."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from heuristic_rules import (  # noqa: E402
    clear_rules_cache,
    compile_high_risk_exec_rules,
    heuristic_time_window_deltas,
    lateral_join_ids,
    load_heuristic_rules,
    match_verdict_conditions,
    policy_block,
    resolve_verdict_from_policy,
    section,
    ssh_lateral_confirmed,
    ssh_result_from_rules,
)
from source_adapters.tigersec_target_impact import (  # noqa: E402
    classify_high_risk_exec,
    find_post_lateral_target_exec_signals,
)


class HeuristicRulesLoaderTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_rules_cache()

    def test_load_default_rules(self) -> None:
        rules = load_heuristic_rules()
        self.assertEqual(rules.get("version"), "1.0.0")
        self.assertIn("lateral_from_target_exec", lateral_join_ids(rules=rules))

    def test_compile_high_risk_rules(self) -> None:
        compiled = compile_high_risk_exec_rules()
        self.assertGreaterEqual(len(compiled), 5)
        cats = classify_high_risk_exec("cat /etc/shadow")
        self.assertIn("credential_access", cats)

    def test_ssh_result_from_rules(self) -> None:
        self.assertEqual(ssh_result_from_rules({"result": "accepted"}), "accepted")
        self.assertEqual(ssh_result_from_rules({"event_type": "ssh_login_failed"}), "failed")
        self.assertTrue(ssh_lateral_confirmed({"event_type": "ssh_login_success"}))

    def test_custom_rules_change_threshold(self) -> None:
        base = load_heuristic_rules()
        custom = json.loads(json.dumps(base))
        custom["target_exec_lateral"]["min_high_risk_events"] = 99
        custom["target_exec_lateral"]["min_risk_categories"] = 99
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump(custom, tmp)
            path = tmp.name
        clear_rules_cache()
        rules = load_heuristic_rules(path)
        suspected = [
            {
                "stage": "lateral_movement",
                "timestamp": "2026-07-01T17:22:50+08:00",
                "host": "192.0.2.92",
                "source_host": "192.0.2.91",
                "lateral_class": "suspected_lateral",
            }
        ]
        exec_on_92 = [
            {
                "timestamp": "2026-07-01T17:23:05+08:00",
                "host_ip": "192.0.2.92",
                "command_line": "cat /etc/shadow",
                "evidence_id": "x1",
            },
            {
                "timestamp": "2026-07-01T17:23:10+08:00",
                "host_ip": "192.0.2.92",
                "command_line": "sudo -l",
                "evidence_id": "x2",
            },
            {
                "timestamp": "2026-07-01T17:23:15+08:00",
                "host_ip": "192.0.2.92",
                "command_line": "nmap localhost",
                "evidence_id": "x3",
            },
        ]
        default_signals = find_post_lateral_target_exec_signals(exec_on_92, suspected)
        strict_signals = find_post_lateral_target_exec_signals(exec_on_92, suspected, rules=rules)
        self.assertEqual(len(default_signals), 1)
        self.assertEqual(len(strict_signals), 0)
        Path(path).unlink(missing_ok=True)
        clear_rules_cache()

    def test_section_defaults(self) -> None:
        cfg = section("confidence_adjustments")
        self.assertEqual(cfg.get("likely_lateral_boost"), 0.03)

    def test_time_window_from_matrix(self) -> None:
        before, after = heuristic_time_window_deltas("target_exec_lateral")
        self.assertEqual(before, 30)
        self.assertEqual(after, 120)
        cfg = section("target_exec_lateral")
        self.assertEqual(cfg.get("time_window"), "lateral_movement")
        self.assertNotIn("window_after_min", cfg)

    def test_policy_bfs_and_verdict(self) -> None:
        bfs = policy_block("bfs_lateral")
        self.assertEqual(bfs.get("max_hops"), 10)
        verdict = resolve_verdict_from_policy(
            {
                "blocked": False,
                "has_initial": True,
                "has_execution": True,
                "has_lateral": True,
                "has_exec": True,
            }
        )
        self.assertEqual(verdict, "confirmed_intrusion_chain")
        self.assertTrue(
            match_verdict_conditions(
                {"has_initial": True, "has_execution": False, "has_exec": False},
                {"blocked": False, "has_initial": True, "has_execution": False, "has_lateral": False, "has_exec": False},
            )
        )


if __name__ == "__main__":
    unittest.main()
