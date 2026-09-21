#!/usr/bin/env python3
"""Tests for alert-confirmation D2 host matching, timestamps, gateway miss scan."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_ROOT = SKILL_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import confirm  # noqa: E402


def load_catalog() -> dict:
    with (SKILL_ROOT / "attack-types.json").open(encoding="utf-8") as f:
        return json.load(f)


def load_fp() -> dict:
    with (SKILL_ROOT / "fp-patterns.json").open(encoding="utf-8") as f:
        return json.load(f)


class ParseTimestampTests(unittest.TestCase):
    def test_empty_alert_cli_preserves_statistics_and_gateway_scan(self):
        # A missed WAF alert must not suppress an independently observed exploit
        # request; HTTP success alone still cannot prove host execution.
        event = {"evidence_id": "gateway-only", "timestamp": "2026-09-18T00:05:00+08:00",
                 "src_ip": "203.0.113.10", "host": "web.example.test",
                 "url": "/webshell/uploads/s.phtml?c=id", "method": "GET", "status": 200}
        for evidence in ({}, {"web_access_log": [event]}):
            with self.subTest(has_gateway=bool(evidence)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "input.json"
                path.write_text(json.dumps({"primary_alerts": [], "correlated_evidence": evidence,
                    "evidence_bundles": evidence,
                    "params": {"ip_intel_online": False, "time_start": "2026-09-18T00:00:00+08:00",
                               "time_end": "2026-09-18T01:00:00+08:00"},
                    "data_access": {"fetch_mode": "live", "fetch_attempts": [
                        {"asset_id": "waf-test", "asset_type": "waf_alert", "status": "failed"}]}}))
                process = subprocess.run([sys.executable, str(SCRIPTS_ROOT / "confirm.py"), "-i", str(path)],
                                         capture_output=True, text=True, timeout=30)
                self.assertEqual(process.returncode, 0, process.stderr)
                result = json.loads(process.stdout)
                self.assertEqual(result["status"], "no_primary_alerts")
                self.assertEqual(result["results"], [])
                self.assertEqual(result["attack_outcome"], "not_applicable")
                self.assertEqual(result["fetch_summary"]["total_events"], 1 if evidence else 0)
                self.assertEqual(result["fetch_summary"]["failed_fetch_queries"], 1)
                self.assertIn("No primary alerts", result["markdown_report"])
                self.assertNotEqual(result["campaign_success"].get("attack_outcome"), "success_confirmed")
                if evidence:
                    self.assertGreater(result["gateway_miss_scan"]["count"], 0)
                    self.assertIn("gateway-only", json.dumps(result["gateway_miss_scan"]))

    def test_unix_epoch_string(self) -> None:
        ts = confirm.parse_ts("1783258308")
        self.assertIsNotNone(ts)
        self.assertEqual(ts, datetime.fromtimestamp(1783258308))

    def test_event_timestamp_prefers_time_field(self) -> None:
        ev = {"time": "1783258308", "command": ["id"]}
        self.assertEqual(confirm.event_timestamp(ev), datetime.fromtimestamp(1783258308))


class VictimHostMatchingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_catalog()
        self.fp = load_fp()

    def test_d2_matches_target_ip_not_waf_domain(self) -> None:
        alert = {
            "alert_id": "waf-cmdi",
            "timestamp": "2026-07-05T21:30:10+08:00",
            "src_ip": "39.144.124.99",
            "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
            "payload": "/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
            "rule_name": "RCE Command Injection",
            "action": "block",
            "host": "test1.u.yinshendun.com:30443",
        }
        params = {
            "target_ip": "192.0.2.91",
            "time_start": "2026-07-05T21:30:00+08:00",
            "time_end": "2026-07-05T21:40:34+08:00",
        }
        evidence = {
            "host_exec": [
                {
                    "evidence_id": "exec-id",
                    "host_ip": "192.0.2.91",
                    "time": "1783258308",
                    "command": ["id"],
                }
            ]
        }
        precheck = {"overall_verdict": "partial_traceable", "confidence": 0.75}
        result = confirm.confirm_alert(
            alert,
            evidence,
            precheck,
            self.catalog,
            self.fp,
            params=params,
        )
        self.assertEqual(result["attack_outcome"], "success_confirmed")
        self.assertTrue(result["attack_success"])
        self.assertIn("exec-id", result["evidence"]["success_proof"])
        self.assertEqual(result["alert_verdict"], "confirmed_attack")
        self.assertEqual(result["attack_type"], "rce")
        self.assertGreaterEqual(result["confidence"], 0.88)
        self.assertIsNone(result.get("layer1_upgrade"))

    def test_sensitive_config_probe_not_classified_as_rce_from_rule_hint(self) -> None:
        for path in ("/.env", "/.htaccess", "/wp-config.php.bak"):
            with self.subTest(path=path):
                alert = {
                    "alert_id": f"waf-config-{path.rsplit('/', 1)[-1]}",
                    "timestamp": "2026-07-10T17:42:13+08:00",
                    "src_ip": "192.168.99.16",
                    "url": f"https://test1.u.yinshendun.com:30443{path}",
                    "payload": path,
                    "rule_name": "RCE Command Execution",
                    "action": "block",
                }
                result = confirm.confirm_alert(
                    alert,
                    {},
                    {"overall_verdict": "partial_traceable", "confidence": 0.75},
                    self.catalog,
                    self.fp,
                )

                self.assertEqual(result["attack_type"], "sensitive_config_probe")
                self.assertEqual(result["attack_type_label"], "敏感配置/备份文件探测")
                self.assertEqual(result["alert_verdict"], "scanning_or_probe")
                self.assertNotIn("rce_pattern_match", result["matched_rules"])

    def test_command_execution_still_classified_as_rce(self) -> None:
        alert = {
            "alert_id": "waf-cmdi-real",
            "timestamp": "2026-07-10T17:42:19+08:00",
            "src_ip": "192.168.99.16",
            "url": "/webshell/uploads/s.phtml?c=cat+/e??/passw?",
            "payload": "/webshell/uploads/s.phtml?c=cat+/e??/passw?",
            "rule_name": "RCE Command Execution",
            "action": "block",
        }
        result = confirm.confirm_alert(
            alert,
            {},
            {"overall_verdict": "partial_traceable", "confidence": 0.75},
            self.catalog,
            self.fp,
        )

        self.assertEqual(result["attack_type"], "rce")
        self.assertEqual(result["alert_verdict"], "confirmed_attack")

    def test_block_recommendation_requires_ip_profile_review_when_unverified(self) -> None:
        alert = {
            "alert_id": "waf-cmdi-repeat",
            "timestamp": "2026-07-10T17:42:19+08:00",
            "src_ip": "115.194.3.17",
            "url": "/webshell/uploads/s.phtml?c=id",
            "payload": "/webshell/uploads/s.phtml?c=id",
            "rule_name": "RCE Command Execution",
            "action": "block",
        }

        result = confirm.confirm_alert(
            alert,
            {},
            {"overall_verdict": "partial_traceable", "confidence": 0.75},
            self.catalog,
            self.fp,
            repeat_count=3,
        )

        self.assertEqual(result["recommended_action"], "manual_review_30m")
        self.assertEqual(result["ip_action_guard"]["reason"], "ip_profile_missing")
        self.assertTrue(any("NAT" in q for q in result["analyst_questions"]))

    def test_block_recommendation_downgrades_for_mobile_or_nat_like_ip(self) -> None:
        alert = {
            "alert_id": "waf-cmdi-repeat-mobile",
            "timestamp": "2026-07-10T17:42:19+08:00",
            "src_ip": "115.194.3.17",
            "url": "/webshell/uploads/s.phtml?c=id",
            "payload": "/webshell/uploads/s.phtml?c=id",
            "rule_name": "RCE Command Execution",
            "action": "block",
        }
        profile = {
            "ip": "115.194.3.17",
            "scope": "public",
            "online_lookup": {
                "status": "success",
                "provider": "ip-api.com",
                "mobile": True,
                "proxy": False,
            },
            "attributes": ["公网地址", "移动网络", "ISP: China Mobile"],
            "summary": "公网地址；移动网络；ISP: China Mobile",
        }

        result = confirm.confirm_alert(
            alert,
            {},
            {"overall_verdict": "partial_traceable", "confidence": 0.75},
            self.catalog,
            self.fp,
            repeat_count=3,
            attacker_ip_profile=profile,
        )

        self.assertEqual(result["recommended_action"], "manual_review_30m")
        self.assertEqual(result["ip_action_guard"]["reason"], "shared_or_nat_exit_risk")
        self.assertIn("mobile_network_possible_cgnat", result["ip_action_guard"]["risk_indicators"])

    def test_block_recommendation_keeps_block_when_ip_profile_is_verified(self) -> None:
        alert = {
            "alert_id": "waf-cmdi-repeat-verified",
            "timestamp": "2026-07-10T17:42:19+08:00",
            "src_ip": "203.0.113.10",
            "url": "/webshell/uploads/s.phtml?c=id",
            "payload": "/webshell/uploads/s.phtml?c=id",
            "rule_name": "RCE Command Execution",
            "action": "block",
        }
        profile = {
            "ip": "203.0.113.10",
            "scope": "public",
            "online_lookup": {
                "status": "success",
                "provider": "ip-api.com",
                "mobile": False,
                "proxy": False,
                "hosting": True,
            },
            "attributes": ["公网地址", "数据中心/托管", "ASN: AS64500"],
            "summary": "公网地址；数据中心/托管；ASN: AS64500",
        }

        result = confirm.confirm_alert(
            alert,
            {},
            {"overall_verdict": "partial_traceable", "confidence": 0.75},
            self.catalog,
            self.fp,
            repeat_count=3,
            attacker_ip_profile=profile,
        )

        self.assertEqual(result["recommended_action"], "block_ip")
        self.assertFalse(result["ip_action_guard"]["downgraded"])
        self.assertIn("已核验", result["recommended_action_label"])

    def test_triage_only_caps_success_even_when_d2_present(self) -> None:
        alert = {
            "alert_id": "probe",
            "timestamp": "2026-07-05T21:30:10+08:00",
            "src_ip": "39.144.124.99",
            "url": "/.env",
            "payload": "/.env",
            "rule_name": "scanner",
            "action": "block",
        }
        evidence = {
            "host_exec": [
                {
                    "evidence_id": "exec-mem",
                    "host_ip": "192.0.2.91",
                    "timestamp": "2026-07-05T21:31:00+08:00",
                    "command": ["echo", "MEM_OK"],
                }
            ]
        }
        precheck = {"overall_verdict": "alert_triage_only", "confidence": 0.5}
        result = confirm.confirm_alert(
            alert,
            evidence,
            precheck,
            self.catalog,
            self.fp,
            params={"target_ip": "192.0.2.91"},
        )
        self.assertEqual(result["confirmation_mode"], "triage_only")
        self.assertEqual(result["attack_outcome"], "success_unknown")
        self.assertFalse(result["attack_success"])
        self.assertLessEqual(result["confidence"], 0.5)

    def test_d2_success_requires_matching_success_web_context_when_access_logs_exist(self) -> None:
        alert = {
            "alert_id": "waf-pass-sqli",
            "timestamp": "2026-07-06T13:49:16+08:00",
            "src_ip": "192.168.99.61",
            "target_ip": "192.0.2.91",
            "url": "/sqli/search.php?q='+UNION+SELECT+1,version(),user()--+-",
            "payload": "/sqli/search.php?q='+UNION+SELECT+1,version(),user()--+-",
            "rule_name": "SQL Injection",
            "action": "pass",
        }
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-sqli",
                    "src_ip": "192.168.99.61",
                    "target_ip": "192.0.2.91",
                    "timestamp": "2026-07-06T13:49:19+08:00",
                    "url": "/sqli/search.php?q='+UNION+SELECT+1,version(),user()--+-",
                    "status": 200,
                    "upstream_status": 200,
                },
                {
                    "evidence_id": "web-cmdi",
                    "src_ip": "192.168.99.61",
                    "target_ip": "192.0.2.91",
                    "timestamp": "2026-07-06T13:49:31+08:00",
                    "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;echo+L2V0Yy9wYXNzd2Q=|base64+-d|xargs+cat",
                    "status": 200,
                    "upstream_status": 200,
                },
            ],
            "host_exec": [
                {
                    "evidence_id": "exec-cmdi",
                    "host_ip": "192.0.2.91",
                    "timestamp": "2026-07-06T13:49:31+08:00",
                    "command_line": "sh -c echo L2V0Yy9wYXNzd2Q=|base64 -d|xargs cat",
                }
            ],
        }
        result = confirm.confirm_alert(alert, evidence, None, self.catalog, self.fp)
        self.assertEqual(result["attack_outcome"], "attempt_failed")
        self.assertFalse(result["attack_success"])
        self.assertEqual(result["alert_success"]["evidence_refs"], [])
        self.assertEqual(result["src_ip"], "192.168.99.61")
        self.assertEqual(result["target_ip"], "192.0.2.91")

    def test_webshell_demo_bridges_successful_upstream_to_d2_evidence(self) -> None:
        repo_root = SKILL_ROOT.parents[2]
        fixture_path = repo_root / "examples" / "alert-confirmation" / "s4-webshell-attack-success.json"
        payload = json.loads(fixture_path.read_text(encoding="utf-8"))

        result = confirm.confirm_alert(
            payload["primary_alerts"][0],
            payload["correlated_evidence"],
            payload["completeness_precheck"],
            self.catalog,
            self.fp,
            scenario=payload["scenario"],
            params=payload["params"],
        )

        self.assertTrue(result["attack_success"])
        self.assertEqual(result["attack_outcome"], "success_confirmed")
        self.assertEqual(
            result["evidence"]["success_proof"],
            ["exec-101", "connect-101", "file-101"],
        )

    def test_host_file_op_file_paths_confirm_matching_path_traversal(self) -> None:
        alert = {
            "alert_id": "waf-lfi-pass",
            "timestamp": "2026-07-06T13:49:19+08:00",
            "src_ip": "192.168.99.61",
            "target_ip": "192.0.2.91",
            "url": "/sqli/page.php?tpl=../../../../../etc/passwd",
            "payload": "/sqli/page.php?tpl=../../../../../etc/passwd",
            "rule_name": "Path Traversal",
            "action": "pass",
        }
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-lfi",
                    "src_ip": "192.168.99.61",
                    "target_ip": "192.0.2.91",
                    "timestamp": "2026-07-06T13:49:19+08:00",
                    "url": "/sqli/page.php?tpl=../../../../../etc/passwd",
                    "status": 200,
                    "upstream_status": 200,
                }
            ],
            "host_file_op": [
                {
                    "evidence_id": "file-passwd",
                    "host_ip": "192.0.2.91",
                    "timestamp": "2026-07-06T13:49:20+08:00",
                    "file_action": "read_sensitive_file",
                    "file_paths": "[\"/etc/passwd\"]",
                }
            ],
        }
        result = confirm.confirm_alert(alert, evidence, None, self.catalog, self.fp)
        self.assertEqual(result["attack_outcome"], "success_confirmed")
        self.assertIn("file-passwd", result["evidence"]["success_proof"])

    def test_analyze_separates_campaign_success_from_alert_success(self) -> None:
        payload = {
            "batch_mode": True,
            "params": {
                "time_start": "2026-07-06T13:49:00+08:00",
                "time_end": "2026-07-06T13:50:00+08:00",
                "target_ip": "192.0.2.91",
            },
            "completeness_precheck": {"overall_verdict": "partial_traceable", "confidence": 0.75},
            "primary_alerts": [
                {
                    "alert_id": "waf-env-block",
                    "timestamp": "2026-07-06T13:49:13+08:00",
                    "src_ip": "192.168.99.61",
                    "target_ip": "192.0.2.91",
                    "url": "/.env",
                    "payload": "/.env",
                    "rule_name": "scanner",
                    "action": "block",
                }
            ],
            "correlated_evidence": {
                "web_access_log": [
                    {
                        "evidence_id": "web-env-403",
                        "src_ip": "192.168.99.61",
                        "target_ip": "-",
                        "timestamp": "2026-07-06T13:49:14+08:00",
                        "url": "/.env",
                        "status": 403,
                    },
                    {
                        "evidence_id": "web-cmdi-passwd",
                        "src_ip": "192.168.99.61",
                        "target_ip": "192.0.2.91",
                        "timestamp": "2026-07-06T13:49:31+08:00",
                        "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;echo+L2V0Yy9wYXNzd2Q=|base64+-d|xargs+cat",
                        "status": 200,
                    },
                ],
                "host_exec": [
                    {
                        "evidence_id": "exec-cmdi-passwd",
                        "host_ip": "192.0.2.91",
                        "timestamp": "2026-07-06T13:49:31+08:00",
                        "command_line": "sh -c echo L2V0Yy9wYXNzd2Q=|base64 -d|xargs cat",
                    }
                ],
            },
        }
        result = confirm.analyze(payload, self.catalog, self.fp)
        item = result["results"][0]
        self.assertFalse(item["alert_success"]["attack_success"])
        self.assertNotEqual(item["attack_outcome"], "success_confirmed")
        self.assertTrue(result["campaign_success"]["attack_success"])
        self.assertIn("192.168.99.61", result["batch_summary"]["top_ips"])

    def test_campaign_success_skips_uncorrelated_d2_without_gateway_upstream(self) -> None:
        payload = {
            "batch_mode": True,
            "params": {
                "time_start": "2026-07-10T00:00:00+08:00",
                "time_end": "2026-07-10T23:59:59+08:00",
                "attacker_ip": "115.194.3.17",
            },
            "primary_alerts": [
                {
                    "alert_id": "waf-traversal-block",
                    "timestamp": "2026-07-10T17:50:00+08:00",
                    "src_ip": "115.194.3.17",
                    "url": "/..;/actuator/env",
                    "payload": "/..;/actuator/env",
                    "rule_name": "目录遍历尝试",
                    "action": "block",
                }
            ],
            "correlated_evidence": {
                "web_access_log": [
                    {
                        "evidence_id": "web-no-upstream",
                        "src_ip": "115.194.3.17",
                        "target_ip": "-",
                        "upstream_addr": "-",
                        "upstream_status": "-",
                        "timestamp": "2026-07-10T17:50:02+08:00",
                        "url": "/..;/actuator/env",
                        "status": 480,
                    }
                ],
                "host_exec": [
                    {
                        "evidence_id": "exec-broad-window",
                        "host_ip": "192.0.2.91",
                        "timestamp": "2026-07-10T17:50:10+08:00",
                        "command_line": "sh -c cat /etc/passwd",
                    }
                ],
            },
        }

        result = confirm.analyze(payload, self.catalog, self.fp)

        self.assertFalse(result["campaign_success"]["attack_success"])
        self.assertEqual(result["campaign_success"]["attack_outcome"], "success_unknown")
        self.assertEqual(
            result["campaign_success"]["attribution"]["d2_correlation"],
            "uncorrelated",
        )
        self.assertEqual(
            result["campaign_success"]["attribution"]["reason"],
            "no_gateway_upstream_target",
        )
        self.assertEqual(result["campaign_success"]["uncorrelated_d2_count"], 1)
        self.assertIn("exec-broad-window", result["campaign_success"]["uncorrelated_d2_refs"])

    def test_waf_alert_without_gateway_log_requests_data_gap(self) -> None:
        alert = {
            "alert_id": "waf-no-gateway",
            "timestamp": "2026-07-10T17:50:00+08:00",
            "src_ip": "115.194.3.17",
            "url": "/..;/actuator/env",
            "payload": "/..;/actuator/env",
            "rule_name": "目录遍历尝试",
            "action": "block",
        }

        result = confirm.confirm_alert(alert, {}, None, self.catalog, self.fp)

        coverage = result["gateway_access_coverage"]
        self.assertEqual(coverage["status"], "missing")
        self.assertEqual(coverage["reason"], "gateway_log_missing")
        self.assertIn("需补充网关访问日志", " ".join(result["data_gaps_impact"]))
        self.assertTrue(any("网关访问日志" in q for q in result["analyst_questions"]))

    def test_waf_alert_with_matching_gateway_log_has_coverage(self) -> None:
        alert = {
            "alert_id": "waf-with-gateway",
            "timestamp": "2026-07-10T17:50:00+08:00",
            "src_ip": "115.194.3.17",
            "url": "/..;/actuator/env",
            "payload": "/..;/actuator/env",
            "rule_name": "目录遍历尝试",
            "action": "block",
        }
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-covered",
                    "timestamp": "2026-07-10T17:50:01+08:00",
                    "src_ip": "115.194.3.17",
                    "url": "/..;/actuator/env",
                    "method": "GET",
                    "status": 403,
                }
            ]
        }

        result = confirm.confirm_alert(alert, evidence, None, self.catalog, self.fp)

        coverage = result["gateway_access_coverage"]
        self.assertEqual(coverage["status"], "matched")
        self.assertIn("web-covered", coverage["evidence_refs"])
        self.assertFalse(any("需补充网关访问日志" in gap for gap in result["data_gaps_impact"]))

    def test_waf_full_url_request_json_method_matches_gateway_path(self) -> None:
        alert = {
            "alert_id": "waf-upload",
            "timestamp": "2026-07-11T12:34:47+08:00",
            "src_ip": "218.74.11.194",
            "url": "https://test1.u.yinshendun.com:30443/webshell/upload.php",
            "request": json.dumps({"method": "POST", "body": "ignored"}),
            "payload": "<?php phpinfo();?>",
            "rule_name": "POST危险文件上传",
            "action": "block",
        }
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-upload-covered",
                    "timestamp": "2026-07-11T12:34:50+08:00",
                    "src_ip": "218.74.11.194",
                    "url": "/webshell/upload.php",
                    "method": "POST",
                    "status": 403,
                }
            ]
        }

        result = confirm.confirm_alert(alert, evidence, None, self.catalog, self.fp)

        coverage = result["gateway_access_coverage"]
        self.assertEqual(coverage["status"], "matched")
        self.assertIn("web-upload-covered", coverage["evidence_refs"])
        self.assertEqual(result["method"], "POST")
        self.assertFalse(any("需补齐或核对网关 access log 字段" in gap for gap in result["data_gaps_impact"]))

    def test_gateway_source_ip_with_csv_quote_still_matches_waf(self) -> None:
        alert = {
            "alert_id": "waf-quoted-source",
            "timestamp": "2026-08-20T14:52:11+08:00",
            "src_ip": "39.144.124.34",
            "url": "/webshell/uploads/s.phtml?c=id",
            "payload": "/webshell/uploads/s.phtml?c=id",
            "rule_name": "WebShell",
            "action": "block",
        }
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-quoted-source",
                    "timestamp": "2026-08-20T14:52:11+08:00",
                    "src_ip": '"39.144.124.34',
                    "url": "/webshell/uploads/s.phtml?c=id",
                    "method": "GET",
                    "status": 200,
                }
            ]
        }

        result = confirm.confirm_alert(alert, evidence, None, self.catalog, self.fp)

        coverage = result["gateway_access_coverage"]
        self.assertEqual(coverage["reason"], "gateway_log_matched")
        self.assertIn("web-quoted-source", coverage["evidence_refs"])

    def test_markdown_reports_gateway_log_gap(self) -> None:
        payload = {
            "batch_mode": True,
            "params": {
                "time_start": "2026-07-10T17:49:00+08:00",
                "time_end": "2026-07-10T17:51:00+08:00",
            },
            "primary_alerts": [
                {
                    "alert_id": "waf-no-gateway",
                    "timestamp": "2026-07-10T17:50:00+08:00",
                    "src_ip": "115.194.3.17",
                    "url": "/..;/actuator/env",
                    "payload": "/..;/actuator/env",
                    "rule_name": "目录遍历尝试",
                    "action": "block",
                }
            ],
            "correlated_evidence": {},
        }

        result = confirm.analyze(payload, self.catalog, self.fp)
        report = confirm.markdown_report(result)

        self.assertEqual(result["batch_summary"]["gateway_log_missing_count"], 1)
        self.assertIn("WAF 告警缺少网关数据", report)
        self.assertIn("需补充网关日志的 WAF 告警", report)

    def test_markdown_distinguishes_populated_gateway_from_unmatched_request(self) -> None:
        payload = {
            "batch_mode": True,
            "params": {
                "time_start": "2026-07-10T17:49:00+08:00",
                "time_end": "2026-07-10T17:51:00+08:00",
            },
            "primary_alerts": [
                {
                    "alert_id": "waf-unmatched-gateway",
                    "timestamp": "2026-07-10T17:50:00+08:00",
                    "src_ip": "115.194.3.17",
                    "url": "/.env",
                    "payload": "/.env",
                    "rule_name": "配置文件探测",
                    "action": "block",
                }
            ],
            "correlated_evidence": {
                "web_access_log": [
                    {
                        "evidence_id": "web-unrelated-source",
                        "timestamp": "2026-07-10T17:50:01+08:00",
                        "src_ip": "107.172.89.112",
                        "url": "/",
                        "method": "GET",
                        "status": 480,
                    }
                ]
            },
        }

        result = confirm.analyze(payload, self.catalog, self.fp)
        report = confirm.markdown_report(result)

        self.assertEqual(result["batch_summary"]["gateway_log_missing_count"], 0)
        self.assertEqual(result["batch_summary"]["gateway_log_unmatched_count"], 1)
        self.assertIn("网关资产有数据但未匹配到对应请求", report)
        self.assertIn("网关资产有数据但未匹配到 WAF 请求", report)
        self.assertNotIn("需补充网关日志的 WAF 告警", report)

class GatewayMissScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_catalog()

    def test_detects_cmdi_without_waf_alert(self) -> None:
        alerts = [
            {
                "alert_id": "waf-env-only",
                "timestamp": "2026-07-05T21:30:10+08:00",
                "src_ip": "39.144.124.99",
                "url": "/.env",
                "payload": "/.env",
                "action": "block",
            }
        ]
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-cmdi-1",
                    "src_ip": "39.144.124.99",
                    "timestamp": "2026-07-05T21:31:00+08:00",
                    "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
                    "status": 200,
                },
                {
                    "evidence_id": "web-env",
                    "src_ip": "39.144.124.99",
                    "timestamp": "2026-07-05T21:30:11+08:00",
                    "url": "/.env",
                    "status": 403,
                },
            ]
        }
        params = {
            "time_start": "2026-07-05T21:30:00+08:00",
            "time_end": "2026-07-05T21:40:34+08:00",
        }
        scan = confirm.scan_gateway_misses(alerts, evidence, self.catalog, params=params)
        self.assertGreaterEqual(scan["count"], 1)
        refs = [item["evidence_ref"] for item in scan["items"]]
        self.assertIn("web-cmdi-1", refs)
        item = next(i for i in scan["items"] if i["evidence_ref"] == "web-cmdi-1")
        self.assertIn(item["severity"], {"high", "critical"})

    def test_gateway_miss_normalizes_quoted_source_ip(self) -> None:
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-quoted-miss",
                    "src_ip": '"39.144.124.99',
                    "timestamp": "2026-07-05T21:31:00+08:00",
                    "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
                    "status": 200,
                }
            ]
        }
        scan = confirm.scan_gateway_misses(
            [],
            evidence,
            self.catalog,
            params={
                "time_start": "2026-07-05T21:30:00+08:00",
                "time_end": "2026-07-05T21:40:34+08:00",
            },
        )

        self.assertEqual(scan["count"], 1)
        self.assertEqual(scan["items"][0]["src_ip"], "39.144.124.99")

    def test_waf_block_does_not_suppress_successful_upload_get(self) -> None:
        alerts = [
            {
                "alert_id": "waf-upload-block",
                "timestamp": "2026-07-06T07:25:31+08:00",
                "src_ip": "115.193.81.185",
                "url": "/exfil/upload.php",
                "payload": "/exfil/upload.php",
                "action": "block",
                "request.method": "POST",
            }
        ]
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-block-ok",
                    "src_ip": "115.193.81.185",
                    "timestamp": "2026-07-06T07:25:33+08:00",
                    "url": "/exfil/upload.php",
                    "request_uri": "/exfil/upload.php",
                    "method": "POST",
                    "status": 403,
                },
                {
                    "evidence_id": "web-mem-c2",
                    "src_ip": "115.193.81.185",
                    "timestamp": "2026-07-06T07:25:38+08:00",
                    "url": "/exfil/upload.php",
                    "request_uri": "/exfil/upload.php",
                    "method": "GET",
                    "status": 302,
                },
                {
                    "evidence_id": "web-phtml-post",
                    "src_ip": "115.193.81.185",
                    "timestamp": "2026-07-06T07:25:33+08:00",
                    "url": "/exfil/upload.php",
                    "method": "POST",
                    "status": 302,
                },
                {
                    "evidence_id": "web-phtml",
                    "src_ip": "115.193.81.185",
                    "timestamp": "2026-07-06T07:25:33+08:00",
                    "url": "/exfil/uploads/test.phtml",
                    "status": 200,
                },
            ]
        }
        params = {
            "time_start": "2026-07-06T07:25:00+08:00",
            "time_end": "2026-07-06T07:27:34+08:00",
        }
        scan = confirm.scan_gateway_misses(alerts, evidence, self.catalog, params=params)
        refs = [item["evidence_ref"] for item in scan["items"]]
        self.assertNotIn("web-block-ok", refs)
        self.assertIn("web-mem-c2", refs)
        self.assertIn("web-phtml", refs)
        mem_item = next(i for i in scan["items"] if i["evidence_ref"] == "web-mem-c2")
        self.assertEqual(mem_item["reason"], "waf_partial_block_same_path")
        bypass = [i for i in scan["items"] if i.get("reason") == "waf_block_bypass"]
        self.assertFalse(bypass)

    def test_waf_block_bypass_requires_tight_method_match(self) -> None:
        alerts = [
            {
                "alert_id": "waf-get-block",
                "timestamp": "2026-07-06T07:25:31+08:00",
                "src_ip": "10.0.0.1",
                "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
                "action": "block",
                "request.method": "GET",
            }
        ]
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-bypass",
                    "src_ip": "10.0.0.1",
                    "timestamp": "2026-07-06T07:25:32+08:00",
                    "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
                    "method": "GET",
                    "status": 200,
                }
            ]
        }
        scan = confirm.scan_gateway_misses(
            alerts,
            evidence,
            self.catalog,
            params={
                "time_start": "2026-07-06T07:25:00+08:00",
                "time_end": "2026-07-06T07:27:34+08:00",
            },
        )
        item = scan["items"][0]
        self.assertEqual(item["evidence_ref"], "web-bypass")
        self.assertEqual(item["reason"], "waf_block_bypass")

    def test_reports_cmdi_date_probe_as_medium_miss(self) -> None:
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-date-noise",
                    "src_ip": "10.0.0.1",
                    "timestamp": "2026-07-06T07:25:28+08:00",
                    "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;date",
                    "status": 200,
                },
                {
                    "evidence_id": "web-cmdi-id",
                    "src_ip": "10.0.0.1",
                    "timestamp": "2026-07-06T07:25:28+08:00",
                    "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;id",
                    "status": 200,
                },
            ]
        }
        scan = confirm.scan_gateway_misses(
            [],
            evidence,
            self.catalog,
            params={
                "time_start": "2026-07-06T07:25:00+08:00",
                "time_end": "2026-07-06T07:27:34+08:00",
            },
        )
        refs = [item["evidence_ref"] for item in scan["items"]]
        self.assertIn("web-date-noise", refs)
        self.assertIn("web-cmdi-id", refs)
        date_item = next(item for item in scan["items"] if item["evidence_ref"] == "web-date-noise")
        self.assertEqual(date_item["severity"], "medium")

    def test_detects_recon_paths_without_waf_alert(self) -> None:
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-admin",
                    "src_ip": "10.0.0.1",
                    "timestamp": "2026-07-06T07:25:28+08:00",
                    "url": "/admin",
                    "status": 404,
                }
            ]
        }
        scan = confirm.scan_gateway_misses(
            [],
            evidence,
            self.catalog,
            params={
                "time_start": "2026-07-06T07:25:00+08:00",
                "time_end": "2026-07-06T07:27:34+08:00",
            },
        )
        item = next(i for i in scan["items"] if i["evidence_ref"] == "web-admin")
        self.assertEqual(item["severity"], "low")

    def test_detects_sqli_and_double_encoded_lfi_without_waf_alert(self) -> None:
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-sqli-union",
                    "src_ip": "10.0.0.1",
                    "timestamp": "2026-07-06T07:25:28+08:00",
                    "url": "/sqli/search.php?q='+UNION+SELECT+id,card_number,cvv+FROM+payment_cards--+-",
                    "status": 200,
                },
                {
                    "evidence_id": "web-lfi-double",
                    "src_ip": "10.0.0.1",
                    "timestamp": "2026-07-06T07:25:29+08:00",
                    "url": "/sqli/page.php?tpl=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                    "status": 200,
                },
            ]
        }
        scan = confirm.scan_gateway_misses(
            [],
            evidence,
            self.catalog,
            params={
                "time_start": "2026-07-06T07:25:00+08:00",
                "time_end": "2026-07-06T07:27:34+08:00",
            },
        )
        refs = [item["evidence_ref"] for item in scan["items"]]
        self.assertIn("web-sqli-union", refs)
        self.assertIn("web-lfi-double", refs)
        self.assertGreaterEqual(scan["summary"]["by_severity"].get("critical", 0), 1)

    def test_scanning_or_probe_gets_gateway_hint(self) -> None:
        catalog = self.catalog
        fp = load_fp()
        alert = {
            "alert_id": "env-scan",
            "timestamp": "2026-07-05T21:30:10+08:00",
            "src_ip": "39.144.124.99",
            "url": "/.env",
            "payload": "/.env",
            "rule_name": "scanner",
            "action": "block",
        }
        evidence = {
            "web_access_log": [
                {
                    "evidence_id": "web-cmdi",
                    "src_ip": "39.144.124.99",
                    "timestamp": "2026-07-05T21:31:00+08:00",
                    "url": "/cmdi/diag.php?tool=ping&host=127.0.0.1;whoami",
                    "status": 200,
                    "upstream_status": 200,
                    "bytes_sent": 800,
                }
            ],
            "host_exec": [],
        }
        params = {
            "time_start": "2026-07-05T21:30:00+08:00",
            "time_end": "2026-07-05T21:40:34+08:00",
        }
        result = confirm.confirm_alert(
            alert,
            evidence,
            None,
            catalog,
            fp,
            params=params,
            gateway_miss_scan=confirm.scan_gateway_misses([alert], evidence, catalog, params=params),
        )
        self.assertEqual(result["alert_verdict"], "confirmed_attack")
        self.assertEqual(result["attack_type"], "sensitive_config_probe")
        hint = result.get("gateway_success_hint")
        self.assertIsNone(hint)

    def test_markdown_names_per_alert_success_count(self) -> None:
        report = confirm.markdown_report(
            {
                "batch_summary": {
                    "total": 1,
                    "confirmed_attack": 1,
                    "success_confirmed": 0,
                    "per_alert_success_confirmed": 0,
                },
                "campaign_success": {
                    "attack_outcome": "success_confirmed",
                    "recommended_action": "escalate_investigate",
                },
                "results": [],
            }
        )

        self.assertIn("单告警成功确认数", report)
        self.assertNotIn("**攻击成功**", report)
        self.assertIn("活动级成功", report)

    def test_markdown_prints_ip_profile_fields_and_sources(self) -> None:
        report = confirm.markdown_report(
            {
                "batch_summary": {
                    "total": 1,
                    "confirmed_attack": 1,
                    "success_confirmed": 0,
                    "per_alert_success_confirmed": 0,
                },
                "campaign_success": {
                    "attack_outcome": "blocked",
                    "recommended_action": "block_ip",
                },
                "attacker_ip_profile": {
                    "ip": "115.194.3.17",
                    "scope": "public",
                    "evidence_geo": {
                        "event_count": 3,
                        "country": "中国",
                        "province": "浙江省",
                        "city": "杭州市",
                        "source_bundles": ["waf_alert", "web_access_log"],
                        "evidence_refs": ["waf-1", "web-1"],
                    },
                    "online_lookup": {
                        "status": "success",
                        "provider": "ipwho.is",
                        "query": "115.194.3.17",
                        "isp": "Chinanet",
                        "asn": "AS4134",
                        "as": "AS4134 CHINANET BACKBONE",
                        "mobile": False,
                        "proxy": False,
                        "hosting": False,
                    },
                    "threat_intel": {
                        "virustotal": {
                            "status": "success",
                            "provider": "virustotal",
                            "query": "115.194.3.17",
                            "asn": "AS4134",
                            "as_owner": "Chinanet",
                            "network": "115.192.0.0/13",
                            "reputation": 0,
                            "last_analysis_stats": {"malicious": 1, "suspicious": 2},
                            "tags": ["scanner"],
                        }
                    },
                    "attributes": ["公网地址", "ISP: Chinanet", "ASN: AS4134"],
                },
                "results": [],
            }
        )

        self.assertIn("攻击源 IP 属性", report)
        self.assertIn("日志证据来源", report)
        self.assertIn("bundles=waf_alert, web_access_log", report)
        self.assertIn("在线情报来源", report)
        self.assertIn("provider=ipwho.is", report)
        self.assertIn("mobile=false; proxy=false; hosting=false", report)
        self.assertIn("VirusTotal 信息", report)
        self.assertIn("malicious=1; suspicious=2", report)
        self.assertIn("network=115.192.0.0/13", report)

    def test_markdown_tells_user_to_configure_virustotal_key(self) -> None:
        report = confirm.markdown_report(
            {
                "batch_summary": {
                    "total": 1,
                    "confirmed_attack": 1,
                    "success_confirmed": 0,
                    "per_alert_success_confirmed": 0,
                },
                "campaign_success": {
                    "attack_outcome": "blocked",
                    "recommended_action": "manual_review_30m",
                },
                "attacker_ip_profile": {
                    "ip": "115.194.3.17",
                    "scope": "public",
                    "evidence_geo": {
                        "event_count": 1,
                        "country": "中国",
                        "province": "浙江省",
                        "city": "杭州市",
                        "source_bundles": ["waf_alert"],
                        "evidence_refs": ["waf-1"],
                    },
                    "online_lookup": {
                        "status": "success",
                        "provider": "ipwho.is",
                        "query": "115.194.3.17",
                        "isp": "Chinanet",
                        "asn": "AS4134",
                    },
                    "threat_intel": {
                        "virustotal": {
                            "status": "config_missing",
                            "provider": "virustotal",
                            "query": "115.194.3.17",
                            "message": "secret not found",
                            "action_required": "configure_virustotal_api_key",
                            "action_required_label": "请配置 VirusTotal API Key：可在运行参数传 virustotal_api_key/vt_api_key，或设置环境变量 VIRUSTOTAL_API_KEY/VT_API_KEY。",
                        }
                    },
                    "attributes": ["公网地址", "VirusTotal 未配置 API Key（仅日志地理）"],
                },
                "results": [],
            }
        )

        self.assertIn("VirusTotal 信息", report)
        self.assertIn("status=config_missing", report)
        self.assertIn("VirusTotal 配置提示", report)
        self.assertIn("请配置 VirusTotal API Key", report)
        self.assertIn("message=secret not found", report)


if __name__ == "__main__":
    unittest.main()
