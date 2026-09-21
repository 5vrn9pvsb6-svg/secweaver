"""Tests for attck-map integration in traceability-analysis."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from attck_trace import (  # noqa: E402
    build_trace_mitre_attack,
    collect_trace_rule_keys,
    resolve_techniques_from_rule_keys,
)


def _cmd_text(ev: dict) -> str:
    cmd = ev.get("command")
    if isinstance(cmd, list):
        return " ".join(str(c) for c in cmd)
    return str(cmd or "")


class AttckTraceTests(unittest.TestCase):
    def test_resolves_policy_and_matched_rules(self) -> None:
        techs = resolve_techniques_from_rule_keys(["webshell_write", "LATERAL-SSH-001"])
        ids = {t["id"] for t in techs}
        self.assertIn("T1505.003", ids)
        self.assertIn("T1021.004", ids)

    def test_91_shaped_evidence_maps_shadow_and_webshell(self) -> None:
        index = {
            "E1": {
                "command": "sh -c echo '<?php system($_GET[c]);?>' > /var/www/uploads/s.phtml",
                "host": "192.0.2.91",
            },
            "E2": {
                "command": "cat /etc/shadow",
                "host": "192.0.2.92",
            },
            "E3": {
                "command": "sshpass -p 'xxx' ssh root@192.0.2.92",
                "host": "192.0.2.91",
            },
        }
        attack_chain = [
            {"stage": "initial_access", "mitre_id": "T1190", "host": "192.0.2.91"},
            {"stage": "execution", "mitre_id": "T1059", "host": "192.0.2.91"},
            {"stage": "lateral_movement", "mitre_id": "T1021.004", "host": "192.0.2.92"},
        ]
        initial = {"vector": "webshell", "host": "192.0.2.91", "correlation_source": "exec_inferred"}
        keys = collect_trace_rule_keys(
            attack_chain=attack_chain,
            initial=initial,
            matched_pattern="web_shell_to_ssh_lateral",
            index=index,
            cmd_text_fn=_cmd_text,
        )
        self.assertIn("webshell_write", keys)
        self.assertIn("sensitive_file_read", keys)
        self.assertIn("LATERAL-SSH-001", keys)

        mitre = build_trace_mitre_attack(
            attack_chain=attack_chain,
            initial=initial,
            matched_pattern="web_shell_to_ssh_lateral",
            index=index,
            cmd_text_fn=_cmd_text,
        )
        ids = set(mitre.get("technique_ids") or [])
        self.assertIn("T1190", ids)
        self.assertIn("T1059", ids)
        self.assertIn("T1021.004", ids)
        self.assertIn("T1505.003", ids)
        self.assertIn("T1003.008", ids)


if __name__ == "__main__":
    unittest.main()
