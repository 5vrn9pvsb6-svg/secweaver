#!/usr/bin/env python3
"""Tests for TigerSec adapter session/TTY heuristics."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ADAPTERS = Path(__file__).resolve().parents[1] / "source_adapters"
if str(ADAPTERS) not in sys.path:
    sys.path.insert(0, str(ADAPTERS.parent))

from source_adapters.tigersec import (  # noqa: E402
    exec_session_signals,
    is_non_interactive_exec,
    is_web_listener_exec,
)


class TigerSecAdapterTests(unittest.TestCase):
    def test_exec_session_signals_webshell_no_tty(self) -> None:
        ev = {"has_tty": False, "tty": "(none)"}
        signals = exec_session_signals(ev)
        self.assertTrue(signals["non_interactive"])
        self.assertTrue(is_non_interactive_exec(ev))

    def test_exec_session_signals_ssh_interactive(self) -> None:
        ev = {"has_tty": True, "tty": "pts/0"}
        signals = exec_session_signals(ev)
        self.assertFalse(signals["non_interactive"])

    def test_is_web_listener_exec_nginx_sh_no_tty(self) -> None:
        ev = {
            "listener_process": "nginx",
            "listener_port": "80",
            "has_tty": False,
            "command": '["sh","-c","id"]',
        }
        self.assertTrue(is_web_listener_exec(ev, []))

    def test_is_web_listener_exec_sshd_interactive_s_phtml_rejected(self) -> None:
        ev = {
            "listener_process": "sshd",
            "listener_port": "22",
            "has_tty": True,
            "tty": "pts/0",
            "command": '["curl","http://127.0.0.1/uploads/s.phtml?c=ls"]',
        }
        self.assertFalse(is_web_listener_exec(ev, []))

    def test_is_web_listener_exec_sshd_indirect_webshell_no_tty(self) -> None:
        ev = {
            "listener_process": "sshd",
            "listener_port": "22",
            "has_tty": False,
            "tty": "(none)",
            "command": '["curl","http://127.0.0.1/uploads/s.phtml?c=id"]',
        }
        self.assertTrue(is_web_listener_exec(ev, []))


if __name__ == "__main__":
    unittest.main()
