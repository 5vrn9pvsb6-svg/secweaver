"""Exercise terminal detection through a PTY, without any installation actions."""
import errno
import os
from pathlib import Path
import pty
import select
import subprocess
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallPresentationTests(unittest.TestCase):
    def command(self):
        source = (ROOT / "src/tools/secweaver-agent/packaging/bootstrap-install.sh").read_text()
        function = source[source.index("status_line() {"):source.index("step_begin() {")]
        return ["bash", "-c", 'set -eu; exec 3>&2; NO_COLOR="${NO_COLOR:-}"; ' + function +
                '\nstatus_line OK "completed"; status_line WARN "recovery"; status_line FAIL "rejected"']

    def terminal_output(self, no_color):
        # Open a private PTY so the actual Bash -t check, not an injected flag,
        # decides whether ANSI escapes belong in the output.
        master, slave = pty.openpty()
        output = bytearray()
        try:
            process = subprocess.Popen(self.command(), stdout=slave, stderr=slave,
                                       env={**os.environ, "TERM": "xterm", "NO_COLOR": no_color})
            deadline = time.monotonic() + 5
            # Read before closing the final slave: macOS can discard buffered
            # terminal output at that close, unlike a regular pipe.
            while time.monotonic() < deadline:
                if not select.select([master], [], [], 0.1)[0]:
                    if process.poll() is not None:
                        break
                    continue
                try:
                    data = os.read(master, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not data:
                    break
                output.extend(data)
            if process.poll() is None:
                process.kill()
            self.assertEqual(process.wait(timeout=2), 0)
        finally:
            os.close(slave)
            os.close(master)
        return bytes(output)

    def test_terminal_color_and_no_color(self):
        output = self.terminal_output("")
        for color in (b"\x1b[32m", b"\x1b[33m", b"\x1b[31m"):
            self.assertIn(color, output)
        self.assertNotIn(b"\x1b[", self.terminal_output("1"))

    def test_redirected_output_is_plain(self):
        result = subprocess.run(self.command(), capture_output=True, check=True,
                                env={**os.environ, "TERM": "xterm", "NO_COLOR": ""}, timeout=5)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"\x1b[", result.stderr)
        for label in (b"OK", b"WARN", b"FAIL"):
            self.assertIn(label, result.stderr)
