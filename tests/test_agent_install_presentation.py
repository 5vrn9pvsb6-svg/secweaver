"""Exercise terminal detection through a PTY, without any installation actions."""
import errno
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
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

    def test_failed_install_shows_specific_rejection_without_echoing_log(self):
        source = (ROOT / "src/tools/secweaver-agent/packaging/bootstrap-install.sh").read_text()
        presentation = source[source.index("status_line() {"):source.index("step_begin() {")]
        failure = source[source.index("show_enrollment_failure() {"):source.index("cleanup() {")]
        # Invoke the real EXIT handler with an isolated log and cleanup stub;
        # no service, package download or enrollment is performed by this test.
        for code, status, text in (
            ("DeviceIdentityConflict", 403, "本机身份已撤销"),
            ("DeviceQuotaExceeded", 403, "企业设备额度已满"),
            ("EnrollmentTokenExhausted", 403, "令牌累计注册次数已用完"),
            ("EnterpriseDisabled", 403, "企业被禁用"),
            ("SubscriptionExpired", 403, "企业订阅已到期"),
            ("AmbiguousReinstall", 409, "匹配多个有效身份"),
            ("RequestReplay", 401, "注册请求重复"),
            ("UnknownRejection", 403, "原因未知"),
        ):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as root:
                log = Path(root) / "install.log"
                log.write_text(f"vendor UPSTREAM_SECRET\n"
                               f"stage=device-enrollment check=authorization url=https://example.test/enroll?token=UPSTREAM_SECRET HTTP={status} reason={code}: UPSTREAM_SECRET\n")
                script = ('set -eu; exec 3>&2; NO_COLOR=1; STEP_NUMBER=3; STEP_TITLE=enrollment; '
                          'UI_OWNER=${BASHPID:-$$}; INSTALL_LOG=$1; cleanup() { :; }; ' +
                          presentation + failure + '\nfinish_install 17')
                result = subprocess.run(["bash", "-c", script, "test", str(log)],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 17, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn(f"reason={code}:", result.stderr)
                self.assertIn(text, result.stderr)
                self.assertIn("Details:", result.stderr)
                self.assertNotIn("UPSTREAM_SECRET", result.stderr)

        # A disappeared diagnostic file must not change the installer failure
        # code or skip cleanup; reporting is subordinate to the EXIT handler.
        with tempfile.TemporaryDirectory() as root:
            missing = Path(root) / "missing.log"
            script = ('set -eu; exec 3>&2; NO_COLOR=1; STEP_NUMBER=3; STEP_TITLE=enrollment; '
                      'UI_OWNER=${BASHPID:-$$}; INSTALL_LOG=$1; cleanup() { echo cleaned >&3; }; ' +
                      presentation + failure + '\nfinish_install 17')
            result = subprocess.run(["bash", "-c", script, "test", str(missing)],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 17, result.stderr)
            self.assertIn("cleaned", result.stderr)
