"""Guard host collectors from reintroducing standalone tool directories."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_UPDATE_PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


class TestSecWeaverAgentModules(unittest.TestCase):
    def test_legacy_standalone_tool_dirs_are_removed(self) -> None:
        for relative in ("src/tools/audit-port-execmon", "src/tools/syslog-risk-json"):
            self.assertFalse((REPO_ROOT / relative).exists(), f"{relative} should not be restored")

    def test_collector_packages_live_under_secweaver_agent(self) -> None:
        for relative in (
            "src/tools/secweaver-agent/pkg/auditportexecmon",
            "src/tools/secweaver-agent/pkg/syslogriskjson",
            "src/tools/secweaver-agent/pkg/windowseventlog",
            "src/tools/secweaver-agent/pkg/windowseventlogriskjson",
            "src/tools/secweaver-agent/pkg/windowsprocessexecmon",
			"src/tools/secweaver-agent/pkg/hostprocesssnapshot",
			"src/tools/secweaver-agent/pkg/hoststatesnapshot",
        ):
            self.assertTrue((REPO_ROOT / relative).is_dir(), f"{relative} should contain module source")

    def test_release_package_uses_agent_owned_audit_config(self) -> None:
        script = (REPO_ROOT / "src/tools/secweaver-agent/scripts/package-release.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('"${ROOT_DIR}/audit-port-execmon.example.json"', script)
        self.assertIn('"${ROOT_DIR}/config.windows.example.json"', script)
        self.assertNotIn("../audit-port-execmon", script)

    def test_release_package_publishes_bootstrap_installer(self) -> None:
        script = (REPO_ROOT / "src/tools/secweaver-agent/scripts/package-release.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('packaging/bootstrap-install.sh', script)
        self.assertIn('"${PACKAGE_DIR}/install.sh"', script)
        self.assertIn("BOOTSTRAP_RELEASE_BASE_URL", script)
        self.assertIn("BOOTSTRAP_LOGTAIL_INSTALL_URL", script)
        self.assertIn("readonly EMBEDDED_RELEASE_BASE_URL", script)
        self.assertIn("readonly EMBEDDED_LOGTAIL_ALIUID", script)
        self.assertIn("readonly EMBEDDED_LOGTAIL_REGION", script)
        self.assertIn("64 hexadecimal characters", script)
        self.assertIn("publish-logtail-installer.sh", script)
        self.assertIn("BOOTSTRAP_LICENSE_SERVER_URL must point to a published authorization origin", script)
        self.assertIn("BOOTSTRAP_ENROLLMENT_ID is required", script)
        self.assertIn("BOOTSTRAP_LOGTAIL_ALIUID is required", script)
        self.assertIn("BOOTSTRAP_LOGTAIL_REGION is required", script)
        bootstrap = (REPO_ROOT / "src/tools/secweaver-agent/packaging/bootstrap-install.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("loongcollectord.service", bootstrap)
        self.assertIn("ilogtaild.service", bootstrap)

    def test_release_package_includes_self_managed_es_helper(self) -> None:
        script = (REPO_ROOT / "src/tools/secweaver-agent/scripts/package-release.sh").read_text(
            encoding="utf-8"
        )
        # Both platform archives must carry the executable helper and every file
        # it reads or needs for a source-checkout-free ES setup.
        for expected in (
            'ES_INTEGRATION_SOURCE="${ROOT_DIR}/elasticsearch"',
            '"${ES_INTEGRATION_SOURCE}/init_es.py"',
            '"${ES_INTEGRATION_SOURCE}/index-template.json"',
            '"${ES_INTEGRATION_SOURCE}/filebeat.yml"',
            '"${ROOT_DIR}/docs/self-managed-es.md"',
            '"${ROOT_DIR}/docs/self-managed-es.zh-CN.md"',
            '"${package_root}/elasticsearch"',
        ):
            self.assertIn(expected, script)
        self.assertGreaterEqual(script.count('install_es_integration "${package_root}"'), 2)

    def test_logtail_publisher_generates_pinned_exported_release(self) -> None:
        publisher = REPO_ROOT / "src/tools/secweaver-agent/scripts/publish-logtail-installer.sh"
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "public"
            fake_bin = root / "bin"
            fake_bin.mkdir()
            vendor_installer = root / "vendor-logtail.sh"
            vendor_installer.write_text(
                "#!/usr/bin/env bash\nset -euo pipefail\necho vendor-install\n",
                encoding="utf-8",
            )
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "output=''\n"
                "args=\"$*\"\n"
                "while [[ $# -gt 0 ]]; do\n"
                "  case \"$1\" in\n"
                "    --output) output=\"$2\"; shift 2 ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                "printf '%s\\n' \"$args\" >\"$CURL_ARGS_LOG\"\n"
                "cp \"$FAKE_LOGTAIL_SOURCE\" \"$output\"\n",
                encoding="utf-8",
            )
            fake_curl.chmod(0o755)
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}:{env['PATH']}",
                    "OUTPUT_DIR": str(output_dir),
                    "PUBLIC_BASE_URL": "https://sls-proxy.example.com",
                    "LOGTAIL_REGION": "cn-hangzhou-internet",
                    "FAKE_LOGTAIL_SOURCE": str(vendor_installer),
                    "CURL_ARGS_LOG": str(root / "curl-args.log"),
                }
            )

            result = subprocess.run(
                ["bash", str(publisher)],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(
                "https://logtail-release-cn-hangzhou.oss-cn-hangzhou.aliyuncs.com/linux64/logtail.sh",
                (root / "curl-args.log").read_text(encoding="utf-8"),
            )
            published = output_dir / "install.sh"
            self.assertIn("BOOTSTRAP_LOGTAIL_REGION=cn-hangzhou-internet", (output_dir / "release.env").read_text())
            self.assertNotIn("oss-cn-hangzhou-internet", (root / "curl-args.log").read_text())
            expected_digest = hashlib.sha256(vendor_installer.read_bytes()).hexdigest()
            self.assertEqual(published.read_bytes(), vendor_installer.read_bytes())
            self.assertEqual(
                (output_dir / "install.sh.sha256").read_text(encoding="ascii"),
                f"{expected_digest}  install.sh\n",
            )
            exported = subprocess.run(
                [
                    "bash",
                    "-c",
                    "source \"$1\"; bash -c 'printf \"%s\\n%s\\n\" \"$BOOTSTRAP_LOGTAIL_INSTALL_URL\" \"$BOOTSTRAP_LOGTAIL_INSTALL_SHA256\"'",
                    "--",
                    str(output_dir / "release.env"),
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=True,
            ).stdout.splitlines()
            self.assertEqual(
                exported,
                ["https://sls-proxy.example.com/logtail/install.sh", expected_digest],
            )

    def test_release_package_rejects_missing_logtail_digest_before_build(self) -> None:
        release_script = REPO_ROOT / "src/tools/secweaver-agent/scripts/package-release.sh"
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            env = os.environ.copy()
            env.update(
                {
                    "OUT_DIR": temp_dir,
                    "BOOTSTRAP_RELEASE_BASE_URL": "https://sls-proxy.example.com/secweaver-agent/releases",
                    "BOOTSTRAP_LICENSE_SERVER_URL": "https://sls-proxy.example.com",
                    "BOOTSTRAP_ENROLLMENT_ID": "machine-group-01",
                    "BOOTSTRAP_LOGTAIL_INSTALL_URL": "https://sls-proxy.example.com/logtail/install.sh",
                    "BOOTSTRAP_LOGTAIL_INSTALL_SHA256": "",
                    "BOOTSTRAP_LOGTAIL_ALIUID": "1234567890123456",
                    "BOOTSTRAP_LOGTAIL_REGION": "cn-hangzhou",
                    "ALLOW_DIRTY_RELEASE": "1",
                }
            )

            result = subprocess.run(
                ["bash", str(release_script)],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("64 hexadecimal characters", result.stderr)
            self.assertNotIn("building secweaver-agent", result.stdout)

    def test_bootstrap_release_preserves_explicit_network_selection(self) -> None:
        # Render only installers into a temporary directory. This exercises the
        # production release config without compiling/publishing delivery archives.
        release_script = REPO_ROOT / "src/tools/secweaver-agent/scripts/package-release.sh"
        for supplied, expected in (
            ("", "cn-hangzhou-internet"),
            ("cn-hangzhou", "cn-hangzhou"),
            ("hangzhou", "cn-hangzhou"),
            ("eu-central-1-internet", "eu-central-1-internet"),
        ):
            with self.subTest(region=supplied), TemporaryDirectory(dir="/tmp") as temp_dir:
                env = os.environ.copy()
                env.update({
                    "OUT_DIR": temp_dir,
                    "BOOTSTRAP_ONLY": "1",
                    "ALLOW_DIRTY_RELEASE": "1",
                    "BOOTSTRAP_ENROLLMENT_ID": "machine-group-test",
                    "BOOTSTRAP_LOGTAIL_INSTALL_SHA256": "0" * 64,
                    "BOOTSTRAP_LOGTAIL_ALIUID": "1234567890123456",
                    "BOOTSTRAP_LOGTAIL_REGION": supplied,
                })
                result = subprocess.run(["bash", str(release_script)], cwd=REPO_ROOT,
                                        env=env, text=True, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                generated = (Path(temp_dir) / "packages" / "install.sh").read_text()
                self.assertIn(f"readonly EMBEDDED_LOGTAIL_REGION={expected}\n", generated)
                self.assertIn("stage=logtail-install", generated)

    def test_release_package_allows_unsigned_updates_by_default(self) -> None:
        release_script = REPO_ROOT / "src/tools/secweaver-agent/scripts/package-release.sh"
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            env = os.environ.copy()
            env.update(
                {
                    "OUT_DIR": temp_dir,
                    "BOOTSTRAP_RELEASE_BASE_URL": "https://sls-proxy.example.com/secweaver-agent/releases",
                    "BOOTSTRAP_LICENSE_SERVER_URL": "https://sls-proxy.example.com",
                    "BOOTSTRAP_ENROLLMENT_ID": "machine-group-01",
                    "BOOTSTRAP_LOGTAIL_INSTALL_URL": "https://sls-proxy.example.com/logtail/install.sh",
                    "BOOTSTRAP_LOGTAIL_INSTALL_SHA256": "0" * 64,
                    "BOOTSTRAP_LOGTAIL_ALIUID": "1234567890123456",
                    "BOOTSTRAP_LOGTAIL_REGION": "cn-hangzhou",
                    "UPDATE_SIGNING_PRIVATE_KEY_FILE": "",
                    "ALLOW_DIRTY_RELEASE": "1",
                }
            )

            result = subprocess.run(
                ["bash", str(release_script)],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=120,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            manifest = Path(temp_dir) / "updates" / "stable" / "update-manifest.json"
            self.assertTrue(manifest.is_file())
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(manifest_payload["schema_version"], "1")
            self.assertNotIn("payload", manifest_payload)
            self.assertNotIn("signature", manifest_payload)
            self.assertFalse((manifest.parent / "update-signing-key.pub").exists())
            self.assertIn("wrote unsigned", result.stdout)
            # Inspect the actual Windows archive: a bootstrap alone cannot repair
            # a package that omitted its helper or offline acceptance guide.
            import zipfile
            archives = list((Path(temp_dir) / "packages").glob("*_windows_amd64.zip"))
            self.assertEqual(len(archives), 1)
            with zipfile.ZipFile(archives[0]) as archive:
                names = archive.namelist()
                for required in ("windows-install-common.ps1", "docs/windows-installation.md", "docs/windows-installation.zh-CN.md"):
                    self.assertTrue(any(name.endswith("/" + required) for name in names), required)
            windows_bootstrap = (Path(temp_dir) / "packages" / "install.ps1").read_text()
            self.assertIn('$EmbeddedLogtailMachineGroup = "machine-group-01-windows"', windows_bootstrap)
            self.assertIn('$EmbeddedLogtailAliUid = "1234567890123456"', windows_bootstrap)


    def test_bootstrap_downloads_verifies_and_invokes_package_installer(self) -> None:
        bootstrap = REPO_ROOT / "src/tools/secweaver-agent/packaging/bootstrap-install.sh"
        version = "9.8.7-test"
        package_name = f"secweaver-agent_{version}_linux_amd64"
        enterprise_id = "ABCDEF1234567890"
        enrollment_id = "sw-enroll-test-machine-group-01"

        with TemporaryDirectory(dir="/tmp") as temp_dir:
            root = Path(temp_dir)
            release_dir = root / "releases" / version
            package_root = root / "package" / package_name
            fake_bin = root / "bin"
            release_dir.mkdir(parents=True)
            package_root.mkdir(parents=True)
            fake_bin.mkdir()
            install_record = root / "install-record.txt"
            preflight_record = root / "preflight-record.txt"
            logtail_install_record = root / "logtail-install-record.txt"

            # Relocate privileged paths in this integration fixture; production
            # still uses the standard layout and real systemd lifecycle checks.
            isolated_bootstrap = root / "bootstrap.sh"
            agent_root = root / "agent"
            (agent_root / "etc").mkdir(parents=True)
            init_dir = root / "init"
            init_dir.mkdir()
            isolated_bootstrap.write_text(
                bootstrap.read_text().replace("/opt/secweaver-agent", str(agent_root))
                .replace("/run/lock", str(root / "locks"))
                .replace("/etc/init.d/", str(init_dir) + "/")
                .replace("/usr/local/ilogtail/", str(root / "vendor") + "/"),
                encoding="utf-8",
            )
            for name, text in {
                "timeout": '[[ "$1" != --kill-after=* ]] || shift\nshift\nexec "$@"',
                "flock": "exit 0",
                "pgrep": "exit 1",
                "systemctl": 'case "$1" in cat) [[ "$2" == ilogtaild.service ]];; show) echo ActiveState=inactive;; *) exit 0;; esac',
            }.items():
                path = fake_bin / name
                path.write_text("#!/usr/bin/env bash\n" + text + "\n")
                path.chmod(0o755)

            fake_install = package_root / "install.sh"
            fake_install.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'printf "%s\\n" "$*" >"${BOOTSTRAP_INSTALL_RECORD}"\n',
                # Raw child output belongs only in the private installation log.
                encoding="utf-8",
            )
            fake_install.chmod(0o755)
            fake_install.write_text(fake_install.read_text() + 'echo child-config-noise\nexit "${TEST_INSTALL_EXIT:-0}"\n')

            fake_agent = fake_bin / "secweaver-agent"
            fake_agent.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'printf "%s\\n" "$*" >"${BOOTSTRAP_PREFLIGHT_RECORD}"\n',
                encoding="utf-8",
            )
            fake_agent.chmod(0o755)
            fake_agent.write_text(fake_agent.read_text() +
                'echo "[WARN] ebpf/btf: kernel BTF is unavailable (backend=auto falls back to audit)"\n'
                'echo "[WARN] logs/host-persistence: output log exists but has no recent lines"\n'
                'echo "[WARN] disk: low free space"\n'
                'if [[ "$1" == preflight ]]; then exit "${TEST_PREFLIGHT_EXIT:-0}"; fi\n'
                'exit "${TEST_DOCTOR_EXIT:-0}"\n')

            fake_uname = fake_bin / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                'if [[ "${1:-}" == "-s" ]]; then echo Linux; else echo x86_64; fi\n',
                encoding="utf-8",
            )
            fake_uname.chmod(0o755)

            fake_logtail_installer = root / "logtail-install.sh"
            fake_logtail_installer.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'printf "%s\\n" "$*" >"${BOOTSTRAP_LOGTAIL_INSTALL_RECORD}"\n'
                'printf \'#!/usr/bin/env bash\\nexit 0\\n\' >"${BOOTSTRAP_FAKE_BIN}/ilogtaild"\n'
                'chmod 0755 "${BOOTSTRAP_FAKE_BIN}/ilogtaild"\n',
                encoding="utf-8",
            )
            fake_logtail_installer.chmod(0o755)
            fake_logtail_installer.write_text(
                fake_logtail_installer.read_text()
                + 'cp "${BOOTSTRAP_FAKE_BIN}/ilogtaild" "${BOOTSTRAP_INIT_DIR}/ilogtaild"\n',
                encoding="utf-8",
            )
            logtail_installer_sha256 = hashlib.sha256(fake_logtail_installer.read_bytes()).hexdigest()

            archive = release_dir / f"{package_name}.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                handle.add(package_root, arcname=package_name)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            pointer = root / "releases" / "latest-version.txt"
            pointer.write_text(version + "\n", encoding="ascii")
            archive.with_suffix(archive.suffix + ".sha256").write_text(
                f"{digest}  {archive.name}\n",
                encoding="ascii",
            )

            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}:{env['PATH']}",
                    "SECWEAVER_BOOTSTRAP_ALLOW_NON_ROOT": "1",
                    "SECWEAVER_BOOTSTRAP_ALLOW_FILE": "1",
                    "SECWEAVER_AGENT_EMBEDDED_RELEASE_BASE_URL": f"file://{root}/releases",
                    "SECWEAVER_AGENT_EMBEDDED_UPDATE_MANIFEST_URL": "https://updates.example.com/secweaver-agent/updates/stable/update-manifest.json",
                    "SECWEAVER_AGENT_EMBEDDED_UPDATE_PUBLIC_KEY": "",
                    "SECWEAVER_LOGTAIL_EMBEDDED_INSTALL_URL": f"file://{fake_logtail_installer}",
                    "SECWEAVER_LOGTAIL_EMBEDDED_INSTALL_SHA256": logtail_installer_sha256,
                    "SECWEAVER_LOGTAIL_EMBEDDED_ALIUID": "1234567890123456",
                    "SECWEAVER_LOGTAIL_EMBEDDED_REGION": "",
                    "SECWEAVER_LOGTAIL_CONFIG_DIR": str(root / "etc" / "ilogtail"),
                    "BOOTSTRAP_INSTALL_RECORD": str(install_record),
                    "BOOTSTRAP_PREFLIGHT_RECORD": str(preflight_record),
                    "BOOTSTRAP_LOGTAIL_INSTALL_RECORD": str(logtail_install_record),
                    "BOOTSTRAP_FAKE_BIN": str(fake_bin),
                    "BOOTSTRAP_INIT_DIR": str(init_dir),
                }
            )
            result = subprocess.run(
                [
                    "bash",
                    str(isolated_bootstrap),
                    "--enterprise-id",
                    enterprise_id.lower(),
                    "--license-server-url",
                    "https://shield.example.com",
                    "--enrollment-id",
                    enrollment_id,
                    "--no-start",
                ],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            install_args = install_record.read_text(encoding="utf-8").strip()
            self.assertIn(f"--enterprise-id {enterprise_id}", install_args)
            self.assertIn("--license-server-url https://shield.example.com", install_args)
            self.assertIn(f"--license-enrollment-id {enrollment_id}", install_args)
            self.assertIn("--license-heartbeat-interval-seconds 180", install_args)
            self.assertNotIn("--update-public-key", install_args)
            self.assertIn(
                f"preflight -config {agent_root}/etc/config.json -strict",
                preflight_record.read_text(encoding="utf-8"),
            )
            details = list((agent_root / "install-logs").glob("install.log.*"))
            self.assertEqual(len(details), 1)
            detail = details[0].read_text()
            self.assertEqual(details[0].stat().st_mode & 0o777, 0o600)
            self.assertIn("package checksum verified", detail)
            self.assertIn("child-config-noise", detail)
            self.assertNotIn("child-config-noise", result.stdout + result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertIn("[OK  ] [6/8]", result.stderr)
            self.assertIn("[SKIP] [8/8]", result.stderr)
            self.assertIn("[INFO] Kernel BTF unavailable", result.stderr)
            self.assertIn("[WARN] disk: low free space", result.stderr)
            self.assertNotIn("\x1b[", result.stderr)
            self.assertEqual(logtail_install_record.read_text(encoding="utf-8").strip(), "install cn-hangzhou-internet")
            self.assertIn("Logtail installer checksum verified", detail)
            logtail_dir = root / "etc" / "ilogtail"
            self.assertTrue((logtail_dir / "users" / "1234567890123456").is_file())
            self.assertEqual(
                (logtail_dir / "user_defined_id").read_text(encoding="utf-8").strip(),
                enrollment_id,
            )

            # Exercise actual top-level errexit/reporting, not only formatters.
            # Neither child failure nor a diagnostic error may print stage OK
            # or execute a subsequent installation step.
            for variable, code, stage in (("TEST_INSTALL_EXIT", 17, 3), ("TEST_PREFLIGHT_EXIT", 19, 4), ("TEST_DOCTOR_EXIT", 23, 8)):
                args = [arg for arg in result.args if arg != "--no-start"]
                failed = subprocess.run(args, cwd=REPO_ROOT, env={**env, variable: str(code)}, text=True, capture_output=True, timeout=30)
                self.assertEqual(failed.returncode, code, failed.stderr)
                self.assertIn("[FAIL]", failed.stderr)
                self.assertNotIn(f"[OK  ] [{stage}/8]", failed.stderr)
                self.assertNotIn("and Logtail are running", failed.stderr)
                self.assertIn("Details:", failed.stderr)

            # A malformed or missing mutable pointer must not execute even the
            # synthetic installer again or silently choose an embedded version.
            install_record.unlink()
            for value in ("../escape", "0.3.6\n0.3.19", "x" * 66, ""):
                pointer.write_text(value, encoding="ascii")
                rejected = subprocess.run(result.args, cwd=REPO_ROOT, env=env, text=True, capture_output=True, timeout=30)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(install_record.exists())
            pointer.unlink()
            missing = subprocess.run(result.args, cwd=REPO_ROOT, env=env, text=True, capture_output=True, timeout=30)
            self.assertNotEqual(missing.returncode, 0)
            self.assertFalse(install_record.exists())
            # Explicit version selection remains available for controlled tests.
            pinned = subprocess.run([*result.args, "--version", version], cwd=REPO_ROOT, env=env, text=True, capture_output=True, timeout=30)
            self.assertEqual(pinned.returncode, 0, pinned.stdout + pinned.stderr)

    def test_bootstrap_requires_machine_group_enrollment(self) -> None:
        bootstrap = REPO_ROOT / "src/tools/secweaver-agent/packaging/bootstrap-install.sh"
        env = os.environ.copy()
        env["SECWEAVER_BOOTSTRAP_ALLOW_NON_ROOT"] = "1"
        env["SECWEAVER_AGENT_EMBEDDED_RELEASE_BASE_URL"] = "https://updates.example.com/releases"
        env["SECWEAVER_AGENT_EMBEDDED_UPDATE_MANIFEST_URL"] = (
            "https://updates.example.com/secweaver-agent/updates/stable/update-manifest.json"
        )
        env["SECWEAVER_AGENT_EMBEDDED_UPDATE_PUBLIC_KEY"] = TEST_UPDATE_PUBLIC_KEY
        env["SECWEAVER_LOGTAIL_EMBEDDED_ALIUID"] = "1234567890123456"
        env["SECWEAVER_LOGTAIL_EMBEDDED_REGION"] = "cn-hangzhou"
        result = subprocess.run(
            [
                "bash",
                str(bootstrap),
                "--enterprise-id",
                "ABCDEF1234567890",
                "--license-server-url",
                "https://shield.example.com",
            ],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--enrollment-id", result.stderr)


if __name__ == "__main__":
    unittest.main()
