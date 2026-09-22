"""Exercise Studio's external Operator boundary without a real ES deployment."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dataasset-ui"))
from dataasset_ui_services import portable


class StandaloneOperatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="operator integration ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        # A harmless executable captures the real subprocess boundary, including
        # paths with spaces and the selected registry/runtime environment.
        self.command = self.root / "secweaver-portable"
        self.command.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "print(json.dumps({'arguments': sys.argv[1:], 'root': os.environ['SECWEAVER_PORTABLE_ROOT'], "
            "'runtime': os.environ['SECWEAVER_PORTABLE_RUNTIME'], 'registry': os.environ['DATAASSET_ROOT']}))\n"
        )
        self.command.chmod(0o755)
        self.environment = patch.dict(os.environ, {
            "SECWEAVER_PORTABLE_ROOT": str(self.root),
            "SECWEAVER_PORTABLE_COMMAND": "",
            "SECWEAVER_PORTABLE_RUNTIME": "",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_external_status_and_registry(self):
        result = portable.portable_status()
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["arguments"], ["--json", "doctor"])
        self.assertEqual(result["data"]["registry"], str(portable.DATAASSET_DIR))
        runtime = self.root / "separate runtime"
        runtime.mkdir()
        (runtime / "state.json").write_text("{}")
        with patch.dict(os.environ, {"SECWEAVER_PORTABLE_RUNTIME": str(runtime)}):
            result = portable.portable_status()
        self.assertEqual(result["data"]["arguments"], ["--json", "status"])
        self.assertEqual(result["data"]["runtime"], str(runtime))

    def test_command_override_and_missing_install(self):
        with patch.dict(os.environ, {
            "SECWEAVER_PORTABLE_ROOT": "",
            "SECWEAVER_PORTABLE_COMMAND": str(self.command),
        }):
            self.assertEqual(portable.portable_status()["data"]["root"], str(self.root))
        with patch.dict(os.environ, {"SECWEAVER_PORTABLE_COMMAND": str(self.root / "missing")}):
            result = portable.portable_status()
        self.assertFalse(result["available"])
        self.assertEqual(result["returncode"], 127)

    def test_binary_layout_and_legacy_fallback(self):
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        self.command.rename(binary_dir / "secweaver-portable")
        self.assertTrue(portable.portable_status()["ok"])
        with patch.dict(os.environ, {"SECWEAVER_PORTABLE_ROOT": ""}):
            _, operator_root, runtime = portable._operator_paths()
        self.assertEqual(operator_root, portable.ROOT / "src" / "es-operator")
        self.assertEqual(runtime, operator_root / "runtime")


class OperatorCommandContractTests(unittest.TestCase):
    """Regress the profile/key distinction and optionally probe a real Operator.

    The sentinel unknown flag is deliberately last: Go must parse all Studio
    flags before rejecting it, and command execution never starts. This checks
    a private CLI without needing Docker, credentials or a running deployment.
    """
    def cases(self):
        for platform, arch in [('linux', 'amd64'), ('linux', 'arm64'), ('linux', 'loong64'), ('windows', 'amd64'), ('windows', 'arm64')]:
            for shipper in ['filebeat', 'fluent-bit', 'secweaver']:
                yield 'enroll', dict(enterprise_id='ABCD1234EFGH5678', platform=platform, arch=arch,
                                    shipper=shipper, shipper_package='/tmp/package with spaces.tar.gz',
                                    agent_package='/tmp/agent.tar.gz', reuse_agent=True, reuse_shipper=True, rotate=True)
            yield 'close_enrollment', dict(enterprise_id='ABCD1234EFGH5678', platform=platform, arch=arch)
        yield 'revoke', dict(enrollment_key='host-credential-key')

    def test_profile_identity_and_credential_key(self):
        for action, payload in self.cases():
            with self.subTest(action=action, payload=payload), patch.object(portable, '_run') as run:
                portable.portable_action(action, payload)
                args = run.call_args.args[0]
                self.assertNotIn('--name', args)
                if action == 'revoke':
                    self.assertEqual(args, ['revoke', '--enrollment-key', payload['enrollment_key']])
                else:
                    self.assertIn('--enterprise-id', args)
                    self.assertEqual(args[args.index('--arch') + 1], payload['arch'])
        with self.assertRaises(ValueError): portable.portable_action('revoke', {'name': 'ambiguous-host'})
        with self.assertRaises(ValueError): portable.portable_action('enroll', {'shipper': '--force'})

    def test_real_cli_accepts_all_studio_flags(self):
        command = os.environ.get('SECWEAVER_OPERATOR_TEST_COMMAND', '')
        if not command:
            if os.environ.get('REQUIRE_OPERATOR_CONTRACT_TESTS') == '1':
                self.fail('SECWEAVER_OPERATOR_TEST_COMMAND must name a built Operator executable')
            self.skipTest('private integration: run make test-operator-contract with an Operator executable')
        for action, payload in self.cases():
            with patch.object(portable, '_run') as run:
                portable.portable_action(action, payload)
            import subprocess
            result = subprocess.run([command, '--json', *run.call_args.args[0], '--studio-contract-probe'],
                                    capture_output=True, text=True, timeout=30, check=False)
            with self.subTest(action=action, payload=payload):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('flag provided but not defined: -studio-contract-probe', result.stdout + result.stderr)


class OperatorLifecycleContractTests(unittest.TestCase):
    """Run Studio -> real CLI -> isolated disk state; never reach a Docker daemon."""

    def test_enroll_close_revoke_lifecycle(self):
        command = os.environ.get('SECWEAVER_OPERATOR_TEST_COMMAND', '')
        operator_root = os.environ.get('SECWEAVER_OPERATOR_TEST_ROOT', '')
        if not command or not operator_root:
            if os.environ.get('REQUIRE_OPERATOR_CONTRACT_TESTS') == '1':
                self.fail('built Operator command and SECWEAVER_OPERATOR_TEST_ROOT are required')
            self.skipTest('private Operator lifecycle integration')
        import base64
        with tempfile.TemporaryDirectory(prefix='studio lifecycle ') as temporary:
            root = Path(temporary)
            runtime = root / 'runtime'
            docker = root / 'docker'
            docker.write_text('#!/bin/sh\nexit 1\n')
            docker.chmod(0o755)
            with patch.dict(os.environ, {
                'SECWEAVER_PORTABLE_COMMAND': str(Path(command).resolve()),
                'SECWEAVER_PORTABLE_ROOT': str(Path(operator_root).resolve()),
                'SECWEAVER_PORTABLE_RUNTIME': str(runtime),
                'PATH': str(root) + os.pathsep + os.environ.get('PATH', ''),
                'SECWEAVER_AGENT_CONTROL_URL': 'https://agent-gateway.example.com',
                'SECWEAVER_AGENT_ENROLLMENT_TOKEN': 'swenr_test.contract-fixture',
                'SECWEAVER_AGENT_UPDATE_PUBLIC_KEY': base64.b64encode(bytes(32)).decode(),
            }):
                def action(name, payload):
                    result = portable.portable_action(name, payload)
                    self.assertTrue(result['ok'], result)
                    return result['data']

                action('init', {'advertise_host': '192.0.2.10'})
                profile = dict(enterprise_id='ABCD1234EFGH5678', platform='linux', arch='amd64')
                created = action('enroll', dict(profile, reuse_agent=True, reuse_shipper=True))
                state_file = runtime / 'state.json'
                state = json.loads(state_file.read_text())
                profile_id = created['profile_id']
                token = state['enrollment_profiles'][profile_id]['token']
                self.assertTrue((runtime / 'enroll' / token / 'install.sh').is_file())
                repeated = action('enroll', profile)
                self.assertEqual(created['install_command'], repeated['install_command'])
                # Device HTTP enrollment is covered by Operator's Go tests. Seed an
                # existing credential here to verify close/revoke boundary semantics.
                key = 'contract-host-key'
                state['enrollments'][key] = dict(host_name='contract-host', platform='linux',
                    enterprise_id=profile['enterprise_id'], username='fixture-user',
                    password='fixture-password', token=None, created_at='2026-01-01T00:00:00Z')
                state_file.write_text(json.dumps(state))
                closed = action('close_enrollment', profile)
                self.assertEqual(closed['active_host_credentials'], 1)
                self.assertFalse((runtime / 'enroll' / token).exists())
                state = json.loads(state_file.read_text())
                self.assertTrue(state['enrollment_profiles'][profile_id]['enrollment_closed_at'])
                self.assertIn(key, state['enrollments'])
                self.assertEqual(action('revoke', {'enrollment_key': key})['revoked'], key)
                self.assertNotIn(key, json.loads(state_file.read_text())['enrollments'])
                self.assertFalse(portable.portable_action('revoke', {'enrollment_key': key})['ok'])


if __name__ == "__main__":
    unittest.main()
