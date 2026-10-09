"""Real backup/config transactions with isolated service/doctor boundaries."""
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "packaging/recovery/restart-behavior-learning.py"
SPEC = importlib.util.spec_from_file_location("learning_recovery", str(SOURCE))
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)


class LearningRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        for path in ("bin", "etc", "data/behavior-learning/file-operations", "data/update"):
            (self.root / path).mkdir(parents=True, exist_ok=True)
        self.config = self.root / "etc/audit-port-execmon.json"
        self.supervisor = self.root / "etc/config.json"
        self.binary = self.root / "bin/secweaver-agent"
        self.binary.write_bytes(b"synthetic binary")
        self.supervisor.write_text(json.dumps({"enterprise_id": "TEST", "modules": {
            "audit-port-execmon": {"enabled": True, "args": ["-config", str(self.config)]}}}))
        self.config.write_text(json.dumps({"custom": "preserve", "behavior_learning": {
            "enabled": True, "generation": 3, "learning_duration_seconds": 86400}}))
        self.state_dir = self.root / "data/behavior-learning"
        self.state_path = self.state_dir / "state.json"
        self.state_path.write_text(json.dumps({"state": {"generation": 3, "healthy_seconds": 42},
                                               "hmac_sha256": "synthetic"}))
        (self.state_dir / "key").write_bytes(b"synthetic learning key")
        (self.state_dir / "admissions.jsonl").write_bytes(b"synthetic admission journal\n")
        (self.state_dir / "file-operations/state.json").write_bytes(b"synthetic file checkpoint")
        self.identity = self.root / "data/license-state.json"
        self.identity.write_bytes(b"synthetic enrolled identity")
        self.args = SimpleNamespace(root=str(self.root), service="fixture.service", apply=True,
                                    relearn=False, health_timeout=30)
        self.calls = []
        self.current = {"mode": "degraded", "baseline_entries": "0", "reason": "source_event_loss"}
        self.started = False
        self.file_active = False

    def command(self, argv, allowed=(0,)):
        # Only process/service boundaries are simulated. Backup, atomic writes,
        # state restoration and retained identity files are actual filesystem IO.
        argv = [str(x) for x in argv]
        self.calls.append(argv)
        if argv[0] == "systemctl":
            if argv[1] == "show":
                self.assertNotIn("--value", argv)
                return "ExecStart={} run -config {}".format(self.binary, self.supervisor)
            if argv[1] == "start":
                self.started = True
                generation = json.loads(self.config.read_text())["behavior_learning"]["generation"]
                self.state_path.write_text(json.dumps({"state": {"generation": generation, "healthy_seconds": 1},
                                                      "hmac_sha256": "new synthetic"}))
            return ""
        if argv[1] == "version":
            return "secweaver-agent 0.3.84"
        if argv[1] == "doctor":
            return json.dumps({"checks": [{"component": "file-learning/status", "detail":
                "filtering_active=" + str(self.file_active).lower()}]})
        if argv[1:3] == ["config", "set-learning-mode"]:
            return "behavior learning: enabled"
        raise AssertionError(argv)

    def observation(self, binary, config):
        if self.started:
            return {"mode": "learning", "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        return self.current

    def execute(self, observer=None):
        with patch.object(recovery, "run", side_effect=self.command), \
             patch.object(recovery, "status", side_effect=observer or self.observation):
            return recovery.recover(self.args)

    def test_check_does_not_change_config_progress_or_restart(self):
        self.args.apply = False
        before = self.config.read_bytes(), self.state_path.read_bytes()
        self.assertEqual(self.execute()["status"], "checked")
        self.assertEqual(before, (self.config.read_bytes(), self.state_path.read_bytes()))
        self.assertFalse((self.root / "data/recovery").exists())
        self.assertFalse(any(x[:2] == ["systemctl", "stop"] for x in self.calls))

    def test_native_doctor_projection_and_invalid_state(self):
        # Exercise the real parser, including native disabled/error wording;
        # service simulations elsewhere must not hide this compatibility edge.
        fixtures = [
            [{"component": "learning/status", "detail": "mode=learning started_at=2026-10-09T00:00:00Z remaining_seconds=3600 filtering_active=false baseline_entries=0 updated_at=2026-10-09T01:00:00Z reason=simple_exec_policy_migrated"}],
            [{"component": "learning/config", "detail": "behavior learning: disabled; reason=config-disabled"}],
            [{"component": "learning/status", "detail": "mode=unknown; learning checkpoint integrity failure"}],
        ]
        for index, checks in enumerate(fixtures):
            with patch.object(recovery, "run", return_value=json.dumps({"checks": checks})) as command:
                if index == 2:
                    with self.assertRaisesRegex(ValueError, "unavailable/invalid"):
                        recovery.status(self.binary, self.supervisor)
                else:
                    self.assertEqual(recovery.status(self.binary, self.supervisor)["mode"],
                                     "learning" if index == 0 else "disabled")
                self.assertIn("-check-license=false", command.call_args[0][0])

    def test_healthy_learning_empty_and_existing_baselines_are_preserved(self):
        for current, relearn in [({"mode": "learning", "baseline_entries": "0"}, False),
                                 ({"mode": "learning", "baseline_entries": "5"}, True),
                                 ({"mode": "enforcing", "baseline_entries": "5"}, False)]:
            with self.subTest(current=current):
                self.current, self.args.relearn = current, relearn
                self.assertEqual(self.execute()["status"], "skipped")
        self.current = {"mode": "degraded", "baseline_entries": "0"}
        self.file_active = True
        self.assertEqual(self.execute()["reason"], "existing_baseline_preserved")
        self.assertFalse(any(x[:2] == ["systemctl", "stop"] for x in self.calls))

    def test_relearn_backs_up_both_streams_preserves_identity_and_is_repeat_safe(self):
        for mode in ("degraded", "disabled", "enforcing", "learning"):
            with self.subTest(mode=mode):
                self.started = False
                self.current = {"mode": mode, "baseline_entries": "0"}
                self.args.relearn = mode == "learning"
                before_state = self.state_path.read_bytes()
                before_config = self.config.read_bytes()
                generation = json.loads(self.config.read_text())["behavior_learning"]["generation"]
                result = self.execute()
                self.assertEqual(result["status"], "relearning")
                backup = Path(result["backup"])
                self.assertEqual((backup / "state/state.json").read_bytes(), before_state)
                self.assertEqual((backup / "audit-port-execmon.json").read_bytes(), before_config)
                self.assertEqual((backup / "state/file-operations/state.json").read_bytes(), b"synthetic file checkpoint")
                self.assertEqual((backup / "audit-port-execmon.json").stat().st_mode & 0o777, 0o600)
                new = json.loads(self.config.read_text())
                self.assertEqual(new["behavior_learning"]["generation"], generation + 1)
                self.assertEqual(new["custom"], "preserve")
                self.assertEqual(self.identity.read_bytes(), b"synthetic enrolled identity")
                self.args.relearn = False
                self.assertEqual(self.execute()["reason"], "already_learning")

    def test_failed_start_rolls_back_config_and_complete_state(self):
        before_state = self.state_path.read_bytes()
        before_config = self.config.read_bytes()
        original = self.command
        starts = 0
        def fail_once(argv, allowed=(0,)):
            nonlocal starts
            if [str(x) for x in argv][:2] == ["systemctl", "start"]:
                starts += 1
                if starts == 1:
                    self.state_path.write_text("partial new checkpoint")
                    raise RuntimeError("synthetic startup failure")
                return ""
            return original(argv, allowed)
        with patch.object(recovery, "run", side_effect=fail_once), \
             patch.object(recovery, "status", side_effect=self.observation):
            with self.assertRaisesRegex(RuntimeError, "startup failure"):
                recovery.recover(self.args)
        self.assertEqual(self.config.read_bytes(), before_config)
        self.assertEqual(self.state_path.read_bytes(), before_state)
        self.assertEqual(starts, 2)
        self.assertEqual(self.identity.read_bytes(), b"synthetic enrolled identity")

    def test_startup_waits_for_fresh_native_status(self):
        observations = 0
        def delayed(binary, config):
            nonlocal observations
            if self.started:
                observations += 1
                if observations == 1:
                    raise ValueError("learning state not initialized yet")
            return self.observation(binary, config)
        with patch.object(recovery.time, "sleep"):
            self.assertEqual(self.execute(delayed)["status"], "relearning")
        self.assertGreaterEqual(observations, 2)

    def test_pending_update_and_symlink_state_refuse_mutation(self):
        marker = self.root / "data/update/health.pending"
        marker.touch()
        with self.assertRaisesRegex(ValueError, "transaction"):
            self.execute()
        marker.unlink()
        (self.state_dir / "unexpected-link").symlink_to(self.identity)
        before = self.config.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "Unsupported learning state"):
            self.execute()
        self.assertEqual(self.config.read_bytes(), before)
        self.assertTrue(any(x[:2] == ["systemctl", "start"] for x in self.calls))

    def test_standalone_collector_lock_prevents_reset(self):
        before = self.config.read_bytes(), self.state_path.read_bytes()
        with (self.state_dir / "lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, "original service restored"):
                self.execute()
        self.assertEqual(before[0], self.config.read_bytes())
        # The isolated restart fixture publishes a same-generation checkpoint;
        # the retained backup/lock proof is the absence of any config mutation.
        self.assertFalse(any(x.name == "state" for x in (self.root / "data/recovery").glob("learning-*/*")))

    def test_concurrent_config_change_prevents_rollback_overwrite(self):
        original = self.command
        def concurrent(argv, allowed=(0,)):
            if [str(x) for x in argv][:2] == ["systemctl", "start"]:
                self.config.write_text('{"external_change":true}')
                raise RuntimeError("synthetic concurrent failure")
            return original(argv, allowed)
        with patch.object(recovery, "run", side_effect=concurrent), \
             patch.object(recovery, "status", side_effect=self.observation):
            with self.assertRaisesRegex(RuntimeError, "Concurrent change prevents rollback.*backup="):
                recovery.recover(self.args)
        self.assertEqual(self.config.read_text(), '{"external_change":true}')
        self.assertEqual(self.identity.read_bytes(), b"synthetic enrolled identity")


if __name__ == "__main__":
    unittest.main()
