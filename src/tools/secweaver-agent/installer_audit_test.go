package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Exercise the shipped shell implementation with real file edits and native awk.
// Only kernel/service operations are fixtures; absolute host paths are relocated
// before execution so the tests cannot modify the developer's audit policy.
func TestLinuxInstallerAuditQueueSetup(t *testing.T) {
	cases := []struct {
		name, version, dispatcher, rules, generated, enabled, fault string
		backlog, wantBacklog, wantQueue                             string
		legacy, stopped, disabled, fail                             bool
	}{
		{name: "centos7", version: "2.8.5", legacy: true, dispatcher: "q_depth = 80\nmax_restarts = 10\n", rules: "-b 64\n", generated: "-b 64\n-e 1\n", backlog: "64", wantBacklog: "8192", wantQueue: "q_depth = 2000"},
		{name: "audit3", version: "3.0.9", dispatcher: "q_depth = 400\n", rules: "-b 4096\n", backlog: "4096", wantBacklog: "8192", wantQueue: "q_depth = 2000"},
		{name: "audit4", version: "4.0.0", dispatcher: "q_depth = 2000\n", rules: "-b 8192\n", backlog: "8192", wantBacklog: "8192", wantQueue: "q_depth = 2000"},
		{name: "larger-existing", version: "3.0.9", dispatcher: "q_depth = 12000\n", rules: "-b 65536\n-b 64\n", backlog: "32768", wantBacklog: "65536", wantQueue: "q_depth = 12000"},
		{name: "missing-directives", version: "3.0.9", dispatcher: "# q_depth = 80\n", generated: "-D\n-e 2\n", backlog: "64", wantBacklog: "8192", wantQueue: "q_depth = 2000"},
		{name: "empty-rule-directory", version: "3.0.9", dispatcher: "q_depth = 400\n", backlog: "64", wantBacklog: "8192", wantQueue: "q_depth = 2000"},
		{name: "generated-only", version: "3.0.9", dispatcher: "q_depth = 400\n", generated: "-b 4096\n-e 1\n", backlog: "4096", wantBacklog: "8192", wantQueue: "q_depth = 2000"},
		{name: "source-only", version: "3.0.9", dispatcher: "q_depth = 400\n", rules: "-b 64\n", generated: "-D\n-e 2\n", backlog: "64", wantBacklog: "8192", wantQueue: "q_depth = 2000"},
		{name: "compact-backlog", version: "3.0.9", dispatcher: "q_depth = 400\n", rules: "-b65536\n-b64\n", backlog: "64", wantBacklog: "65536", wantQueue: "q_depth = 2000"},
		{name: "immutable", version: "2.8.5", legacy: true, enabled: "2", dispatcher: "q_depth = 80\n", rules: "-b 64\n", backlog: "64", wantBacklog: "64", wantQueue: "q_depth = 2000"},
		{name: "start-instead-of-reload", version: "2.8.5", legacy: true, stopped: true, dispatcher: "q_depth = 80\n", rules: "-b 64\n", backlog: "64", wantBacklog: "8192", wantQueue: "q_depth = 2000"},
		{name: "comments", version: "3.0.9", dispatcher: "  q_depth = 0080 # burst buffer\n", rules: "# -b 100000\n-b 00064 # kernel buffer\n", backlog: "64", wantBacklog: "8192", wantQueue: "  q_depth = 2000 # burst buffer"},
		{name: "duplicate-queue", version: "3.0.9", dispatcher: "q_depth = 80\nq_depth = 400\n", rules: "-b 64\n", backlog: "64", wantBacklog: "8192", wantQueue: "q_depth = 80\nq_depth = 400"},
		{name: "invalid-policy", version: "3.0.9", dispatcher: "q_depth = 80\n", rules: "-b broken\n", backlog: "64", fail: true},
		{name: "reload-failed", version: "2.8.5", legacy: true, dispatcher: "q_depth = 80\n", rules: "-b 64\n", backlog: "64", fault: "reload", fail: true},
		{name: "start-failed", version: "2.8.5", legacy: true, stopped: true, dispatcher: "q_depth = 80\n", rules: "-b 64\n", backlog: "64", fault: "start", fail: true},
		{name: "missing-daemon", version: "3.0.9", dispatcher: "q_depth = 2000\n", rules: "-b 8192\n", backlog: "8192", fault: "pid", fail: true},
		{name: "missing-unit", version: "3.0.9", dispatcher: "q_depth = 2000\n", rules: "-b 8192\n", backlog: "8192", fault: "unit", fail: true},
		{name: "malformed-status", version: "3.0.9", dispatcher: "q_depth = 2000\n", rules: "-b 8192\n", backlog: "broken", fail: true},
		{name: "backlog-not-applied", version: "3.0.9", dispatcher: "q_depth = 2000\n", rules: "-b 64\n", backlog: "64", fault: "backlog", fail: true},
		{name: "tuning-disabled", version: "3.0.9", disabled: true, dispatcher: "q_depth = 80\n", rules: "-b 64\n", backlog: "64", wantBacklog: "64", wantQueue: "q_depth = 80"},
		{name: "unknown-version", version: "9.0.0", dispatcher: "q_depth = 80\n", rules: "-b 64\n", backlog: "64", wantBacklog: "8192", wantQueue: "q_depth = 80"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAuditInstallerFixture(t)
			dispatcherPath := "audit/auditd.conf"
			auditConf := "write_logs = yes\nmax_log_file_action = ROTATE\n"
			if tc.legacy {
				dispatcherPath = "audisp/audispd.conf"
				auditConf += "dispatcher = /sbin/audispd\ndisp_qos = lossy\n"
				fixture.write(t, "init.d/auditd", "#!/bin/sh\n", 0755)
			} else {
				auditConf += tc.dispatcher
			}
			fixture.write(t, "audit/auditd.conf", auditConf, 0640)
			if tc.legacy {
				fixture.write(t, dispatcherPath, tc.dispatcher, 0640)
			}
			if tc.rules != "" {
				fixture.write(t, "audit/rules.d/10-base.rules", "# operator policy\n"+tc.rules+"-a never,exit -F exe=/usr/bin/example\n-e 1\n", 0600)
			}
			if tc.generated != "" {
				fixture.write(t, "audit/audit.rules", tc.generated, 0600)
			}
			fixture.write(t, "backlog", tc.backlog, 0600)
			if !tc.stopped {
				fixture.write(t, "active", "yes", 0600)
			}
			enabled := tc.enabled
			if enabled == "" {
				enabled = "1"
			}
			tune := "1"
			if tc.disabled {
				tune = "0"
			}
			env := []string{"AUDIT_VERSION=" + tc.version, "AUDIT_ENABLED=" + enabled, "AUDIT_FAULT=" + tc.fault, "AUDIT_TUNE=" + tune}
			before := fixture.read(t, dispatcherPath)
			output, err := fixture.run(t, "start_auditd_service", env...)
			if (err != nil) != tc.fail {
				t.Fatalf("unexpected setup result: %v\n%s", err, output)
			}
			trace := fixture.read(t, "trace")
			// A queue adjustment must not load/clear rules or force-stop the daemon.
			for _, forbidden := range []string{"auditctl:-D", "auditctl:-R", "systemctl:restart", "service:restart", "systemctl:stop", "service:stop", "--now"} {
				if strings.Contains(trace, forbidden) {
					t.Fatalf("unexpected destructive lifecycle operation: %s", trace)
				}
			}
			if tc.fail {
				if tc.name == "invalid-policy" && fixture.read(t, dispatcherPath) != before {
					t.Fatal("invalid backlog policy must fail before publishing dispatcher changes")
				}
				if tc.fault == "reload" && !strings.Contains(output, "dispatcher backup=") {
					t.Fatal("reload failure must identify the recovery backup")
				}
				return
			}
			if fixture.read(t, "backlog") != tc.wantBacklog {
				t.Fatalf("unexpected effective kernel backlog: %s", output)
			}
			if !strings.Contains(fixture.read(t, dispatcherPath), tc.wantQueue) {
				t.Fatalf("unexpected dispatcher configuration: %s", fixture.read(t, dispatcherPath))
			}
			if tc.disabled || tc.name == "duplicate-queue" || tc.name == "unknown-version" {
				if fixture.read(t, dispatcherPath) != before {
					t.Fatal("operator-owned dispatcher policy changed")
				}
			}
			if tc.name == "missing-directives" {
				if !strings.HasPrefix(fixture.read(t, "audit/audit.rules"), "-b 8192\n-D\n-e 2\n") {
					t.Fatal("backlog must be inserted before the immutable rule")
				}
				if fixture.read(t, "audit/rules.d/70-secweaver-backlog.rules") != "-b 8192\n" {
					t.Fatal("missing augenrules backlog source")
				}
			}
			if tc.name == "empty-rule-directory" || tc.name == "generated-only" {
				if fixture.read(t, "audit/rules.d/70-secweaver-backlog.rules") != "-b 8192\n" {
					t.Fatal("generated policy alone must not substitute for an augenrules source")
				}
			}
			if tc.name == "source-only" && !strings.HasPrefix(fixture.read(t, "audit/audit.rules"), "-b 8192\n-D\n-e 2\n") {
				t.Fatal("augenrules source alone must not substitute for a direct-loader policy")
			}
			if tc.enabled == "2" && (!strings.Contains(output, "next reboot") || strings.Contains(trace, "auditctl:-b")) {
				t.Fatal("immutable kernel policy must be deferred instead of changed")
			}
			if tc.stopped && !strings.Contains(trace, "service:start") {
				t.Fatal("CentOS 7 daemon startup must use service auditd start")
			}
			if !tc.stopped && tc.legacy && strings.Contains(trace, "systemctl:reload") {
				t.Fatal("CentOS 7 reload must use the audit init script")
			}
			if tc.rules != "" && !tc.disabled {
				rules := fixture.read(t, "audit/rules.d/10-base.rules")
				if !strings.Contains(rules, "-a never,exit -F exe=/usr/bin/example\n-e 1\n") {
					t.Fatal("unrelated audit policy changed")
				}
			}
			backups, err := filepath.Glob(filepath.Join(fixture.root, dispatcherPath) + ".secweaver-backup.*")
			if err != nil {
				t.Fatal(err)
			}
			if before != fixture.read(t, dispatcherPath) {
				if len(backups) != 1 {
					t.Fatalf("expected one dispatcher backup, got %v", backups)
				}
				data, err := os.ReadFile(backups[0])
				if err != nil || string(data) != before {
					t.Fatal("dispatcher backup did not preserve original bytes")
				}
				info, err := os.Stat(filepath.Join(fixture.root, dispatcherPath))
				if err != nil || info.Mode().Perm() != 0640 {
					t.Fatal("dispatcher configuration permissions changed")
				}
			}
			// The second install must neither create another backup nor reload a
			// healthy dispatcher. This catches configuration churn on every upgrade.
			traceBefore := trace
			if output, err := fixture.run(t, "start_auditd_service", env...); err != nil {
				t.Fatalf("idempotent install failed: %v\n%s", err, output)
			}
			backupsAfter, _ := filepath.Glob(filepath.Join(fixture.root, dispatcherPath) + ".secweaver-backup.*")
			if len(backupsAfter) != len(backups) || strings.Contains(strings.TrimPrefix(fixture.read(t, "trace"), traceBefore), ":reload") {
				t.Fatal("unchanged queues were rewritten/reloaded on repeat installation")
			}
		})
	}
}

type auditInstallerFixture struct {
	root, functions string
}

// Relocate every privileged path and provide strict command fixtures: any
// unplanned kernel or service operation fails instead of reaching the host.
func newAuditInstallerFixture(t *testing.T) auditInstallerFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("native POSIX filesystem and shell semantics required for the Linux installer")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash required")
	}
	source, err := os.ReadFile("packaging/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "audit_queue_values() {")
	if start < 0 {
		// The old installer had no queue helpers; retain its actual lifecycle
		// function so the same behavior assertions can expose the original gap.
		start = strings.Index(string(source), "start_auditd_service() {")
	}
	end := strings.Index(string(source), "stop_legacy_collectors() {")
	if start < 0 || end <= start {
		t.Fatal("missing shipped audit setup functions")
	}
	fixture := auditInstallerFixture{root: filepath.Join(t.TempDir(), "audit host")}
	fixture.functions = strings.NewReplacer(
		"/etc/audit/", "${AUDIT_TEST_ROOT}/audit/",
		"/etc/audisp/", "${AUDIT_TEST_ROOT}/audisp/",
		"/etc/init.d/auditd", "${AUDIT_TEST_ROOT}/init.d/auditd",
	).Replace(string(source)[start:end])
	for _, dir := range []string{"audit/rules.d", "audisp", "stubs"} {
		if err := os.MkdirAll(filepath.Join(fixture.root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	fixture.write(t, "trace", "", 0600)
	fixture.write(t, "stubs/auditctl", `#!/usr/bin/env bash
set -euo pipefail
echo "auditctl:$*" >> "$AUDIT_TEST_ROOT/trace"
case "$1" in
  -v) echo "auditctl version $AUDIT_VERSION" ;;
  -s)
    echo "enabled $AUDIT_ENABLED"
    if [[ "$AUDIT_FAULT" == pid ]]; then echo 'pid 0'; else echo 'pid 473'; fi
    printf 'backlog_limit %s\n' "$(<"$AUDIT_TEST_ROOT/backlog")"
    echo 'backlog 0'; echo 'lost 0' ;;
  -b) [[ "$AUDIT_FAULT" == backlog ]] || printf '%s' "$2" > "$AUDIT_TEST_ROOT/backlog" ;;
  *) exit 99 ;;
esac
`, 0755)
	fixture.write(t, "stubs/systemctl", `#!/usr/bin/env bash
set -euo pipefail
echo "systemctl:$*" >> "$AUDIT_TEST_ROOT/trace"
case "$1" in
  cat) [[ "$AUDIT_FAULT" != unit ]] ;;
  enable) exit 0 ;;
  is-active) [[ -f "$AUDIT_TEST_ROOT/active" ]] ;;
  start|reload)
    [[ "$AUDIT_FAULT" != "$1" ]] || exit 1
    touch "$AUDIT_TEST_ROOT/active" ;;
  *) exit 99 ;;
esac
`, 0755)
	fixture.write(t, "stubs/service", `#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == auditd ]] || exit 99
echo "service:$2" >> "$AUDIT_TEST_ROOT/trace"
[[ "$AUDIT_FAULT" != "$2" ]] || exit 1
case "$2" in start|reload) touch "$AUDIT_TEST_ROOT/active" ;; *) exit 99 ;; esac
`, 0755)
	return fixture
}

func (f auditInstallerFixture) write(t *testing.T, name, contents string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(f.root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}

func (f auditInstallerFixture) read(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.root, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A subprocess deadline bounds broken fixtures; the timeout facade validates
// production command limits while service/kernel fixtures complete immediately.
func (f auditInstallerFixture) run(t *testing.T, action string, env ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	harness := `set -euo pipefail
log() { echo "$*"; }
warn() { echo "WARN: $*" >&2; }
fatal() { echo "ERROR: $*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }
timeout() {
  [[ "$1" == --kill-after=5s && ( "$2" == 10s || "$2" == 30s ) ]] || return 99
  shift 2; "$@"
}
restorecon() { :; }
` + f.functions + "\n" + action
	command := exec.CommandContext(ctx, "bash", "-c", harness)
	command.Env = append(os.Environ(), "AUDIT_TEST_ROOT="+f.root, "PATH="+filepath.Join(f.root, "stubs")+":"+os.Getenv("PATH"))
	command.Env = append(command.Env, env...)
	output, err := command.CombinedOutput()
	return string(output), err
}
