package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Run actual installer capability functions with kernel/service facades. An
// unsupported Audit kernel must never reach auditd tuning or lifecycle calls.
func TestInstallerLinuxCollectionSelection(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash required")
	}
	contents, err := os.ReadFile("packaging/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(contents)
	start, end := strings.Index(source, "need_cmd() {"), strings.Index(source, "is_systemd_running() {")
	if start < 0 || end < start {
		t.Fatal("cannot locate installer collection functions")
	}
	for _, tc := range []struct {
		name, enabled, ebpf, want string
		fail                      bool
	}{
		{"audit", "1", "0", "auto", false},
		{"immutable-audit", "2", "0", "auto", false},
		{"ebpf-only", "failed", "1", "ebpf_only", false},
		{"both-unavailable", "failed", "0", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Function overrides stay inside this disposable subprocess; the
			// production installer always uses the actual kernel prerequisites.
			script := "set -euo pipefail\n" + source[start:end] + `
log() { echo "$*"; }
fatal() { echo "ERROR: $*"; exit 1; }
need_cmd() { return 0; }
timeout() { shift 2; "$@"; }
auditctl() { [[ "$ENABLED" != failed ]] || return 1; printf 'enabled %s\npid 1\n' "$ENABLED"; }
ebpf_kernel_prerequisites_available() { [[ "$EBPF" == 1 ]]; }
start_auditd_service() { echo AUDIT_SERVICE_STARTED; }
prepare_linux_collection_mode
printf 'SELECTED=%s\n' "$AUDIT_RUNTIME_MODE"
`
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(), "ENABLED="+tc.enabled, "EBPF="+tc.ebpf)
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.fail {
				t.Fatalf("unexpected result err=%v output=%s", err, out)
			}
			if !tc.fail && !strings.Contains(string(out), "SELECTED="+tc.want) {
				t.Fatalf("wrong mode: %s", out)
			}
			if tc.enabled == "failed" && strings.Contains(string(out), "AUDIT_SERVICE_STARTED") {
				t.Fatalf("unavailable Audit triggered auditd setup: %s", out)
			}
		})
	}
}
