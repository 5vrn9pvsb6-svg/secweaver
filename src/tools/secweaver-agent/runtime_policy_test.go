package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secweaver-agent/pkg/agentlicense"
)

// Policy writes must preserve disabled modules, persisted state paths, learning
// options and file permissions, and converge without a restart loop.
func TestManagedRuntimePolicyPreservesConfigAndConverges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	const body = `{"enterprise_id":"0123456789ABCDEF","license":{"enabled":false,"heartbeat_interval_seconds":180},"modules":{"host_process_snapshot":{"enabled":false,"args":["--interval=10m","-state","keep-state.json"]},"syslog-risk-json":{"enabled":true,"args":["-min-level","high"]}}}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	policy := &agentlicense.RuntimePolicy{HostProcessIntervalMinutes: 30, HeartbeatIntervalMinutes: 5, Revision: 1}
	changed, err := applyManagedRuntimePolicy(path, policy)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	got, _ := os.ReadFile(path)
	for _, want := range []string{`"heartbeat_interval_seconds": 300`, `"enabled": false`, `"--interval=30m0s"`, `"keep-state.json"`, `"high"`} {
		if !bytes.Contains(got, []byte(want)) {
			t.Fatalf("missing preserved/updated field %s: %s", want, got)
		}
	}
	changed, err = applyManagedRuntimePolicy(path, policy)
	if err != nil || changed {
		t.Fatal("policy did not converge", changed, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("config permissions changed")
	}
}

// Invalid server data or local argv must leave the config byte-for-byte intact.
func TestManagedRuntimePolicyRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name               string
		interval           string
		process, heartbeat int
	}{
		{"range", "10m", 0, 5}, {"heartbeat", "10m", 30, 61}, {"bad-argv", "invalid", 30, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			body := []byte(strings.ReplaceAll(`{"license":{},"modules":{"host-process-snapshot":{"args":["-interval","INTERVAL"]}}}`, "INTERVAL", tc.interval))
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := applyManagedRuntimePolicy(path, &agentlicense.RuntimePolicy{HostProcessIntervalMinutes: tc.process, HeartbeatIntervalMinutes: tc.heartbeat, Revision: 1}); err == nil {
				t.Fatal("invalid policy accepted")
			}
			got, _ := os.ReadFile(path)
			if !bytes.Equal(got, body) {
				t.Fatal("invalid policy mutated file")
			}
		})
	}
}

func TestRuntimeIntervalArgsSpellingsAndMissingFlag(t *testing.T) {
	for _, args := range [][]string{nil, {"--interval", "10m"}, {"-interval=10m"}, {"-interval", "10m", "--interval=20m"}, {"-state", "-interval", "--"}} {
		got, changed, err := runtimeIntervalArgs(args, 30*time.Minute)
		if err != nil || !changed {
			t.Fatal(got, changed, err)
		}
		if _, changed, err = runtimeIntervalArgs(got, 30*time.Minute); err != nil || changed {
			t.Fatal("nonconvergent argv", got, err)
		}
	}
	if _, changed, err := runtimeIntervalArgs([]string{"--interval=1800s"}, 30*time.Minute); err != nil || changed {
		t.Fatal("equivalent duration changed")
	}
	if runtimePolicyRestartAllowed(&agentlicense.UpdateReport{HealthPending: true}) || runtimePolicyRestartAllowed(&agentlicense.UpdateReport{Status: "state_read_failed"}) {
		t.Fatal("unsafe upgrade restart allowed")
	}
}
