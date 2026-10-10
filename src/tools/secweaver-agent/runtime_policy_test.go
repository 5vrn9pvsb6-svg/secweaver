package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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

// State cadence is independently optional. Managed scans preserve enablement,
// comparison state, full-baseline cadence and learning, then converge on replay.
func TestManagedHostStateCadencePreservesStateAndOptionalFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	const body = `{"license":{"heartbeat_interval_seconds":300},"modules":{"host-state-snapshot":{"enabled":false,"args":["--socket-interval=5m","-identity-interval","7m","-service-interval","9m","--kernel-interval=10m","-state","keep-state.json","-full-snapshot-interval","24h"]},"audit-port-execmon":{"enabled":false,"args":["-learning-mode","enforce"]},"syslog-risk-json":{"enabled":true}}}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	policy := &agentlicense.RuntimePolicy{HostProcessIntervalMinutes: 30, HeartbeatIntervalMinutes: 5, Revision: 2}
	if changed, err := applyManagedRuntimePolicy(path, policy); err != nil || changed {
		t.Fatal("omitted fields changed state", changed, err)
	}
	socket, identity, service, kernel := 15, 20, 30, 60
	policy.HostSocketIntervalMinutes = &socket
	policy.HostIdentityIntervalMinutes = &identity
	policy.HostServiceIntervalMinutes = &service
	policy.HostKernelContextIntervalMinutes = &kernel
	if changed, err := applyManagedRuntimePolicy(path, policy); err != nil || !changed {
		t.Fatal(changed, err)
	}
	var cfg struct {
		Modules map[string]struct {
			Enabled bool
			Args    []string
		}
	}
	got, _ := os.ReadFile(path)
	if err := json.Unmarshal(got, &cfg); err != nil {
		t.Fatal(err)
	}
	args := cfg.Modules["host-state-snapshot"].Args
	for flag, want := range map[string]string{"socket-interval": "15m0s", "identity-interval": "20m0s", "service-interval": "30m0s", "kernel-interval": "1h0m0s", "full-snapshot-interval": "24h", "state": "keep-state.json"} {
		if value, _ := stringFlag(args, flag); value != want {
			t.Fatal(flag, value, want)
		}
	}
	if cfg.Modules["host-state-snapshot"].Enabled || !reflect.DeepEqual(cfg.Modules["audit-port-execmon"].Args, []string{"-learning-mode", "enforce"}) {
		t.Fatal("enablement/learning changed", cfg)
	}
	if changed, err := applyManagedRuntimePolicy(path, policy); err != nil || changed {
		t.Fatal("repeated policy restarted", changed, err)
	}
	// A partial later policy must not assume defaults for omitted timers.
	socket = 25
	policy.HostIdentityIntervalMinutes, policy.HostServiceIntervalMinutes, policy.HostKernelContextIntervalMinutes = nil, nil, nil
	if _, err := applyManagedRuntimePolicy(path, policy); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	if !bytes.Contains(got, []byte("20m0s")) || !bytes.Contains(got, []byte("1h0m0s")) {
		t.Fatal("omitted values reset", string(got))
	}
	for _, invalid := range []int{0, -1, 1441} {
		policy.HostSocketIntervalMinutes = &invalid
		if _, err := applyManagedRuntimePolicy(path, policy); err == nil {
			t.Fatal("invalid state interval accepted", invalid)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(after, got) {
			t.Fatal("invalid policy rewrote configuration")
		}
	}
}

// Go flag duplicates, inline forms, terminators and a path named like a flag
// must retain their original ownership when several durations change at once.
func TestRuntimeHostStateCadenceArgs(t *testing.T) {
	desired := map[string]time.Duration{"socket-interval": 15 * time.Minute, "kernel-interval": time.Hour}
	args := []string{"-state", "-socket-interval", "--socket-interval=5m", "-socket-interval", "6m", "--"}
	got, changed, err := runtimeCadenceArgs(args, "host-state-snapshot", desired)
	if err != nil || !changed {
		t.Fatal(got, changed, err)
	}
	want := []string{"-state", "-socket-interval", "--socket-interval=15m0s", "-socket-interval", "15m0s", "-kernel-interval", "1h0m0s", "--"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got, want)
	}
	if _, changed, err := runtimeCadenceArgs(got, "host-state-snapshot", desired); err != nil || changed {
		t.Fatal("nonconvergent state flags", changed, err)
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
	desired := map[string]time.Duration{"interval": 30 * time.Minute}
	for _, args := range [][]string{nil, {"--interval", "10m"}, {"-interval=10m"}, {"-interval", "10m", "--interval=20m"}, {"-state", "-interval", "--"}} {
		got, changed, err := runtimeCadenceArgs(args, "host-process-snapshot", desired)
		if err != nil || !changed {
			t.Fatal(got, changed, err)
		}
		if _, changed, err = runtimeCadenceArgs(got, "host-process-snapshot", desired); err != nil || changed {
			t.Fatal("nonconvergent argv", got, err)
		}
	}
	if _, changed, err := runtimeCadenceArgs([]string{"--interval=1800s"}, "host-process-snapshot", desired); err != nil || changed {
		t.Fatal("equivalent duration changed")
	}
	if runtimePolicyRestartAllowed(&agentlicense.UpdateReport{HealthPending: true}) || runtimePolicyRestartAllowed(&agentlicense.UpdateReport{Status: "state_read_failed"}) {
		t.Fatal("unsafe upgrade restart allowed")
	}
}
