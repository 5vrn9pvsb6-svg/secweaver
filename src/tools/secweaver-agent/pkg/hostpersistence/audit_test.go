package hostpersistence

import (
	"context"

	"errors"
	"os"
	"path/filepath"

	"testing"
	"time"
)

// These tests cover audit configuration, watch parsing, timeout handling, rollback, and bounded correlation.

func TestLoadRuntimeConfigAuditFollowLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"audit":{"follow_log":false}}`)
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadRuntimeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.FollowLog {
		t.Fatal("expected audit.follow_log=false to disable audit log follower")
	}
}

func TestParseAuditWatchListLine(t *testing.T) {
	path, perm, ok := parseAuditWatchListLine(`-w /etc/cron.d -p wa -k tb_host_persistence`, "tb_host_persistence")
	if !ok || path != "/etc/cron.d" || perm != "wa" {
		t.Fatalf("path=%q perm=%q ok=%v", path, perm, ok)
	}
	if _, _, ok := parseAuditWatchListLine(`-a always,exit -F arch=b64 -S execve -F key=tb_external_listener_exec`, "tb_host_persistence"); ok {
		t.Fatal("non-watch rule should not match host-persistence watch parser")
	}
	if _, _, ok := parseAuditWatchListLine(`-w /etc/cron.d -p wa -k other_key`, "tb_host_persistence"); ok {
		t.Fatal("different key should not match")
	}
}

func TestRunAuditctlUsesTimeout(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		if timeout != auditctlTimeout {
			t.Fatalf("timeout = %s, want %s", timeout, auditctlTimeout)
		}
		return nil, context.DeadlineExceeded
	}
	if err := runAuditctl("-s"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runAuditctl error = %v", err)
	}
}

func TestStartAuditEnrichmentRollsBackPartialWatchSetup(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	dir := t.TempDir()
	first := filepath.Join(dir, "a")
	second := filepath.Join(dir, "b")
	for _, path := range []string{first, second} {
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(args) > 1 && args[0] == "-w" && args[1] == second {
			return nil, errors.New("forced watch failure")
		}
		return nil, nil
	}
	cfg := runtimeConfig{
		Audit: auditRuntimeConfig{
			Enabled: true, Key: "tb_host_persistence", Perm: "wa", ManageRules: true, FailOnError: true,
		},
		Watch: []watchTarget{{Path: first}, {Path: second}},
	}
	if _, _, err := startAuditEnrichment(context.Background(), cfg); err == nil {
		t.Fatal("expected partial watch setup failure")
	}
	deleteByKeyCalls := 0
	for _, call := range calls {
		if len(call) == 3 && call[0] == "-D" && call[1] == "-k" {
			deleteByKeyCalls++
		}
	}
	if deleteByKeyCalls != 2 {
		t.Fatalf("delete-by-key calls = %d, want startup cleanup and rollback; calls=%#v", deleteByKeyCalls, calls)
	}
}

func TestAuditTrackerBoundsUniquePaths(t *testing.T) {
	tracker := newAuditTracker(time.Hour, 2)
	tracker.maxPaths = 3
	for i, path := range []string{"/a", "/b", "/c", "/d"} {
		tracker.Add(auditChange{Timestamp: time.Now().Add(time.Duration(i) * time.Second), Paths: []string{path}})
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if len(tracker.byPath) != 3 {
		t.Fatalf("tracked paths = %d, want hard cap 3", len(tracker.byPath))
	}
	if _, exists := tracker.byPath["/a"]; exists {
		t.Fatal("oldest path should be evicted at the hard cap")
	}
}
