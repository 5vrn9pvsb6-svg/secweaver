package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"secweaver-agent/pkg/agentlicense"
)

// Mixed-unit settings must converge while preserving watch configs, comparison
// state, enablement and learning flags. Failed edits leave the file untouched.
func TestExtendedCollectionCadencePreservesState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"enterprise_id":"0123456789ABCDEF","license":{"heartbeat_interval_seconds":300},"operations_report":{"enabled":false,"snapshot_interval_seconds":300,"jitter_seconds":30,"output":"keep-health.log"},"modules":{"host-persistence":{"enabled":false,"args":["-config","keep-watch.json","--poll-interval=30s","-state","keep-files.json"]},"host-process-snapshot":{"enabled":true,"args":["-interval","30m","-full-snapshot-interval","24h","-state","keep-process.json"]},"host-state-snapshot":{"enabled":false,"args":["-socket-interval","5m","-full-snapshot-interval","24h","-state","keep-state.json"]},"audit-port-execmon":{"enabled":false,"args":["-learning-mode","enforce"]}}}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	policy := &agentlicense.RuntimePolicy{HostProcessIntervalMinutes: 30, HeartbeatIntervalMinutes: 5, Revision: 1}
	if changed, err := applyManagedRuntimePolicy(path, policy); err != nil || changed {
		t.Fatal("omitted fields changed timers", changed, err)
	}
	health, persistence, fullProcess, fullState := 15, 60, 48, 72
	policy.HealthReportIntervalMinutes, policy.HostPersistenceIntervalSeconds = &health, &persistence
	policy.HostProcessFullSnapshotHours, policy.HostStateFullSnapshotHours = &fullProcess, &fullState
	if changed, err := applyManagedRuntimePolicy(path, policy); err != nil || !changed {
		t.Fatal(changed, err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	report, err := normalizeOperationsReportConfig(cfg.Operations)
	if err != nil || report.Enabled || report.SnapshotInterval.Seconds() != 900 || report.Jitter.Seconds() != 30 {
		t.Fatal("health options changed", report, err)
	}
	for name, flags := range map[string]map[string]string{
		"host-persistence":      {"poll-interval": "1m0s", "config": "keep-watch.json", "state": "keep-files.json"},
		"host-process-snapshot": {"interval": "30m", "full-snapshot-interval": "48h0m0s", "state": "keep-process.json"},
		"host-state-snapshot":   {"socket-interval": "5m", "full-snapshot-interval": "72h0m0s", "state": "keep-state.json"},
		"audit-port-execmon":    {"learning-mode": "enforce"},
	} {
		for flag, want := range flags {
			if got, _ := stringFlag(cfg.Modules[name].Args, flag); got != want {
				t.Fatal(name, flag, got, want)
			}
		}
	}
	if *cfg.Modules["host-persistence"].Enabled || *cfg.Modules["host-state-snapshot"].Enabled || !*cfg.Modules["host-process-snapshot"].Enabled {
		t.Fatal("module enablement changed")
	}
	before, _ := os.ReadFile(path)
	if changed, err := applyManagedRuntimePolicy(path, policy); err != nil || changed {
		t.Fatal("replay did not converge", changed, err)
	}
	policy.HealthReportIntervalMinutes, policy.HostPersistenceIntervalSeconds, policy.HostProcessFullSnapshotHours, policy.HostStateFullSnapshotHours = nil, nil, nil, nil
	if changed, err := applyManagedRuntimePolicy(path, policy); err != nil || changed {
		t.Fatal("old policy reset timers", changed, err)
	}
	for _, setting := range []struct {
		target   **int
		min, max int
	}{
		{&policy.HealthReportIntervalMinutes, 1, 1440}, {&policy.HostPersistenceIntervalSeconds, 10, 3600},
		{&policy.HostProcessFullSnapshotHours, 1, 168}, {&policy.HostStateFullSnapshotHours, 1, 168},
	} {
		for _, bad := range []int{0, setting.min - 1, setting.max + 1} {
			*setting.target = &bad
			if _, err := applyManagedRuntimePolicy(path, policy); err == nil {
				t.Fatal("invalid timer accepted", bad)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("invalid timer partially rewrote config")
			}
		}
		*setting.target = nil
	}
	// A report absent from local config is not silently introduced/enabled.
	if err := os.WriteFile(path, []byte(`{"license":{"heartbeat_interval_seconds":300},"modules":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	policy.HealthReportIntervalMinutes = &health
	if changed, err := applyManagedRuntimePolicy(path, policy); err != nil || changed {
		t.Fatal("missing report became managed", changed, err)
	}
}
