package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"secweaver-agent/pkg/agentlicense"
)

func TestStatusTrackerWritesModuleAndLicenseState(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "status.json")
	statePath := filepath.Join(dir, "license-state.json")
	if err := agentlicense.SaveState(statePath, agentlicense.State{DeviceID: "device-from-state"}); err != nil {
		t.Fatal(err)
	}
	modules := []runtimeModule{
		{Spec: moduleSpec{Name: "syslog-risk-json"}},
		{Spec: moduleSpec{Name: "host-persistence"}},
	}
	tracker := newStatusTracker(statusPath, "6X13NGV4G9CVK92E", agentlicense.Config{
		Enabled:   true,
		StatePath: statePath,
	}, modules)

	tracker.write()
	tracker.moduleStarting("syslog-risk-json", 1234)
	tracker.licenseCheck(agentlicense.Result{State: agentlicense.State{DeviceID: "device-from-check"}}, nil)
	tracker.heartbeat(errors.New("temporary network error"))

	data, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	var got agentStatusFile
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.EnterpriseID != "6X13NGV4G9CVK92E" || got.DeviceID != "device-from-state" {
		t.Fatalf("unexpected identity fields: %+v", got)
	}
	if !got.License.Enabled || got.License.LastCheckAt == "" || got.License.LastError != "temporary network error" {
		t.Fatalf("unexpected license status: %+v", got.License)
	}
	if got.Modules["syslog-risk-json"].Status != "running" || got.Modules["syslog-risk-json"].PID != 1234 {
		t.Fatalf("unexpected syslog module status: %+v", got.Modules["syslog-risk-json"])
	}
	if got.Modules["host-persistence"].Status != "configured" {
		t.Fatalf("unexpected host-persistence status: %+v", got.Modules["host-persistence"])
	}
}

func TestStatusTrackerWritesDiagnostics(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "status.json")
	tracker := newStatusTracker(statusPath, "6X13NGV4G9CVK92E", agentlicense.Config{}, nil)
	tracker.setDiagnostic("audit_demux/audit-port-execmon", "warn", "audit demux subscriber queue dropped lines", map[string]uint64{"dropped_lines": 1000})
	data, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	var got agentStatusFile
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	diag := got.Diagnostics["audit_demux/audit-port-execmon"]
	if diag.Level != "warn" || diag.Metrics["dropped_lines"] != 1000 {
		t.Fatalf("unexpected diagnostic: %+v", diag)
	}
}

func TestAllModulesRunningRequiresStableObservationWindow(t *testing.T) {
	modules := []runtimeModule{
		{Spec: moduleSpec{Name: "syslog-risk-json"}},
		{Spec: moduleSpec{Name: "host-persistence"}},
	}
	tracker := newStatusTracker(filepath.Join(t.TempDir(), "status.json"), "6X13NGV4G9CVK92E", agentlicense.Config{}, modules)

	tracker.moduleStarting("syslog-risk-json", 1234)
	tracker.moduleStarting("host-persistence", 1235)
	if !tracker.allModulesRunning() {
		t.Fatal("expected stable running modules to pass the update health gate")
	}

	tracker.moduleRestarting("host-persistence", errors.New("unexpected exit"), 0, 1)
	tracker.moduleStarting("host-persistence", 1236)
	if tracker.allModulesRunning() {
		t.Fatal("a module restart during update probation must fail the health gate")
	}
}

func TestStatusTrackerHealthRequiresFreshModuleOutput(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "host-process.log")
	modules := []runtimeModule{{
		Spec:   moduleRegistry["host-process-snapshot"],
		Config: moduleConfig{Args: []string{"-output", output}},
	}}
	tracker := newStatusTracker(filepath.Join(dir, "status.json"), "6X13NGV4G9CVK92E", agentlicense.Config{}, modules)
	tracker.moduleStarting("host-process-snapshot", 123)
	if tracker.allModulesHealthySince(time.Now().Add(-time.Minute)) {
		t.Fatal("missing output must not pass update probation")
	}
	if err := os.WriteFile(output, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !tracker.allModulesHealthySince(time.Now().Add(-time.Minute)) {
		t.Fatal("running module with fresh output should pass update probation")
	}
}

func TestStatusTrackerHealthRequiresEveryPeriodicOutput(t *testing.T) {
	dir := t.TempDir()
	processOutput := filepath.Join(dir, "host-process.log")
	stateOutput := filepath.Join(dir, "host-state.log")
	modules := []runtimeModule{
		{Spec: moduleRegistry["host-process-snapshot"], Config: moduleConfig{Args: []string{"-output", processOutput}}},
		{Spec: moduleRegistry["host-state-snapshot"], Config: moduleConfig{Args: []string{"-output", stateOutput}}},
	}
	tracker := newStatusTracker(filepath.Join(dir, "status.json"), "6X13NGV4G9CVK92E", agentlicense.Config{}, modules)
	tracker.moduleStarting("host-process-snapshot", 123)
	tracker.moduleStarting("host-state-snapshot", 124)
	if err := os.WriteFile(processOutput, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if tracker.allModulesHealthySince(time.Now().Add(-time.Minute)) {
		t.Fatal("one fresh periodic output must not hide another missing output")
	}
	if err := os.WriteFile(stateOutput, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !tracker.allModulesHealthySince(time.Now().Add(-time.Minute)) {
		t.Fatal("all periodic outputs are fresh")
	}
}

func TestStatusTrackerManagedHealthRequiresFreshHeartbeat(t *testing.T) {
	dir := t.TempDir()
	modules := []runtimeModule{{Spec: moduleSpec{Name: "syslog-risk-json"}}}
	tracker := newStatusTracker(filepath.Join(dir, "status.json"), "6X13NGV4G9CVK92E", agentlicense.Config{Enabled: true}, modules)
	tracker.moduleStarting("syslog-risk-json", 123)
	since := time.Now().Add(-time.Second)
	if tracker.allModulesHealthySince(since) {
		t.Fatal("managed update health passed before a control-plane heartbeat")
	}
	tracker.heartbeat(nil)
	if !tracker.allModulesHealthySince(since) {
		t.Fatal("fresh successful heartbeat should satisfy the managed control-plane health gate")
	}
	tracker.heartbeat(errors.New("control plane unavailable"))
	if tracker.allModulesHealthySince(since) {
		t.Fatal("latest heartbeat failure must fail the managed control-plane health gate")
	}
}

func TestStatusTrackerReadinessReflectsCurrentFailures(t *testing.T) {
	modules := []runtimeModule{{Spec: moduleSpec{Name: "audit-port-execmon"}}}
	tracker := newStatusTracker(filepath.Join(t.TempDir(), "status.json"), "6X13NGV4G9CVK92E", agentlicense.Config{Enabled: true}, modules)
	if ready, _ := tracker.readiness(); ready {
		t.Fatal("configured but unstarted module must not be ready")
	}

	tracker.moduleStarting("audit-port-execmon", 123)
	tracker.licenseCheck(agentlicense.Result{}, nil)
	if ready, reason := tracker.readiness(); !ready {
		t.Fatalf("running module should be ready: %s", reason)
	}

	tracker.moduleRestarting("audit-port-execmon", errors.New("crash"), time.Second, 1)
	if ready, _ := tracker.readiness(); ready {
		t.Fatal("restarting module must not be ready")
	}
	tracker.moduleStarting("audit-port-execmon", 124)
	if ready, reason := tracker.readiness(); !ready {
		t.Fatalf("recovered module should be ready despite historical restart count: %s", reason)
	}

	tracker.setDiagnostic("audit_demux/audit-port-execmon", "warn", "subscriber restarted", nil)
	if ready, reason := tracker.readiness(); !ready {
		t.Fatalf("warning diagnostic must not fail readiness: %s", reason)
	}
	tracker.setDiagnostic("audit_demux/audit-port-execmon", "error", "evidence overwritten", map[string]uint64{"backlog_overflows": 1})
	if ready, reason := tracker.readiness(); ready || !strings.Contains(reason, "evidence overwritten") {
		t.Fatalf("error diagnostic readiness = %v reason=%q", ready, reason)
	}
}

func TestStatusTrackerClearDiagnosticRestoresReadiness(t *testing.T) {
	modules := []runtimeModule{{Spec: moduleSpec{Name: "audit-port-execmon"}}}
	tracker := newStatusTracker(filepath.Join(t.TempDir(), "status.json"), "6X13NGV4G9CVK92E", agentlicense.Config{}, modules)
	tracker.moduleStarting("audit-port-execmon", 123)
	tracker.setDiagnostic("audit_demux/reader/audit.log", "error", "reader unavailable", nil)
	if ready, _ := tracker.readiness(); ready {
		t.Fatal("reader error must fail readiness")
	}
	tracker.clearDiagnostic("audit_demux/reader/audit.log")
	if ready, reason := tracker.readiness(); !ready {
		t.Fatalf("cleared recoverable diagnostic should restore readiness: %s", reason)
	}
}

func TestStatusWriterReportsRetriesAndRecoversFromDiskFailure(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "status.json")
	modules := []runtimeModule{{Spec: moduleSpec{Name: "audit-port-execmon"}}}
	tracker := newStatusTracker(statusPath, "6X13NGV4G9CVK92E", agentlicense.Config{}, modules)
	tracker.write()
	tracker.writeInterval = 10 * time.Millisecond
	var allowWrite atomic.Bool
	tracker.writeFile = func(path string, payload interface{}, perm os.FileMode) error {
		if !allowWrite.Load() {
			return errors.New("disk is read-only")
		}
		return writeJSONAtomic(path, payload, perm)
	}
	tracker.startWriter()
	tracker.moduleStarting("audit-port-execmon", 321)

	waitForStatusCondition(t, time.Second, func() bool {
		tracker.mu.Lock()
		defer tracker.mu.Unlock()
		return tracker.persistence.LastError == "disk is read-only" && tracker.persistence.ErrorCount > 0
	})
	if ready, reason := tracker.readiness(); ready || !strings.Contains(reason, "status persistence") {
		t.Fatalf("readiness during status failure = %v reason=%q", ready, reason)
	}

	allowWrite.Store(true)
	waitForStatusCondition(t, time.Second, func() bool {
		tracker.mu.Lock()
		defer tracker.mu.Unlock()
		return tracker.persistence.LastError == "" && tracker.persistence.LastSuccessAt != ""
	})
	if err := tracker.closeWriter(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	var got agentStatusFile
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Persistence.ErrorCount == 0 || got.Persistence.LastError != "" {
		t.Fatalf("unexpected persistence recovery state: %+v", got.Persistence)
	}
}

func TestStatusWriterCloseFlushesPendingState(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "status.json")
	modules := []runtimeModule{{Spec: moduleSpec{Name: "syslog-risk-json"}}}
	tracker := newStatusTracker(statusPath, "6X13NGV4G9CVK92E", agentlicense.Config{}, modules)
	tracker.write()
	tracker.writeInterval = time.Hour
	tracker.startWriter()
	tracker.moduleStarting("syslog-risk-json", 456)
	if err := tracker.closeWriter(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	var got agentStatusFile
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if health := got.Modules["syslog-risk-json"]; health.Status != "running" || health.PID != 456 {
		t.Fatalf("final status was not flushed: %+v", health)
	}
}

func TestStatusWriterCoalescesRapidMutations(t *testing.T) {
	dir := t.TempDir()
	tracker := newStatusTracker(filepath.Join(dir, "status.json"), "6X13NGV4G9CVK92E", agentlicense.Config{}, []runtimeModule{{Spec: moduleSpec{Name: "syslog-risk-json"}}})
	tracker.write()
	tracker.writeInterval = 40 * time.Millisecond
	var writes atomic.Int32
	tracker.writeFile = func(path string, payload interface{}, perm os.FileMode) error {
		writes.Add(1)
		return writeJSONAtomic(path, payload, perm)
	}
	tracker.startWriter()
	tracker.moduleStarting("syslog-risk-json", 789)
	for index := 0; index < 50; index++ {
		tracker.setDiagnostic("coalesce", "warn", "rapid mutation", map[string]uint64{"index": uint64(index)})
	}
	time.Sleep(20 * time.Millisecond)
	if got := writes.Load(); got != 0 {
		t.Fatalf("writer did not wait for coalescing interval: writes=%d", got)
	}
	waitForStatusCondition(t, time.Second, func() bool { return writes.Load() == 1 })
	time.Sleep(60 * time.Millisecond)
	if got := writes.Load(); got != 1 {
		t.Fatalf("rapid mutations produced %d writes, want 1", got)
	}
	if err := tracker.closeWriter(); err != nil {
		t.Fatal(err)
	}
}

func waitForStatusCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for status condition")
}
