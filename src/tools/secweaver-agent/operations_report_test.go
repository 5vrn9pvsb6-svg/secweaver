package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/output"
)

func TestOperationsReporterWritesPrivateStructuredLifecycleRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secweaver-agent-health.log")
	tracker := newStatusTracker(filepath.Join(dir, "status.json"), "6X13NGV4G9CVK92E", agentlicense.Config{}, []runtimeModule{{Spec: moduleSpec{Name: "syslog-risk-json"}}})
	tracker.moduleStarting("syslog-risk-json", 123)
	reporter := newAgentOperationsReporter(operationsReportRuntime{
		Enabled: true, Output: path, SnapshotInterval: time.Hour, MaxSizeBytes: output.DefaultMaxSizeBytes, MaxBackups: 1,
	}, tracker, nil, output.HostIdentity{HostName: "test-host", HostIP: "10.0.0.1"}, "0.3.14")
	reporter.start()
	waitForOperationsReport(t, path)
	if err := reporter.close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("health log mode=%04o, want 0600", got)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		var event operationsReportEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.AssetType != operationsReportAssetType || event.EvidenceID == "" || event.Timestamp == "" || event.Host != "test-host" {
			t.Fatalf("invalid operations event: %+v", event)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count < 2 {
		t.Fatalf("records=%d, want startup and shutdown records", count)
	}
}

func TestNormalizeOperationsReportDefaultsAndDisable(t *testing.T) {
	config, err := normalizeOperationsReportConfig(operationsReportConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.SnapshotInterval != 5*time.Minute || config.Jitter != time.Minute {
		t.Fatalf("unexpected operations report defaults: %+v", config)
	}
	if config.MaxSizeBytes != output.DefaultMaxSizeBytes || config.MaxBackups != output.DefaultMaxBackups {
		t.Fatalf("unexpected operations report retention defaults: %+v", config)
	}

	falseValue := false
	config, err = normalizeOperationsReportConfig(operationsReportConfig{Enabled: &falseValue})
	if err != nil {
		t.Fatal(err)
	}
	if config.Enabled {
		t.Fatal("operations report remained enabled after explicit disable")
	}
}

func TestOperationsHealthIncludesStatusPersistenceFailure(t *testing.T) {
	status, severity, reasons := operationsHealth(agentStatusFile{
		Modules:     map[string]agentlicense.ModuleHealth{"syslog-risk-json": {Status: "running", PID: 123}},
		Persistence: statusPersistence{LastError: "disk full", ErrorCount: 1},
	}, auditDemuxMetrics{})
	if status != "unhealthy" || severity != "high" || !containsOperationsString(reasons, "status_persistence_error") {
		t.Fatalf("persistence failure was not elevated: status=%q severity=%q reasons=%v", status, severity, reasons)
	}
}

// waitForOperationsReport waits only for file creation; the reporter's own
// buffered writer controls delivery and the test never sleeps for a snapshot.
func waitForOperationsReport(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("operations report was not created: %s", path)
}
