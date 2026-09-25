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
		DeploymentMode: deploymentES, Enabled: true, Output: path, SnapshotInterval: time.Hour, MaxSizeBytes: output.DefaultMaxSizeBytes, MaxBackups: 1,
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
		if event.DeploymentMode != deploymentES {
			t.Fatalf("health log lost deployment ownership: %+v", event)
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

// A local collector fault must be observable in the emitted health document,
// while both healthy and broken collectors retain unverified cloud delivery.
func TestOperationsReporterReflectsLocalShipperFailure(t *testing.T) {
	for _, broken := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "health.log")
		tracker := newStatusTracker(filepath.Join(dir, "status.json"), "", agentlicense.Config{}, nil)
		reporter := newAgentOperationsReporter(operationsReportRuntime{Enabled: true, IncludeShipperStatus: true, Output: path, SnapshotInterval: time.Hour, MaxSizeBytes: output.DefaultMaxSizeBytes, MaxBackups: 1}, tracker, nil, output.HostIdentity{HostName: "test"}, "test")
		// Seed before the owner goroutine starts; any unwanted re-probe would
		// replace this fixture with the developer machine's unknown collector.
		reporter.shipperCheckedAt = time.Now()
		reporter.shipperStatus = operationsShipper{Type: "logtail", Configuration: "configured", ServiceStatus: "active", ProcessStatus: "running", CloudDelivery: "unverified", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
		if broken {
			reporter.shipperStatus.ProcessStatus = "unhealthy"
		}
		reporter.start()
		waitForOperationsReport(t, path)
		if err := reporter.close(); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var event operationsReportEvent
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				t.Fatal(err)
			}
			if event.Shipper == nil || event.Shipper.Type != "logtail" || event.Shipper.CloudDelivery != "unverified" {
				t.Fatalf("invalid shipper: %+v", event.Shipper)
			}
			if containsOperationsString(event.ReasonCodes, "shipper_local_unhealthy") != broken {
				t.Fatalf("invalid reasons: %+v", event)
			}
			if broken && event.HealthStatus == "healthy" {
				t.Fatalf("false healthy report: %+v", event)
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		f.Close()
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
