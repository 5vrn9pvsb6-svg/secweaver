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
	"secweaver-agent/pkg/eventwhitelist"
	agentoutput "secweaver-agent/pkg/output"
)

func TestConfiguredAlertOutputBudget(t *testing.T) {
	disabled := false
	configPath := filepath.Join(t.TempDir(), "etc", "config.json")
	defaultPath := filepath.Join(filepath.Dir(filepath.Dir(configPath)), "logs", "custom-risk-alert.log")
	for _, tc := range []struct {
		name     string
		protocol string
		rules    eventwhitelist.Config
		want     string
	}{
		{name: "legacy"},
		{name: "device before enrollment", protocol: "device_v2", want: defaultPath},
		{name: "disabled", protocol: "device_v2", rules: eventwhitelist.Config{Enabled: &disabled}},
		{name: "custom", protocol: "device_v2", rules: eventwhitelist.Config{AlertOutput: filepath.Join(t.TempDir(), "alerts.log")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			if tc.name == "custom" {
				want = tc.rules.AlertOutput
			}
			cfg := agentConfig{License: agentlicense.Config{Protocol: tc.protocol}, CollectionRules: tc.rules}
			path := configuredAlertOutput(cfg, configPath)
			if path != want {
				t.Fatalf("alert path=%q, want %q", path, want)
			}
			count := 0
			if want != "" {
				count = 1
			}
			if got := configuredOutputFileCount(nil, nil, nil, path); got != count {
				t.Fatalf("alert budget count=%d, want %d", got, count)
			}
		})
	}
}

func TestManagedLogsDeduplicateAllWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.log")
	module := runtimeModule{Spec: moduleDescriptor{Name: "fixture", OutputPaths: func([]string) []string {
		return []string{path, "-", ""}
	}}}
	outputs := configuredLogOutputs([]runtimeModule{module}, &scheduledUpdateConfig{StatusOutput: path},
		&operationsReportRuntime{Enabled: true, Output: path, MaxSizeBytes: 10, MaxBackups: 2}, path)
	if len(outputs) != 1 || outputs[0].MaxSizeBytes != 10 || outputs[0].MaxBackups != 2 || !strings.Contains(outputs[0].Name, "custom-risk-alert") {
		t.Fatalf("deduplicated inventory=%+v", outputs)
	}
	if got := configuredOutputFileCount([]runtimeModule{module}, nil, &operationsReportRuntime{Output: "/disabled"}, path); got != 1 {
		t.Fatalf("disabled operations reserved a slot: %d", got)
	}
}

func TestDoctorInspectManagedLogs(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "events.log"), filepath.Join(dir, "health.log"), filepath.Join(dir, "update.log"), filepath.Join(dir, "alerts.log")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("event\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := agentConfig{
		License: agentlicense.Config{Protocol: "device_v2"}, CollectionRules: eventwhitelist.Config{AlertOutput: paths[3]},
		Operations: operationsReportConfig{Output: paths[1], MaxSizeMB: 2, MaxBackups: 2},
	}
	modules := []runtimeModule{{Spec: moduleDescriptor{Name: "fixture", OutputPaths: func([]string) []string { return []string{paths[0]} }}}}
	var checks []doctorCheck
	logs := doctorInspectLogs(cfg, filepath.Join(dir, "etc", "config.json"), modules, &scheduledUpdateConfig{StatusOutput: paths[2]},
		func(level doctorLevel, component, message, detail string) {
			checks = append(checks, doctorCheck{level, component, message, detail})
		})
	if len(logs) != 4 || len(checks) != 0 {
		t.Fatalf("logs=%+v checks=%+v", logs, checks)
	}
	for _, entry := range logs {
		if entry.CurrentSizeBytes == nil || *entry.CurrentSizeBytes != 6 || entry.PerFileBudgetBytes != 2048*1024*1024/4 || !entry.ScanComplete {
			t.Fatalf("incorrect file diagnostics: %+v", entry)
		}
		if entry.Name == "agent-health" && (entry.MaxSizeBytes != 2<<20 || entry.MaxBackups != 2) {
			t.Fatalf("health limits ignored: %+v", entry)
		}
	}
	var text bytes.Buffer
	printDoctorReport(&text, doctorReport{Logs: logs}, false)
	for _, marker := range []string{"log retention", "custom-risk-alert: current=6", "backups=0/5", "last_rotation=unknown"} {
		if !strings.Contains(text.String(), marker) {
			t.Fatalf("nonverbose doctor missing %q: %s", marker, text.String())
		}
	}
	body, err := json.Marshal(doctorReport{Logs: logs})
	if err != nil {
		t.Fatal(err)
	}
	var decoded doctorReport
	if err := json.Unmarshal(body, &decoded); err != nil || !reflect.DeepEqual(logs, decoded.Logs) {
		t.Fatalf("JSON inventory did not round trip: %s, %v", body, err)
	}
}

func TestDoctorRotationInspectionIsReadOnly(t *testing.T) {
	t.Setenv("SECWEAVER_OUTPUT_BUDGET_ENABLED", "false")
	path := filepath.Join(t.TempDir(), "events.log")
	writer, err := agentoutput.OpenRotatingFile(path, 0600, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err := writer.Write([]byte("test\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 10, 16, 1, 2, 3, 0, time.UTC)
	if err := os.Chtimes(path+".1", stamp, stamp); err != nil {
		t.Fatal(err)
	}
	// Backups outside the configured retention still count; doctor must not
	// prune them merely because a future writer open would enforce new limits.
	for _, suffix := range []string{".7", ".notes", ".0", ".-1", ".1.gz"} {
		if err := os.WriteFile(path+suffix, []byte("old"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	entry := inspectDoctorLog(managedLogOutput{Name: "fixture", Path: path}, agentoutput.RetentionLimits{MaxSizeBytes: 10, MaxBackups: 1})
	if entry.BackupCount != 2 || entry.BackupSizeBytes != 13 || entry.TotalSizeBytes != 23 || entry.LastRotationEstimate != stamp.Format(time.RFC3339Nano) || entry.RotationTimeSource != "backup_mtime_estimate" || !entry.ScanComplete {
		t.Fatalf("rotation inventory=%+v", entry)
	}
	after, err := os.Stat(path + ".1")
	if err != nil || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() {
		t.Fatalf("doctor changed backup metadata: %v", err)
	}
	if body, err := os.ReadFile(path + ".7"); err != nil || string(body) != "old" {
		t.Fatalf("doctor pruned/modified backup: %q %v", body, err)
	}
}

func TestDoctorLogMissingAndNonregular(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "events.log")
	entry := inspectDoctorLog(managedLogOutput{Path: path}, agentoutput.RetentionLimits{})
	if entry.CurrentSizeBytes != nil || entry.BackupCount != 0 || entry.RotationTimeSource != "unknown" || !entry.ScanComplete {
		t.Fatalf("missing log should not invent observations: %+v", entry)
	}
	if err := os.MkdirAll(path+".1", 0700); err != nil {
		t.Fatal(err)
	}
	entry = inspectDoctorLog(managedLogOutput{Path: path}, agentoutput.RetentionLimits{})
	if entry.ScanComplete || entry.BackupCount != 0 || entry.InspectionError == "" {
		t.Fatalf("nonregular backup was treated as a log: %+v", entry)
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	entry = inspectDoctorLog(managedLogOutput{Path: path}, agentoutput.RetentionLimits{})
	if entry.ScanComplete || entry.CurrentSizeBytes != nil {
		t.Fatalf("nonregular active file accepted: %+v", entry)
	}
}

func TestDoctorLogScanLimitAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")
	for _, suffix := range []string{"", ".1", ".2"} {
		if err := os.WriteFile(path+suffix, []byte("event"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	entry := inspectDoctorLogWithLimit(managedLogOutput{Path: path}, agentoutput.RetentionLimits{}, 1)
	if entry.ScanComplete || !strings.Contains(entry.InspectionError, "scan limit") {
		t.Fatalf("bounded scan claimed complete inventory: %+v", entry)
	}
	if err := os.Symlink(path, path+".3"); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	entry = inspectDoctorLog(managedLogOutput{Path: path}, agentoutput.RetentionLimits{})
	if entry.ScanComplete || entry.BackupCount != 2 || entry.BackupSizeBytes != 10 || !strings.Contains(entry.InspectionError, "not a regular file") {
		t.Fatalf("symlink backup was followed: %+v", entry)
	}
}

func TestAlertBudgetIncludedWithModuleLearningAndParentStreams(t *testing.T) {
	dir := t.TempDir()
	outputs := make([]string, 6)
	for i := range outputs {
		outputs[i] = filepath.Join(dir, string(rune('a'+i))+".log")
	}
	modules := []runtimeModule{{Spec: moduleDescriptor{Name: "fixture-with-learning", OutputPaths: func([]string) []string { return outputs }}}}
	updater := &scheduledUpdateConfig{StatusOutput: filepath.Join(dir, "update.log")}
	operations := &operationsReportRuntime{Enabled: true, Output: filepath.Join(dir, "health.log")}
	alertPath := filepath.Join(dir, "alerts.log")
	files := configuredOutputFileCount(modules, updater, operations, alertPath)
	if files != 9 {
		t.Fatalf("budget divisor=%d, want 9 including alert", files)
	}
	limits, err := agentoutput.EffectiveRetention(agentoutput.DiskBudgetConfig{}, files, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxSizeBytes != 39768215 || limits.PerFileBudgetBytes != 238609294 || limits.MaxBackups != 5 {
		t.Fatalf("nine-output default limits=%+v", limits)
	}
}
