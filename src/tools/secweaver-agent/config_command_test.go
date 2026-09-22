package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"secweaver-agent/pkg/agentlicense"
)

func TestSetEnterpriseIDInConfigPreservesKnownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{
  "enterprise_id": "REPLACE_WITH_16_CHAR_ID",
  "modules": {"syslog-risk-json": {"enabled": true}}
}`)
	if err := os.WriteFile(path, body, 0640); err != nil {
		t.Fatal(err)
	}
	got, err := setEnterpriseIDInConfig(path, "6x13ngv4g9cvk92e")
	if err != nil {
		t.Fatal(err)
	}
	if got != "6X13NGV4G9CVK92E" {
		t.Fatalf("enterprise ID = %q", got)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(updated, &payload); err != nil {
		t.Fatal(err)
	}
	if string(payload["enterprise_id"]) != `"6X13NGV4G9CVK92E"` {
		t.Fatalf("unexpected config: %s", updated)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("permissions = %o", info.Mode().Perm())
	}
}

func TestSetEnterpriseIDInConfigRejectsInvalidValueWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"modules":{"syslog-risk-json":{"enabled":true}}}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := setEnterpriseIDInConfig(path, "invalid"); err == nil {
		t.Fatal("expected invalid enterprise ID error")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != string(body) {
		t.Fatalf("invalid update changed config: %s", unchanged)
	}
}

func TestSetLicenseInConfigWritesValidatedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{
  "enterprise_id": "6X13NGV4G9CVK92E",
  "modules": {"syslog-risk-json": {"enabled": true}}
}`)
	if err := os.WriteFile(path, body, 0640); err != nil {
		t.Fatal(err)
	}
	failClosed := true
	err := setLicenseInConfig(path, agentlicense.Config{
		Enabled:              true,
		ServerURL:            "https://shield.example.com",
		EnrollmentID:         "sw-enroll-test-token",
		CheckIntervalSeconds: 21600,
		HeartbeatSeconds:     180,
		OutageGraceSeconds:   intPointer(86400),
		FailClosed:           &failClosed,
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		License agentlicense.Config `json:"license"`
	}
	if err := json.Unmarshal(updated, &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.License.Enabled || payload.License.ServerURL != "https://shield.example.com" || payload.License.EnrollmentID != "sw-enroll-test-token" {
		t.Fatalf("license not configured: %+v", payload.License)
	}
	if payload.License.HeartbeatSeconds != 180 {
		t.Fatalf("heartbeat interval not configured: %+v", payload.License)
	}
	if payload.License.OutageGraceSeconds == nil || *payload.License.OutageGraceSeconds != 86400 {
		t.Fatalf("outage grace not configured: %+v", payload.License)
	}
}

func TestMigrateConfigLayoutPreservesCustomAndSystemPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{
  "status_path": "/var/lib/secweaver-agent/status.json",
  "modules": {
    "host-persistence": {
      "args": ["-output", "/var/log/host-persistence.log", "-audit-log", "/var/log/audit/audit.log"]
    },
    "custom": {"args": ["-output", "/srv/custom/events.log"]}
  }
}`)
	if err := os.WriteFile(path, body, 0640); err != nil {
		t.Fatal(err)
	}
	changed, err := migrateConfigLayout(path, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected known legacy paths to change")
	}
	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(migrated)
	for _, expected := range []string{
		`/opt/secweaver-agent/data/status.json`,
		`/opt/secweaver-agent/logs/host-persistence.log`,
		`/var/log/audit/audit.log`,
		`/srv/custom/events.log`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("migrated config does not contain %q: %s", expected, text)
		}
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("configuration permissions changed: info=%v err=%v", info, err)
	}
}

func intPointer(value int) *int {
	return &value
}

func TestSetUpdateInConfigEnablesSignedServerManagedUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"enterprise_id":"6X13NGV4G9CVK92E","modules":{"syslog-risk-json":{"enabled":true}}}`)
	if err := os.WriteFile(path, body, 0640); err != nil {
		t.Fatal(err)
	}
	autoInstall := true
	err := setUpdateInConfig(path, updateConfig{
		Enabled:              true,
		ManifestURL:          "https://updates.example.com/secweaver-agent/updates/stable/update-manifest.json",
		Channel:              "stable",
		IntervalSeconds:      21600,
		InitialDelaySeconds:  60,
		JitterSeconds:        300,
		AutoInstall:          &autoInstall,
		PublicKey:            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		RequireServerPolicy:  true,
		HealthTimeoutSeconds: 90,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Update.Enabled || !cfg.Update.RequireServerPolicy || cfg.Update.HealthTimeoutSeconds != 90 {
		t.Fatalf("unexpected update config: %+v", cfg.Update)
	}
}

func TestSetUpdateInConfigDefaultsToUnsignedUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"enterprise_id":"6X13NGV4G9CVK92E","modules":{"syslog-risk-json":{"enabled":true}}}`)
	if err := os.WriteFile(path, body, 0640); err != nil {
		t.Fatal(err)
	}
	if err := setUpdateInConfig(path, updateConfig{
		Enabled:     true,
		ManifestURL: "https://updates.example.com/secweaver-agent/updates/stable/update-manifest.json",
		Channel:     "stable",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Update.PublicKey != "" || len(cfg.Update.TrustedPublicKeys) != 0 {
		t.Fatalf("unsigned update configuration unexpectedly contains trust keys: %+v", cfg.Update)
	}
}

func TestEnsureHostProcessSnapshotAddsMissingModule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{
  "enterprise_id": "6X13NGV4G9CVK92E",
  "modules": {"syslog-risk-json": {"enabled": true}}
}`)
	if err := os.WriteFile(path, body, 0640); err != nil {
		t.Fatal(err)
	}
	added, err := ensureHostProcessSnapshotInConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !added {
		t.Fatal("missing module should be added")
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg agentConfig
	if err := json.Unmarshal(updated, &cfg); err != nil {
		t.Fatal(err)
	}
	module, ok := cfg.Modules["host-process-snapshot"]
	if !ok || module.Enabled == nil || !*module.Enabled {
		t.Fatalf("module not enabled: %+v", module)
	}
	if interval, ok := stringFlag(module.Args, "interval"); !ok || interval != "10m" {
		t.Fatalf("unexpected module args: %v", module.Args)
	}
	if full, ok := stringFlag(module.Args, "full-snapshot-interval"); !ok || full != "24h" {
		t.Fatalf("full snapshot interval missing: %v", module.Args)
	}
	if state, ok := stringFlag(module.Args, "state"); !ok || state == "" {
		t.Fatalf("state path missing: %v", module.Args)
	}
}

func TestEnsureHostProcessSnapshotPreservesExistingModule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{
  "enterprise_id": "6X13NGV4G9CVK92E",
  "modules": {"host_process_snapshot": {"enabled": false, "args": ["-interval", "30m"]}}
}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	added, err := ensureHostProcessSnapshotInConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if added {
		t.Fatal("existing normalized module must not be overwritten")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != string(body) {
		t.Fatalf("existing module changed: %s", unchanged)
	}
}

func TestEnsureHostStateSnapshotAddsMissingModule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"enterprise_id":"6X13NGV4G9CVK92E","modules":{"syslog-risk-json":{"enabled":true}}}`)
	if err := os.WriteFile(path, body, 0640); err != nil {
		t.Fatal(err)
	}
	added, err := ensureHostStateSnapshotInConfig(path)
	if err != nil || !added {
		t.Fatalf("added=%v err=%v", added, err)
	}
	var cfg agentConfig
	updated, _ := os.ReadFile(path)
	if err := json.Unmarshal(updated, &cfg); err != nil {
		t.Fatal(err)
	}
	module := cfg.Modules["host-state-snapshot"]
	if module.Enabled == nil || !*module.Enabled {
		t.Fatalf("module not enabled: %+v", module)
	}
	if interval, ok := stringFlag(module.Args, "socket-interval"); !ok || interval != "5m" {
		t.Fatalf("unexpected args: %v", module.Args)
	}
}

func TestEnsureHostStateSnapshotPreservesExplicitDisable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"modules":{"host_state_snapshot":{"enabled":false}}}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	added, err := ensureHostStateSnapshotInConfig(path)
	if err != nil || added {
		t.Fatalf("added=%v err=%v", added, err)
	}
	updated, _ := os.ReadFile(path)
	if string(updated) != string(body) {
		t.Fatalf("existing config changed: %s", updated)
	}
}

func TestOptimizeCollectorsMigratesLegacyWindowsReaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{
  "enterprise_id": "6X13NGV4G9CVK92E",
  "modules": {
    "windows-eventlog-risk-json": {"enabled": true, "args": ["-channels", "Security,System"]},
    "windows-process-execmon": {"enabled": true, "args": ["-channels", "Security,Microsoft-Windows-Sysmon/Operational"]},
    "host-process-snapshot": {"enabled": true, "args": ["-interval", "10m"]},
    "host-state-snapshot": {"enabled": true, "args": ["-socket-interval", "1m"]}
  }
}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := optimizeCollectorsInConfig(path)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	risk := cfg.Modules["windows-eventlog-risk-json"]
	channels, _ := stringFlag(risk.Args, "channels")
	if !strings.Contains(channels, "Microsoft-Windows-Sysmon/Operational") {
		t.Fatalf("risk channels were not merged: %v", risk.Args)
	}
	if evidence, ok := stringFlag(risk.Args, "evidence-output"); !ok || evidence == "" {
		t.Fatalf("evidence output missing: %v", risk.Args)
	}
	process := cfg.Modules["windows-process-execmon"]
	if process.Enabled == nil || *process.Enabled {
		t.Fatalf("duplicate Windows reader still enabled: %+v", process)
	}
	if timeout, _ := stringFlag(cfg.Modules["host-process-snapshot"].Args, "collection-timeout"); timeout != "45s" {
		t.Fatalf("collection timeout missing: %v", cfg.Modules["host-process-snapshot"].Args)
	}
	if full, _ := stringFlag(cfg.Modules["host-process-snapshot"].Args, "full-snapshot-interval"); full != "24h" {
		t.Fatalf("full snapshot interval missing: %v", cfg.Modules["host-process-snapshot"].Args)
	}
	if budget, _ := stringFlag(cfg.Modules["host-state-snapshot"].Args, "max-fd-scan"); budget != "100000" {
		t.Fatalf("FD scan budget missing: %v", cfg.Modules["host-state-snapshot"].Args)
	}
	changed, err = optimizeCollectorsInConfig(path)
	if err != nil || changed {
		t.Fatalf("second optimization must be idempotent: changed=%v err=%v", changed, err)
	}
}

func TestOptimizeCollectorsPreservesStandaloneReaderWhenRiskDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{
  "enterprise_id": "6X13NGV4G9CVK92E",
  "modules": {
    "windows-eventlog-risk-json": {"enabled": false},
    "windows-process-execmon": {"enabled": true}
  }
}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := optimizeCollectorsInConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("disabled risk module should not rewrite standalone reader configuration")
	}
}
