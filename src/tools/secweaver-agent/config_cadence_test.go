package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"secweaver-agent/pkg/agentlicense"
)

// Reinstallation uses the preserve sentinel; a caller can still deliberately
// change cadence. A blank first installation receives the new five-minute default.
func TestSetLicenseCadenceDefaultPreservesExisting(t *testing.T) {
	for _, tc := range []struct{ previous, requested, want int }{{0, 0, 300}, {180, 0, 180}, {600, 0, 600}, {180, 300, 300}} {
		path := filepath.Join(t.TempDir(), "config.json")
		body, _ := json.Marshal(map[string]any{"enterprise_id": "0123456789ABCDEF", "license": map[string]any{"heartbeat_interval_seconds": tc.previous}, "modules": map[string]any{"syslog-risk-json": map[string]any{"enabled": true}}})
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		if err := setLicenseInConfig(path, agentlicense.Config{HeartbeatSeconds: tc.requested}); err != nil {
			t.Fatal(err)
		}
		cfg, err := loadConfig(path)
		if err != nil || cfg.License.HeartbeatSeconds != tc.want {
			t.Fatal(tc, cfg.License, err)
		}
	}
}
