package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Preserve must be byte-for-byte inert for legacy installations. Opt-in only
// changes activation switches; scope and baseline generation are user-owned.
func TestSetLearningModePreservesExistingPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	legacy := []byte("{\"output_log\":\"/tmp/test.log\",\"custom\":42}\n")
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	status, err := setLearningModeInConfig(path, "preserve")
	if err != nil || status != "disabled; reason=existing-config-preserved" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(legacy) {
		t.Fatal("preserve rewrote config")
	}
	body := []byte(`{"custom":42,"behavior_learning":{"enabled":false,"generation":7,"event_types":["exec"]}}`)
	for _, mode := range []string{"enable", "shadow", "disable"} {
		t.Run(mode, func(t *testing.T) {
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := setLearningModeInConfig(path, mode); err != nil {
				t.Fatal(err)
			}
			var cfg struct {
				Custom   int `json:"custom"`
				Learning struct {
					Enabled    bool     `json:"enabled"`
					Shadow     bool     `json:"shadow"`
					Generation int      `json:"generation"`
					Types      []string `json:"event_types"`
				} `json:"behavior_learning"`
			}
			got, _ := os.ReadFile(path)
			if err := json.Unmarshal(got, &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.Custom != 42 || cfg.Learning.Generation != 7 || len(cfg.Learning.Types) != 1 || cfg.Learning.Enabled != (mode != "disable") || cfg.Learning.Shadow != (mode == "shadow") {
				t.Fatalf("modified unrelated policy: %+v", cfg)
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0600 {
				t.Fatalf("permissions: %v", info.Mode())
			}
		})
	}
	if _, err := setLearningModeInConfig(path, "enable; touch /tmp/invalid"); err == nil {
		t.Fatal("accepted invalid mode")
	}
}

func TestSetLearningModeReportsInvalidPreservedPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	body := []byte(`{"behavior_learning":{"enabled":true,"unexpected":1}}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	status, err := setLearningModeInConfig(path, "preserve")
	if err != nil || !strings.Contains(status, "existing-config-invalid") {
		t.Fatalf("status=%q err=%v", status, err)
	}
	if _, err := setLearningModeInConfig(path, "enable"); err == nil {
		t.Fatal("explicit mode ignored invalid policy")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(body) {
		t.Fatal("invalid config changed")
	}
}
