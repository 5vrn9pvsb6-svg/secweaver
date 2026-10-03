package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Doctor must distinguish absent legacy policy from enabled but unreadable
// state, without initializing a baseline merely to answer a diagnostic query.
func TestDoctorLinuxLearningReportsDisabledAndUnavailable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.json")
	module := runtimeModule{Spec: moduleDescriptor{Name: "audit-port-execmon"}, Config: moduleConfig{Args: []string{"-config", path, "-output-log", filepath.Join(dir, "logs", "exec.log")}}}
	for _, tc := range []struct{ body, key, detail string }{
		{`{}`, "learning/config", "--learning-mode enable or shadow"},
		{`{"behavior_learning":{"enabled":true}}`, "learning/status", "mode=unknown"},
		{`{"behavior_learning":{"invalid":true}}`, "learning/status", "unavailable"},
	} {
		t.Run(tc.body, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			var found bool
			doctorCheckLinuxLearning([]runtimeModule{module}, func(level doctorLevel, key, message, detail string) {
				if key == tc.key && level == doctorWarn && strings.Contains(message+detail, tc.detail) {
					found = true
				}
			})
			if !found {
				t.Fatal("missing actionable warning")
			}
		})
	}
	status := behaviorLearningStatus([]runtimeModule{module}, nil)
	if status.FilteringActive || status.Mode != "unknown" {
		t.Fatalf("invalid policy status: %+v", status)
	}
	if status := behaviorLearningStatus(nil, nil); status.Mode != "disabled" || status.Reason != "collector_disabled" {
		t.Fatalf("disabled collector: %+v", status)
	}
}
