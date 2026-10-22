package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// An unreadable module policy must be visible without starting a collector or
// attempting to fix/rewrite the operator's file during a diagnostic command.
func TestDoctorLinuxBackendsReportsUnreadableConfig(t *testing.T) {
	module := runtimeModule{Spec: moduleDescriptor{Name: "audit-port-execmon"}, Config: moduleConfig{
		Args: []string{"-config", filepath.Join(t.TempDir(), "missing.json")},
	}}
	found := false
	doctorCheckLinuxBackends([]runtimeModule{module}, func(level doctorLevel, key, message, detail string) {
		if level == doctorWarn && key == "exec/local-backends" && strings.Contains(message, "unavailable") && detail != "" {
			found = true
		}
	})
	if !found {
		t.Fatal("unreadable backend policy was not diagnosed")
	}
}
