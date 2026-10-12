package main

import (
	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/behaviorlearning"
	"testing"
)

func TestLearningRuntimeReasons(t *testing.T) {
	s := behaviorlearning.StatusSnapshot{Enabled: true, Mode: "enforcing", FilteringActive: true, UpdatedAt: "2026-10-12T00:01:00Z", Reason: "baseline_note"}
	for _, tc := range []struct {
		health agentlicense.ModuleHealth
		reason string
	}{
		{agentlicense.ModuleHealth{Status: "stopped"}, "collector_not_running"},
		{agentlicense.ModuleHealth{Status: "running", LastStartAt: "2026-10-12T00:02:00Z"}, "awaiting_current_runtime"},
	} {
		got := qualifyLearningRuntime(s, nil, tc.health)
		if got.FilteringActive || got.FilteringReason != tc.reason || got.Reason != s.Reason {
			t.Fatalf("runtime reason: %+v", got)
		}
	}
}

// A unified Windows risk owner with no evidence output must not mask the
// standalone evidence collector or read another stream as if it were risk.
func TestHeartbeatLearningStreamOwnershipAndLegacyDefaults(t *testing.T) {
	modules := []runtimeModule{
		{Spec: moduleDescriptor{Name: "windows-eventlog-risk-json"}, Config: moduleConfig{Args: []string{"-evidence-output", "", "-risk-behavior-learning=false"}}},
		{Spec: moduleDescriptor{Name: "windows-process-execmon"}, Config: moduleConfig{Args: []string{"-behavior-learning=false"}}},
	}
	got := behaviorLearningStatus(modules, nil, agentlicense.Config{}, "")
	if len(got.Streams) != 4 || got.Mode != "disabled" {
		t.Fatalf("missing bounded streams: %+v", got)
	}
	for kind, s := range got.Streams {
		if s.Mode != "disabled" || len(s.Streams) != 0 {
			t.Fatalf("invalid %s stream: %+v", kind, s)
		}
	}
	if got.Streams["exec"].Reason != "disabled" || got.Streams["risk"].Reason != "disabled" {
		t.Fatal("ownership transfer ignored")
	}
	// Disabled risk does not require a registered identity or native Event Log.
	if got, err := readHeartbeatRiskLearning([]string{"-risk-behavior-learning=false"}, agentlicense.Config{}, ""); err != nil || got.FilteringActive || got.Mode != "disabled" {
		t.Fatalf("disabled risk: %+v %v", got, err)
	}
}
