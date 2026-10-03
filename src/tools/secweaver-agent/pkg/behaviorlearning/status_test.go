package behaviorlearning

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Status probes must not upgrade a baseline observation into proof of active
// filtering after restart, policy change, or degraded input.
func TestSnapshotFilteringRequiresCurrentHealthyRuntime(t *testing.T) {
	cfg, err := (Config{Enabled: true}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	state := State{Device: "device", BaselineID: "baseline", Mode: "enforcing", Generation: cfg.Generation, Policy: policyHash(cfg), Started: now.Add(-25 * time.Hour)}
	summary := Summary{DeviceID: state.Device, BaselineID: state.BaselineID, Mode: "enforcing", Time: now.Add(-time.Minute), SourceHealthy: true, FilteringActive: true}
	if !Snapshot(cfg, &state, &summary, now).FilteringActive {
		t.Fatal("healthy runtime was not active")
	}
	cases := []struct {
		name   string
		change func(*Config, *State, *Summary)
	}{
		{"shadow config", func(c *Config, _ *State, _ *Summary) { c.Shadow = true }},
		{"shadow runtime", func(_ *Config, _ *State, s *Summary) { s.Shadow = true }},
		{"stopped", func(_ *Config, s *State, _ *Summary) { s.CleanShutdown = true }},
		{"stale", func(_ *Config, _ *State, s *Summary) { s.Time = now.Add(-11 * time.Minute) }},
		{"future", func(_ *Config, _ *State, s *Summary) { s.Time = now.Add(time.Second) }},
		{"different baseline", func(_ *Config, _ *State, s *Summary) { s.BaselineID = "old" }},
		{"different device", func(_ *Config, _ *State, s *Summary) { s.DeviceID = "old" }},
		{"degraded", func(_ *Config, s *State, _ *Summary) { s.Mode = "degraded" }},
		{"unhealthy", func(_ *Config, _ *State, s *Summary) { s.SourceHealthy = false }},
		{"new generation", func(c *Config, _ *State, _ *Summary) { c.Generation++ }},
		{"new matching policy", func(c *Config, _ *State, _ *Summary) { c.MinOccurrences++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, s, r := cfg, state, summary
			tc.change(&c, &s, &r)
			if Snapshot(c, &s, &r, now).FilteringActive {
				t.Fatal("unsafe active status")
			}
		})
	}
	if got := Snapshot(Config{}, nil, nil, now); got.Enabled || got.Mode != "disabled" {
		t.Fatalf("disabled: %+v", got)
	}
	if got := Snapshot(cfg, nil, nil, now); got.Mode != "unknown" || got.FilteringActive {
		t.Fatalf("missing state: %+v", got)
	}
	state.Mode, state.HealthySeconds = "learning", 3600.2
	if got := Snapshot(cfg, &state, nil, now); got.RemainingSeconds != 82800 || got.StartedAt == "" {
		t.Fatalf("progress: %+v", got)
	}
}

// A busy rotating log must remain a bounded read, ignoring partial and unrelated
// records while retaining the most recent valid observation in the tail.
func TestReadLatestSummaryBoundedTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "behavior-learning.log")
	now := time.Now().UTC()
	old, _ := json.Marshal(Summary{Time: now.Add(-time.Minute), EventType: "behavior_summary"})
	latest, _ := json.Marshal(Summary{Time: now, EventType: "behavior_learning_status", Mode: "learning"})
	body := strings.Repeat("x", 140<<10) + "\n" + string(latest) + "\n" + string(old) + "\n{malformed\n{\"event_type\":\"exec\"}\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadLatestSummary(path)
	if err != nil || !got.Time.Equal(now) {
		t.Fatalf("latest=%+v error=%v", got, err)
	}
	if _, err := ReadLatestSummary(filepath.Dir(path)); err == nil {
		t.Fatal("accepted directory")
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLatestSummary(path); err == nil {
		t.Fatal("accepted missing status")
	}
}
