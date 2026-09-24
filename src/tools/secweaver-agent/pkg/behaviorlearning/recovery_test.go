package behaviorlearning

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInspectDoesNotCompeteWithLiveWriter(t *testing.T) {
	f := newFixture(t)
	state, err := Inspect(f.e.cfg.StateDir, f.e.cfg.StateMB)
	if err != nil || state == nil || state.Mode != "learning" {
		t.Fatalf("inspect: %+v %v", state, err)
	}
	if state.CleanShutdown {
		t.Fatal("live writer marked clean")
	}
}

// An unclean restart can hide source loss after the last checkpoint; it must
// not silently restore an enforceable baseline even if the file is authentic.
func TestUncleanRestartRequiresExplicitRelearn(t *testing.T) {
	f := newFixture(t)
	promote(t, f)
	cfg := f.e.cfg
	f.e.store.Close()
	f.e.closed = true
	restored, err := New(cfg, "device-test", f.e.original, f.e.summary)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if restored.state.Mode != "degraded" || restored.state.Reason != "unclean_restart_requires_relearn" {
		t.Fatalf("restart state: %+v", restored.state)
	}
}

func TestAuthenticatedStateRejectsModifiedBaseline(t *testing.T) {
	f := newFixture(t)
	promote(t, f)
	if err := f.e.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.e.cfg.StateDir, "state.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err = json.Unmarshal(b, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["hmac_sha256"] = json.RawMessage(`"0000000000000000000000000000000000000000000000000000000000000000"`)
	b, _ = json.Marshal(envelope)
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Inspect(f.e.cfg.StateDir, f.e.cfg.StateMB); err == nil {
		t.Fatal("tampered checkpoint accepted")
	}
}

func TestFaultDoesNotWaitForOutputLock(t *testing.T) {
	f := newFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	f.e.original = func(json.RawMessage) error { close(entered); <-release; return nil }
	go func() { defer close(done); _ = f.e.Process(observation(1)) }()
	<-entered
	faultDone := make(chan struct{})
	go func() { f.e.Fault("overflow"); close(faultDone) }()
	select {
	case <-faultDone:
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("reader fault waited on writer")
	}
	close(release)
	<-done
	if err := f.e.Tick(); err != nil {
		t.Fatal(err)
	}
	if f.e.state.Mode != "degraded" {
		t.Fatal("pending fault ignored")
	}
}

func TestExpiredHealthLeaseRestartsCooldown(t *testing.T) {
	f := newFixture(t)
	f.e.healthUntil = f.now.Add(-time.Second)
	f.e.Health(true, false)
	if !f.e.healthySince.Equal(f.now) {
		t.Fatal("lease gap skipped cooldown")
	}
}

func TestFailedBaselineCommitNeverEnforces(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 8; i++ {
		f.e.state.HealthySeconds = float64(i * 3600)
		f.e.Process(observation(i))
	}
	f.e.store.limit = 3
	f.e.freeze(f.now)
	if f.e.state.Mode != "degraded" {
		t.Fatal("memory-only baseline became active")
	}
	f.raw = nil
	f.e.Process(observation(100))
	if len(f.raw) != 1 {
		t.Fatal("failed commit suppressed evidence")
	}
}
