package behaviorlearning

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	e                    *Engine
	now                  time.Time
	raw                  []json.RawMessage
	summaries            []Summary
	failRaw, failSummary bool
}

// newFixture uses a controlled clock; no test waits a day or depends on a
// particular host's audit setup. Sink failures exercise the real state machine.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: time.Now()}
	cfg, _ := (Config{Enabled: true, StateDir: t.TempDir()}).Normalize()
	e, err := New(cfg, "device-test", func(raw json.RawMessage) error {
		if f.failRaw {
			return errors.New("disk full")
		}
		f.raw = append(f.raw, append(json.RawMessage(nil), raw...))
		return nil
	}, func(s Summary) error {
		if f.failSummary {
			return errors.New("summary disk full")
		}
		f.summaries = append(f.summaries, s)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	f.e = e
	e.now = func() time.Time { return f.now }
	e.lastTick = f.now
	e.rateOrigin = f.now
	e.lastSave = f.now
	e.lastFlush = f.now
	e.healthySince = f.now.Add(-10 * time.Minute)
	e.healthUntil = f.now.Add(time.Hour)
	t.Cleanup(func() { e.Close() })
	return f
}
func observation(n int) Observation {
	return Observation{Context: Context{Service: "app.service:8080", Parent: "verified-java", Executable: "/usr/bin/stat", Digest: "verified-digest", Args: []string{"stat", "--", "/var/lib/app/ready"}, CWD: "/var/lib/app", UID: "1001", EUID: "1001", GID: "1001", EGID: "1001", AUID: "4294967295", Session: "service_noninteractive", Capability: "audit-v1"}, Complete: true, EventID: fmt.Sprintf("boot:event:%d", n), Instance: fmt.Sprintf("boot:%d:1", n), ParentInstance: "root:1", Raw: json.RawMessage(fmt.Sprintf("{\"event_type\":\"exec\",\"pid\":%d}", n))}
}

// promote feeds actual observations at distinct healthy-hour positions; only
// the virtual clock/progress is accelerated, not the eligibility conditions.
func promote(t *testing.T, f *fixture) {
	t.Helper()
	for i := 0; i < 8; i++ {
		f.e.state.HealthySeconds = float64(i * 3600)
		if err := f.e.Process(observation(i)); err != nil {
			t.Fatal(err)
		}
	}
	f.e.state.HealthySeconds = 86400
	f.e.freeze(f.now)
	if f.e.state.Mode != "enforcing" {
		t.Fatalf("mode=%s reason=%s", f.e.state.Mode, f.e.state.Reason)
	}
	f.raw = nil
}

func TestLearnFreezeExactMatchAndUnknownNeverAbsorbed(t *testing.T) {
	f := newFixture(t)
	promote(t, f)
	if err := f.e.Process(observation(100)); err != nil {
		t.Fatal(err)
	}
	if len(f.raw) != 0 {
		t.Fatal("known behavior was emitted")
	}
	changed := observation(101)
	changed.Context.Args = []string{"stat", "--", "/other"}
	for i := 0; i < 6; i++ {
		changed.EventID = fmt.Sprint("unknown", i)
		if err := f.e.Process(changed); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.raw) != 6 || len(f.e.state.Entries) != 1 || len(f.e.state.Candidates) != 0 {
		t.Fatal("unknown activity was learned or suppressed")
	}
	if err := f.e.flush(f.now); err != nil {
		t.Fatal(err)
	}
	s := f.summaries[0]
	if s.Observed != 1 || s.Suppressed != 1 || s.Emitted != 0 {
		t.Fatalf("summary: %+v", s)
	}
}

func TestIncompleteSensitiveAndChangedIdentityAlwaysEmit(t *testing.T) {
	for _, change := range []func(*Observation){
		func(o *Observation) { o.Complete = false },
		func(o *Observation) { o.Reason = "always_emit_shell" },
		func(o *Observation) { o.Context.EUID = "0" },
		func(o *Observation) { o.Context.Digest = "changed" },
		func(o *Observation) { o.Context.Parent = "another-parent" },
		func(o *Observation) { o.Context.Capability = "ebpf-incomplete" },
	} {
		f := newFixture(t)
		promote(t, f)
		o := observation(100)
		change(&o)
		if err := f.e.Process(o); err != nil {
			t.Fatal(err)
		}
		if len(f.raw) != 1 {
			t.Fatal("changed or incomplete event suppressed")
		}
	}
}

func TestLearningClockDoesNotCountDowntimeOrUnhealthyTime(t *testing.T) {
	f := newFixture(t)
	f.now = f.now.Add(24 * time.Hour)
	if err := f.e.Tick(); err != nil {
		t.Fatal(err)
	}
	if f.e.state.HealthySeconds != 0 || f.e.state.Mode != "learning" {
		t.Fatal("clock jump completed learning")
	}
	f.e.Health(false, false)
	f.now = f.now.Add(time.Second)
	_ = f.e.Tick()
	if f.e.state.HealthySeconds != 0 {
		t.Fatal("unhealthy clock advanced")
	}
	f.e.Health(true, true)
	if f.e.state.Mode != "degraded" {
		t.Fatal("known loss did not invalidate generation")
	}
	f.e.Health(true, false)
	if f.e.state.Mode != "degraded" {
		t.Fatal("loss was silently forgiven")
	}
}

func TestRateLimitAcrossBucketBoundary(t *testing.T) {
	f := newFixture(t)
	promote(t, f)
	// The learned sparse behavior has a floor of ten per rolling five minutes.
	for i := 0; i < 10; i++ {
		if err := f.e.Process(observation(100 + i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.raw) != 0 {
		t.Fatal("premature rate trigger")
	}
	f.now = f.now.Add(5 * time.Second)
	_ = f.e.Process(observation(200))
	if len(f.raw) != 1 {
		t.Fatal("boundary reset rate budget")
	}
	f.now = f.now.Add(301 * time.Second)
	f.e.healthUntil = f.now.Add(time.Hour)
	_ = f.e.Process(observation(201))
	if len(f.raw) != 2 {
		t.Fatal("anomaly protection did not persist")
	}
}

func TestRestartLockCorruptionAndGeneration(t *testing.T) {
	f := newFixture(t)
	promote(t, f)
	cfg := f.e.cfg
	if _, err := New(cfg, "device-test", f.e.original, f.e.summary); err == nil {
		t.Fatal("second state writer acquired lock")
	}
	if err := f.e.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := New(cfg, "device-test", f.e.original, f.e.summary)
	if err != nil {
		t.Fatal(err)
	}
	if restored.state.Mode != "enforcing" || len(restored.state.Entries) != 1 {
		t.Fatal("baseline not restored")
	}
	if !restored.warmUntil.After(time.Now()) {
		t.Fatal("restart erased rate protection")
	}
	restored.Close()
	cfg.Generation++
	fresh, err := New(cfg, "device-test", f.e.original, f.e.summary)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.state.Mode != "learning" || len(fresh.state.Entries) != 0 {
		t.Fatal("explicit relearn failed")
	}
	fresh.Close()
	if err = os.WriteFile(filepath.Join(cfg.StateDir, "state.json"), []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = New(cfg, "device-test", f.e.original, f.e.summary); err == nil {
		t.Fatal("corrupt state accepted")
	}
	// Prevent test cleanup from overwriting the intentional corruption.
	f.e.store = nil
}

func TestSinkFailuresAndDedupRetry(t *testing.T) {
	f := newFixture(t)
	promote(t, f)
	f.e.Fault("test_full")
	f.failRaw = true
	o := observation(100)
	if f.e.Process(o) == nil {
		t.Fatal("write failure ignored")
	}
	f.failRaw = false
	if err := f.e.Process(o); err != nil {
		t.Fatal(err)
	}
	if len(f.raw) != 1 {
		t.Fatal("failed event was marked delivered")
	}
	f.e.Process(o)
	if len(f.raw) != 1 {
		t.Fatal("successful retry duplicated")
	}
}

func TestStateNeverStoresPlaintextArguments(t *testing.T) {
	f := newFixture(t)
	o := observation(1)
	o.Context.Args = []string{"stat", "secret-example-token"}
	f.e.Process(o)
	if err := f.e.store.Commit(f.e.state); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(f.e.cfg.StateDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret-example-token") {
		t.Fatal("plaintext command leaked to state")
	}
	for _, name := range []string{"key", "state.json", "initialized", "lock"} {
		st, err := os.Stat(filepath.Join(f.e.cfg.StateDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("%s permissions: %v", name, st.Mode())
		}
	}
}

func TestConfigRejectsUnknownAndConflictingFields(t *testing.T) {
	for _, raw := range []string{
		`{"enabled":true,"min_occurences":5}`,
		`{"enabled":true,"learning_duration_seconds":3600}`,
		`{"enabled":true,"on_error":"drop"}`,
		`{"enabled":true,"max_candidate_entries":9999999}`,
	} {
		if _, err := Decode(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	c, err := Decode(nil)
	if err != nil || c.Enabled {
		t.Fatal("upgrade omission enabled suppression")
	}
	c, err = Decode(json.RawMessage(`{"enabled":true}`))
	if err != nil || c.LearningSeconds != 86400 {
		t.Fatal("new install defaults")
	}
}

func TestEvidenceBudgetAndReplay(t *testing.T) {
	f := newFixture(t)
	promote(t, f)
	parent := observation(100)
	f.e.Process(parent)
	child := observation(101)
	child.Complete = false
	child.ParentInstance = parent.Instance
	f.e.Process(child)
	if len(f.raw) != 2 || !strings.Contains(string(f.raw[0]), "\"context_only\":true") {
		t.Fatal("missing real ancestor replay")
	}
	f.raw = nil
	f.e.evidenceBytes = (f.e.cfg.MemoryMB << 20) / 4
	f.e.Process(observation(102))
	if len(f.raw) != 1 {
		t.Fatal("evidence exhaustion suppressed event")
	}
}

func TestSummaryFailureInvalidatesFiltering(t *testing.T) {
	f := newFixture(t)
	promote(t, f)
	f.e.Process(observation(100))
	f.failSummary = true
	if err := f.e.flush(f.now); err == nil {
		t.Fatal("summary sink failure ignored")
	}
	// Tick is the lifecycle boundary that converts a flush failure into degradation.
	f.e.lastFlush = f.now.Add(-time.Hour)
	if err := f.e.Tick(); err == nil || f.e.state.Mode != "degraded" {
		t.Fatal("summary failure did not stop filtering")
	}
}

func BenchmarkKnownBehavior(b *testing.B) {
	cfg, _ := (Config{StateDir: b.TempDir()}).Normalize()
	e, err := New(cfg, "device", func(json.RawMessage) error { return nil }, func(Summary) error { return nil })
	if err != nil {
		b.Fatal(err)
	}
	defer e.Close()
	o := observation(100)
	o.Instance = "" // bounded-context fallback benchmark
	key := e.fingerprint(o.Context)
	e.state.Mode = "enforcing"
	e.state.Entries[key] = &Entry{Limit: ^uint64(0)}
	e.healthySince = time.Now().Add(-time.Hour)
	e.healthUntil = time.Now().Add(time.Hour)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.EventID = fmt.Sprint(i)
		_ = e.Process(o)
	}
}
