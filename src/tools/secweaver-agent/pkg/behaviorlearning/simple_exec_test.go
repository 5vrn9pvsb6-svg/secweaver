package behaviorlearning

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func simpleFixture(t *testing.T) *fixture {
	t.Helper()
	return fixtureWithConfig(t, Config{Enabled: true, simpleExec: true, StateDir: t.TempDir()})
}

// Native IDs identify distinct executions; process identity is deliberately
// irrelevant to this fixture's exact normalized field strings.
func simpleObservation(n int) Observation {
	o := observation(n)
	o.Context = Context{Exec: &ExecFields{ListenerProcess: "java", PIDName: "bash", Exe: "/bin/bash", CommandLine: "bash -c check"}}
	o.Instance, o.ParentInstance = "", ""
	return o
}

func feedSimple(t *testing.T, f *fixture, first, count int) {
	t.Helper()
	for i := first; i < first+count; i++ {
		if err := f.e.Process(simpleObservation(i)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSimpleExecFiltersFifthWhileLearningAndFreezesOnlyAdmissions(t *testing.T) {
	f := simpleFixture(t)
	feedSimple(t, f, 0, 4)
	if len(f.raw) != 4 || len(f.e.state.Entries) != 0 {
		t.Fatal("first four events must remain original")
	}
	feedSimple(t, f, 4, 1)
	if len(f.raw) != 4 || len(f.e.state.Entries) != 1 || f.e.state.Mode != "learning" {
		t.Fatal("fifth did not filter during learning")
	}
	status := f.e.summaryBase(f.now)
	if !status.FilteringActive || !Snapshot(f.e.cfg, &f.e.state, &status, f.now).FilteringActive {
		t.Fatal("learning with an active baseline was reported as inactive")
	}
	// A burst must not reactivate the old P95 rule, and a later isolated hit
	// must not require another five executions in its hour.
	feedSimple(t, f, 5, 100)
	f.now = f.now.Add(2 * time.Hour)
	f.e.Health(true, false)
	feedSimple(t, f, 105, 1)
	if len(f.raw) != 4 {
		t.Fatal("legacy rate/expiry/health warmup gate was applied")
	}
	for i := 0; i < 5; i++ {
		o := simpleObservation(200 + i)
		o.Context.Exec.CommandLine = "second command"
		if err := f.e.Process(o); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.e.state.Entries) != 2 || len(f.raw) != 8 {
		t.Fatal("learning stopped after first admission")
	}
	f.e.freeze(f.now)
	for i := 0; i < 6; i++ {
		o := simpleObservation(300 + i)
		o.Context.Exec.CommandLine = "unknown after freeze"
		if err := f.e.Process(o); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.e.state.Entries) != 2 || len(f.e.state.Candidates) != 0 || len(f.raw) != 14 {
		t.Fatal("post-learning misses were learned or suppressed")
	}
	if err := f.e.flush(f.now); err != nil {
		t.Fatal(err)
	}
	var suppressed, emitted uint64
	for _, s := range f.summaries {
		suppressed += s.Suppressed
		emitted += s.Emitted
	}
	if suppressed != 103 || emitted != 0 {
		t.Fatalf("pre-admission originals were recounted: suppressed=%d emitted=%d", suppressed, emitted)
	}
}

func TestSimpleExecRollingWindowAndSourceDedup(t *testing.T) {
	for _, elapsed := range []time.Duration{time.Hour, time.Hour + time.Nanosecond} {
		t.Run(elapsed.String(), func(t *testing.T) {
			f := simpleFixture(t)
			start := f.now
			for i := 0; i < 4; i++ {
				f.now = start.Add(time.Duration(i) * 10 * time.Minute)
				f.e.Health(true, false)
				feedSimple(t, f, i, 1)
				feedSimple(t, f, i, 1)
			}
			f.now = start.Add(elapsed)
			f.e.Health(true, false)
			feedSimple(t, f, 4, 1)
			want := 1
			if elapsed > time.Hour {
				want = 0
			}
			if len(f.e.state.Entries) != want || len(f.raw) != 5-want {
				t.Fatalf("entries=%d originals=%d", len(f.e.state.Entries), len(f.raw))
			}
		})
	}
}

func TestSimpleExecExactlyFourFields(t *testing.T) {
	f := simpleFixture(t)
	feedSimple(t, f, 0, 5)
	changes := []func(*Observation){
		func(o *Observation) { o.Context.Exec.ListenerProcess += " " },
		func(o *Observation) { o.Context.Exec.PIDName = "BASH" },
		func(o *Observation) { o.Context.Exec.Exe = "/usr/bin/bash" },
		func(o *Observation) { o.Context.Exec.CommandLine += " " },
		func(o *Observation) { o.Context.Exec.CommandLine = "" },
		func(o *Observation) { o.EventID = "" },
	}
	for i, change := range changes {
		o := simpleObservation(100 + i)
		change(&o)
		if err := f.e.Process(o); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.raw) != 4+len(changes) {
		t.Fatal("changed or incomplete fields suppressed")
	}
	o := simpleObservation(200)
	o.Context.UID, o.Context.EUID, o.Context.Capability, o.Context.Parent = "0", "999", "different-backend", "other-parent"
	if err := f.e.Process(o); err != nil || len(f.raw) != 4+len(changes) {
		t.Fatalf("extra fields changed match: %v", err)
	}
	// Redacting both commands to the same display token must not merge their
	// pre-redaction identities or persist either secret in state/journal.
	for i := 0; i < 5; i++ {
		o := simpleObservation(300 + i)
		o.Context.Exec.CommandLine = "tool --token=synthetic-secret-one"
		if err := f.e.Process(o); err != nil {
			t.Fatal(err)
		}
	}
	o = simpleObservation(400)
	o.Context.Exec.CommandLine = "tool --token=synthetic-secret-two"
	before := len(f.raw)
	if err := f.e.Process(o); err != nil || len(f.raw) != before+1 {
		t.Fatal("distinct command secrets merged")
	}
	if err := f.e.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"state.json", "admissions.jsonl"} {
		body, err := os.ReadFile(filepath.Join(f.e.cfg.StateDir, name))
		if err != nil || strings.Contains(string(body), "synthetic-secret") {
			t.Fatalf("persisted command content in %s: %v", name, err)
		}
	}
}

// Linux matches the collected strings even when the adapter cannot prove full
// argv. Evidence quality neither partitions the tuple nor bypasses source dedup.
func TestSimpleExecLearnsDespiteCommandEvidenceDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		complete     bool
	}{
		{"missing EXECVE", "incomplete_or_truncated_command", false},
		{"truncated without reason", "", false},
		{"diagnostic with complete argv", "adapter_diagnostic", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := simpleFixture(t)
			for i := 0; i < 6; i++ {
				o := simpleObservation(i)
				o.Complete, o.Reason = tc.complete, tc.reason
				// Alternate quality for the same tuple, including the fifth hit.
				if i == 2 || i == 4 {
					o.Complete, o.Reason = true, ""
				}
				for replay := 0; replay < 2; replay++ {
					if err := f.e.Process(o); err != nil {
						t.Fatal(err)
					}
				}
				if i < 4 && (len(f.raw) != i+1 || len(f.e.state.Entries) != 0) {
					t.Fatal("diagnostic skipped a candidate or replay promoted it early")
				}
			}
			if len(f.raw) != 4 || len(f.e.state.Entries) != 1 || len(f.e.state.Candidates) != 0 {
				t.Fatal("diagnostics prevented five-hit admission or subsequent filtering")
			}
			var first map[string]any
			if err := json.Unmarshal(f.raw[0], &first); err != nil {
				t.Fatal(err)
			}
			wantReason := tc.reason
			if wantReason == "" {
				wantReason = "incomplete_or_truncated_command"
			}
			if first["decision_reason"] != "learning" || first["command_evidence_reason"] != wantReason || first["behavior_fingerprint"] == "" {
				t.Fatalf("learning decision and evidence diagnostic not separated: %s", f.raw[0])
			}
			if err := f.e.flush(f.now); err != nil {
				t.Fatal(err)
			}
			var suppressed uint64
			for _, summary := range f.summaries {
				suppressed += summary.Suppressed
			}
			if suppressed != 2 {
				t.Fatalf("suppressed=%d; fifth and sixth distinct events should count", suppressed)
			}
		})
	}
}

// Other streams still require their native evidence; the Linux exec policy
// must not accidentally admit partial scripts or uncorrelated file/network data.
func TestSimpleExecDiagnosticChangePreservesOtherStreamGates(t *testing.T) {
	for _, kind := range []string{"exec", "active_connect", "powershell_script_block", "linux_file", "windows_file"} {
		t.Run(kind, func(t *testing.T) {
			cfg, ctx := simplePolicyCase(t, kind)
			if strings.HasSuffix(kind, "_file") {
				windows := kind == "windows_file"
				cfg = FilePolicy(Config{Enabled: true, StateDir: t.TempDir(), EventTypes: []string{"file_op"}}, windows)
				ctx = fileObservation(0, windows).Context
			}
			f := fixtureWithConfig(t, cfg)
			for i := 0; i < 6; i++ {
				o := Observation{Context: ctx, Complete: false, Reason: "incomplete_evidence", EventID: fmt.Sprint(i), Raw: json.RawMessage(`{"event_type":"test"}`)}
				if err := f.e.Process(o); err != nil {
					t.Fatal(err)
				}
			}
			if len(f.raw) != 6 || len(f.e.state.Candidates) != 0 || len(f.e.state.Entries) != 0 {
				t.Fatal("another stream inherited Linux exec's diagnostic-only completeness")
			}
		})
	}
}

// Relaxing command evidence is not permission to ignore missing match fields,
// disabled streams, shadow, health/fault state or durable-admission failures.
func TestSimpleExecIncompleteEvidenceRetainsOperationalGuards(t *testing.T) {
	for _, reason := range []string{"invalid_fields", "missing_source", "scope", "shadow", "source_unhealthy", "degraded", "journal", "frozen"} {
		t.Run(reason, func(t *testing.T) {
			f := simpleFixture(t)
			switch reason {
			case "scope":
				f.e.cfg.EventTypes = []string{"file_op"}
			case "shadow":
				f.e.cfg.Shadow = true
			case "source_unhealthy":
				f.e.Health(false, false)
			case "degraded":
				f.e.Fault("audit_lost")
			case "journal":
				f.e.store.limit = 3
			case "frozen":
				f.e.freeze(f.now)
			}
			for i := 0; i < 6; i++ {
				o := simpleObservation(i)
				o.Complete, o.Reason = false, "incomplete_or_truncated_command"
				if reason == "invalid_fields" {
					o.Context.Exec.CommandLine = ""
				}
				if reason == "missing_source" {
					o.EventID = ""
				}
				if err := f.e.Process(o); err != nil {
					t.Fatal(err)
				}
			}
			wantEntries := 0
			if reason == "shadow" {
				wantEntries = 1
			}
			if len(f.raw) != 6 || len(f.e.state.Entries) != wantEntries {
				t.Fatalf("guard %s: originals=%d entries=%d", reason, len(f.raw), len(f.e.state.Entries))
			}
			var last map[string]any
			if err := json.Unmarshal(f.raw[5], &last); err != nil {
				t.Fatal(err)
			}
			if last["decision_reason"] == "incomplete_or_truncated_command" || last["command_evidence_reason"] != "incomplete_or_truncated_command" {
				t.Fatalf("command diagnostic hid operational reason: %s", f.raw[5])
			}
		})
	}
}

func TestSimpleExecShadowEmptyAndFailureFallbacks(t *testing.T) {
	t.Run("clock regression", func(t *testing.T) {
		f := simpleFixture(t)
		feedSimple(t, f, 0, 5)
		f.now = f.e.lastTick.Add(-time.Second)
		if err := f.e.Tick(); err != nil {
			t.Fatal(err)
		}
		feedSimple(t, f, 5, 1)
		if len(f.raw) != 5 || f.e.state.Reason != "clock_regression" {
			t.Fatal("clock regression kept filtering")
		}
	})
	t.Run("shadow", func(t *testing.T) {
		f := simpleFixture(t)
		f.e.cfg.Shadow = true
		feedSimple(t, f, 0, 10)
		if len(f.raw) != 10 || len(f.e.state.Entries) != 1 || f.e.summaryBase(f.now).FilteringActive {
			t.Fatal("shadow suppressed or stopped learning")
		}
	})
	t.Run("empty", func(t *testing.T) {
		f := simpleFixture(t)
		f.e.freeze(f.now)
		if f.e.state.Mode != "enforcing" || f.e.state.Reason != "baseline_empty" || f.e.summaryBase(f.now).FilteringActive {
			t.Fatal("empty baseline degraded or claimed filtering")
		}
	})
	t.Run("admission failure", func(t *testing.T) {
		f := simpleFixture(t)
		feedSimple(t, f, 0, 4)
		f.e.store.limit = 3
		feedSimple(t, f, 4, 1)
		if len(f.raw) != 5 || len(f.e.state.Entries) != 0 || f.e.state.Mode != "degraded" {
			t.Fatal("failed journal write lost fifth original")
		}
	})
	t.Run("summary failure", func(t *testing.T) {
		f := simpleFixture(t)
		feedSimple(t, f, 0, 5)
		f.failSummary = true
		if err := f.e.Checkpoint(); err == nil {
			t.Fatal("summary failure hidden")
		}
		feedSimple(t, f, 5, 1)
		if len(f.raw) != 5 || f.e.summaryBase(f.now).FilteringActive {
			t.Fatal("summary failure kept filtering")
		}
	})
	t.Run("unhealthy", func(t *testing.T) {
		f := simpleFixture(t)
		feedSimple(t, f, 0, 5)
		f.e.Health(false, false)
		feedSimple(t, f, 5, 1)
		if len(f.raw) != 5 {
			t.Fatal("expired health still filtered")
		}
	})
	t.Run("capacity", func(t *testing.T) {
		f := simpleFixture(t)
		f.e.cfg.MaxEntries, f.e.cfg.MaxCandidates = 1, 1
		feedSimple(t, f, 0, 5)
		for i := 0; i < 10; i++ {
			o := simpleObservation(100 + i)
			o.Context.Exec.CommandLine = "other"
			if err := f.e.Process(o); err != nil {
				t.Fatal(err)
			}
		}
		if len(f.raw) != 14 || len(f.e.state.Entries) != 1 || f.e.state.Reason != "baseline_capacity" {
			t.Fatal("capacity failure lost unknown originals")
		}
	})
}

func TestSimpleExecCleanRestartPreservesCandidatesAndDedup(t *testing.T) {
	f := simpleFixture(t)
	f.now = time.Now().Add(-time.Minute)
	feedSimple(t, f, 0, 4)
	if err := f.e.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := New(f.e.cfg, "device-test", f.e.original, f.e.summary)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	restored.Health(true, false)
	if err := restored.Process(simpleObservation(3)); err != nil || len(f.raw) != 4 {
		t.Fatal("restart counted a reread")
	}
	// Previously complete candidates and new incomplete observations share the
	// existing tuple/hash across restart; no generation reset is required.
	o := simpleObservation(4)
	o.Complete, o.Reason = false, "incomplete_or_truncated_command"
	if err := restored.Process(o); err != nil || len(f.raw) != 4 || len(restored.state.Entries) != 1 {
		t.Fatalf("restart lost candidate progress: %v", err)
	}
}

func TestSimpleExecMigratesOnlyCompatibleLegacyState(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprint(mismatch), func(t *testing.T) {
			f := newFixture(t)
			promote(t, f)
			oldID := f.e.state.BaselineID
			if err := f.e.Close(); err != nil {
				t.Fatal(err)
			}
			cfg := f.e.cfg
			cfg.simpleExec = true
			if mismatch {
				cfg.LearningSeconds++
			}
			e, err := New(cfg, "device-test", f.e.original, f.e.summary)
			if mismatch {
				if err == nil {
					e.Close()
					t.Fatal("unrelated policy change was silently migrated")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if e.state.Mode != "learning" || e.state.BaselineID == oldID || len(e.state.Entries) != 0 || e.state.Reason != "simple_exec_policy_migrated" {
				t.Fatal("old entries reused or migration not visible")
			}
			if _, err := os.Stat(filepath.Join(cfg.StateDir, "legacy-state.json")); err != nil {
				t.Fatal("legacy state was not archived")
			}
		})
	}
}

// The benchmark measures known-event matching, with a new source ID per input.
// Dedup housekeeping is kept bounded without hitting the deliberate capacity
// fallback, so this measures real suppression rather than repeated-ID rejection.
func BenchmarkSimpleExecKnown(b *testing.B) {
	cfg := Config{Enabled: true, simpleExec: true, StateDir: b.TempDir()}
	e, err := New(cfg, "bench", func(json.RawMessage) error { return nil }, func(Summary) error { return nil })
	if err != nil {
		b.Fatal(err)
	}
	defer e.Close()
	e.Health(true, false)
	for i := 0; i < 5; i++ {
		if err := e.Process(simpleObservation(i)); err != nil {
			b.Fatal(err)
		}
	}
	e.healthUntil = time.Now().Add(24 * time.Hour)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%1024 == 0 {
			clear(e.seen)
		}
		if err := e.Process(simpleObservation(i + 5)); err != nil {
			b.Fatal(err)
		}
	}
}
