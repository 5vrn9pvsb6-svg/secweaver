package behaviorlearning

import "testing"

// Repeated status snapshots must not turn post-admission counters into a
// whole-input denominator. Exercise misses, replays and failed sink writes.
func TestEngineCoverageCountsBeforeAdmissionAndFailures(t *testing.T) {
	f := simpleFixture(t)
	feedSimple(t, f, 0, 5)
	feedSimple(t, f, 4, 1) // replay of the fifth source event
	f.e.freeze(f.now)
	miss := simpleObservation(6)
	miss.Context.Exec.CommandLine = "new command"
	if err := f.e.Process(miss); err != nil {
		t.Fatal(err)
	}
	invalid := simpleObservation(7)
	invalid.Context.Exec.Exe = ""
	if err := f.e.Process(invalid); err != nil {
		t.Fatal(err)
	}
	f.failRaw = true
	invalid.EventID = "event:8"
	if err := f.e.Process(invalid); err == nil {
		t.Fatal("sink failure missing")
	}
	c := f.e.coverageSnapshot()
	if c.Inputs != 9 || c.Duplicates != 1 || c.Qualified != 6 || c.Rejected != 2 || c.BaselineMisses != 1 || c.Suppressed != 1 || c.Emitted != 6 || c.OutputErrors != 1 {
		t.Fatalf("coverage: %+v", c)
	}
	if c.Inputs != c.Duplicates+c.Suppressed+c.Emitted+c.OutputErrors {
		t.Fatal("lost input accounting")
	}
	if err := f.e.flush(f.now); err != nil {
		t.Fatal(err)
	}
	status := f.summaries[len(f.summaries)-1]
	if status.EngineCoverage == nil || status.EngineCoverage.RunID == "" {
		t.Fatal("missing status coverage")
	}
	f.e.coverage.Inputs++
	if status.EngineCoverage.Inputs != 9 {
		t.Fatal("published counters mutated")
	}
	for _, s := range f.summaries[:len(f.summaries)-1] {
		if s.EngineCoverage != nil {
			t.Fatal("coverage duplicated into per-behavior aggregate")
		}
	}
}
