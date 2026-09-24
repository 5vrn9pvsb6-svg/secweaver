package behaviorlearning

import (
	"errors"
	"strings"
	"testing"
)

func windowsObservation(n int) Observation {
	o := observation(n)
	o.Context = Context{Service: "service-command", Parent: "parent-command", Executable: `C:\Program Files\Example\worker.exe`, Digest: strings.Repeat("a", 64), Args: []string{`worker.exe --check`}, CWD: `C:\Program Files\Example`, Session: "service_noninteractive", Capability: "windows-sysmon-sha256-v1", Windows: &WindowsContext{User: `nt authority\system`, ParentUser: `nt authority\system`, Integrity: "System", LogonID: "0x3e7", SessionID: "0"}}
	return o
}

func TestShutdownCheckpointFailurePersistsDegradedState(t *testing.T) {
	f := newFixture(t)
	if err := f.e.CloseWithCheckpoint(func() error { return errors.New("disk sync failed") }); err == nil {
		t.Fatal("shutdown swallowed checkpoint failure")
	}
	s, err := OpenStore(f.e.cfg.StateDir, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	state, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != "degraded" || state.Reason != "shutdown_output_checkpoint_failed" {
		t.Fatalf("unsafe restart state: %+v", state)
	}
}

func TestWindowsBaselinePromotionMatchAndChanges(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 8; i++ {
		f.e.state.HealthySeconds = float64(i * 3600)
		if err := f.e.Process(windowsObservation(i)); err != nil {
			t.Fatal(err)
		}
	}
	f.e.state.HealthySeconds = 86400
	f.e.freeze(f.now)
	if f.e.state.Mode != "enforcing" {
		t.Fatalf("baseline failed: %+v", f.e.state)
	}
	f.raw = nil
	if err := f.e.Process(windowsObservation(100)); err != nil {
		t.Fatal(err)
	}
	if len(f.raw) != 0 {
		t.Fatal("eligible known Windows exec not suppressed")
	}
	for i, mutate := range []func(*Context){
		func(c *Context) { c.Args[0] += " --unexpected" },
		func(c *Context) { c.Digest = strings.Repeat("b", 64) },
		func(c *Context) { c.Windows.SessionID = "1" },
		func(c *Context) { c.Windows.User = "alice" },
		func(c *Context) { c.Parent = "different-parent" },
	} {
		o := windowsObservation(101 + i)
		mutate(&o.Context)
		if err := f.e.Process(o); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.raw) != 5 {
		t.Fatalf("changed context lost: %d", len(f.raw))
	}
	if err := f.e.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if f.summaries[0].Suppressed != 1 {
		t.Fatal("suppression not accounted before cursor checkpoint")
	}
}
