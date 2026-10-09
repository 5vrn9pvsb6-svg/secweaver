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

// All remaining adapters exercise the same real store/counter. Only the clock
// is controlled, so no native service or day-long wait can mask a rule mismatch.
func TestSimplePoliciesShareRollingFiveImmediateAndFrozenRules(t *testing.T) {
	for _, kind := range []string{"exec", "active_connect", "powershell_script_block"} {
		t.Run(kind, func(t *testing.T) {
			cfg, ctx := simplePolicyCase(t, kind)
			f := fixtureWithConfig(t, cfg)
			process := func(id int) {
				t.Helper()
				o := Observation{Context: ctx, Complete: true, EventID: fmt.Sprint(id), Raw: json.RawMessage(`{"event_type":"test"}`)}
				if err := f.e.Process(o); err != nil {
					t.Fatal(err)
				}
			}
			start := f.now
			for i := 0; i < 4; i++ {
				process(i)
				process(i) // Reader retry is not another occurrence.
			}
			f.now = start.Add(time.Hour + time.Nanosecond)
			f.e.Health(true, false)
			process(4)
			if len(f.e.state.Entries) != 0 || len(f.raw) != 5 {
				t.Fatal("expired/replayed observations trained a baseline")
			}
			for i := 5; i < 9; i++ {
				process(i)
			}
			if len(f.raw) != 8 || len(f.e.state.Entries) != 1 || f.e.state.Mode != "learning" {
				t.Fatal("fifth event did not immediately filter")
			}
			if status := f.e.summaryBase(f.now); status.SourceEventType != kind || !status.FilteringActive {
				t.Fatalf("wrong stream status: %+v", status)
			}
			for i := 9; i < 100; i++ {
				process(i)
			}
			if len(f.raw) != 8 {
				t.Fatal("legacy rate model resumed output")
			}
			f.e.freeze(f.now)
			switch kind {
			case "exec":
				ctx.Exec.CommandLine += " "
			case "active_connect":
				ctx.Network.Port++
			case "powershell_script_block":
				ctx.Risk.ScriptSHA256 = strings.Repeat("b", 64)
			}
			for i := 100; i < 106; i++ {
				process(i)
			}
			if len(f.raw) != 14 || len(f.e.state.Candidates) != 0 || len(f.e.state.Entries) != 1 {
				t.Fatal("frozen baseline learned or suppressed a changed tuple")
			}
		})
	}
}

func simplePolicyCase(t *testing.T, kind string) (Config, Context) {
	t.Helper()
	cfg := Config{Enabled: true, StateDir: t.TempDir(), EventTypes: []string{kind}}
	fields := ExecFields{PIDName: "powershell.exe", Exe: `C:\Users\Alice\powershell.exe`, CommandLine: "powershell -File job.ps1"}
	switch kind {
	case "exec":
		return WindowsExecPolicy(cfg), Context{Exec: &fields}
	case "active_connect":
		return NetworkPolicy(cfg), Context{Network: &NetworkFields{ExecFields: fields, Protocol: "tcp", Address: "8.8.8.8", Port: 22}}
	default:
		return ScriptPolicy(cfg), Context{Risk: &WindowsRiskContext{Provider: "Microsoft-Windows-PowerShell", Channel: "Microsoft-Windows-PowerShell/Operational", UserSID: "S-1-5-21-1001", Path: "", ScriptSHA256: strings.Repeat("a", 64)}}
	}
}

func TestSimpleNetworkAndScriptRequireCompleteExactTuples(t *testing.T) {
	for _, kind := range []string{"active_connect", "powershell_script_block"} {
		cfg, ctx := simplePolicyCase(t, kind)
		f := fixtureWithConfig(t, cfg)
		tuple, ok := cfg.simpleTuple(ctx)
		if !ok {
			t.Fatal("complete tuple rejected")
		}
		originalKey := f.e.simpleHash(kind, tuple)
		var changes []func()
		if kind == "active_connect" {
			n := ctx.Network
			changes = []func(){func() { n.PIDName += "X" }, func() { n.Exe += " " }, func() { n.CommandLine += " " }, func() { n.Protocol = "udp" }, func() { n.Address = "1.1.1.1" }, func() { n.Port++ }}
		} else {
			r := ctx.Risk
			changes = []func(){func() { r.Provider += "X" }, func() { r.Channel += "X" }, func() { r.UserSID += "X" }, func() { r.Path = `C:\job.ps1` }, func() { r.ScriptSHA256 = strings.Repeat("c", 64) }}
		}
		for _, change := range changes {
			change()
			next, complete := cfg.simpleTuple(ctx)
			if !complete || f.e.simpleHash(kind, next) == originalKey {
				t.Fatalf("%s field difference merged", kind)
			}
			originalKey = f.e.simpleHash(kind, next)
		}
		if kind == "active_connect" {
			ctx.Network.ListenerProcess = "invented"
		} else {
			ctx.Risk.ScriptSHA256 = "partial"
		}
		if _, ok := cfg.simpleTuple(ctx); ok {
			t.Fatalf("%s incomplete tuple accepted", kind)
		}
	}
}

// Migration must authenticate the old policy/device before discarding its
// entries. The archived checkpoint remains available for an explicit rollback.
func TestSimpleWindowsAndScriptMigrateLegacyStateOnce(t *testing.T) {
	for _, kind := range []string{"exec", "powershell_script_block"} {
		t.Run(kind, func(t *testing.T) {
			cfg, _ := simplePolicyCase(t, kind)
			legacy := cfg
			legacy.simpleExec = false
			sink := func(json.RawMessage) error { return nil }
			summary := func(Summary) error { return nil }
			old, err := New(legacy, "test-device", sink, summary)
			if err != nil {
				t.Fatal(err)
			}
			baseline := old.state.BaselineID
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			next, err := New(cfg, "test-device", sink, summary)
			if err != nil {
				t.Fatal(err)
			}
			if next.state.BaselineID == baseline || next.state.Reason != "simple_policy_migrated" {
				t.Fatal("legacy state reused")
			}
			if _, err := os.Stat(filepath.Join(cfg.StateDir, "legacy-state.json")); err != nil {
				t.Fatal(err)
			}
			baseline = next.state.BaselineID
			if err := next.Close(); err != nil {
				t.Fatal(err)
			}
			restored, err := New(cfg, "test-device", sink, summary)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			if restored.state.BaselineID != baseline {
				t.Fatal("clean restart restarted learning")
			}
		})
	}
}
