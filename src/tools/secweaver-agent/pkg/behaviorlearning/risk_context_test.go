package behaviorlearning

import (
	"fmt"
	"strings"
	"testing"
)

func riskObservation(n int) Observation {
	return Observation{Context: Context{Executable: "root/standardcimv2/msft_nettcpconnection", Capability: "windows-powershell-cdxml-v1",
		Risk: &WindowsRiskContext{Provider: "Microsoft-Windows-PowerShell", Channel: "Microsoft-Windows-PowerShell/Operational",
			UserSID: "S-1-5-18", ModuleClass: "root/standardcimv2/msft_nettcpconnection", ScriptSHA256: strings.Repeat("a", 64)}},
		Complete: true, EventID: fmt.Sprint("script:", n), Raw: []byte(`{"source_stream":"windows_risk"}`)}
}

// Risk matching exercises the real authenticated engine without inventing an
// exec instance. Exact origin/content changes never reuse a qualified entry.
func TestRiskBaselineExactMatchingProtectedAndRateAnomaly(t *testing.T) {
	f := newFixture(t)
	f.e.cfg.EventTypes = []string{"powershell_script_block"}
	for i := 0; i < 8; i++ {
		f.e.state.HealthySeconds = float64(i * 3600)
		if err := f.e.Process(riskObservation(i)); err != nil {
			t.Fatal(err)
		}
	}
	f.e.state.HealthySeconds = 86400
	f.e.freeze(f.now)
	if f.e.state.Mode != "enforcing" {
		t.Fatal(f.e.state.Reason)
	}
	f.raw = nil
	if err := f.e.Process(riskObservation(100)); err != nil || len(f.raw) != 0 || len(f.e.evidence) != 0 {
		t.Fatal("exact script did not suppress without exec replay cache")
	}
	for i, change := range []func(*Observation){
		func(o *Observation) { o.Context.Risk.ScriptSHA256 = strings.Repeat("b", 64) },
		func(o *Observation) {
			o.Context.Risk.Path = `C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Other.psm1`
		},
		func(o *Observation) { o.Context.Risk.UserSID = "S-1-5-21-1-2-3-1001" },
		func(o *Observation) { o.Reason = "protected_security_event" },
		func(o *Observation) { o.Context.Windows = &WindowsContext{} },
	} {
		o := riskObservation(200 + i)
		change(&o)
		if err := f.e.Process(o); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.raw) != 5 {
		t.Fatal("changed/protected script matched baseline")
	}
	f.raw = nil
	f.e.cfg.Shadow = true
	_ = f.e.Process(riskObservation(300))
	if len(f.raw) != 1 {
		t.Fatal("shadow suppressed script")
	}
	f.raw = nil
	f.e.cfg.Shadow = false
	for i := 0; i < 12; i++ {
		_ = f.e.Process(riskObservation(400 + i))
	}
	if len(f.raw) == 0 {
		t.Fatal("burst above rate limit stayed suppressed")
	}
	f.raw = nil
	f.e.Fault("source_event_loss")
	_ = f.e.Process(riskObservation(500))
	if len(f.raw) != 1 || f.e.state.Mode != "degraded" {
		t.Fatal("source loss stayed suppressed")
	}
}

func TestNativeRiskNeverReplaysProcessAncestry(t *testing.T) {
	f := newFixture(t)
	f.e.cfg.EventTypes = []string{"powershell_script_block"}
	f.e.evidence["unverified-parent"] = evidence{raw: []byte(`{"event_type":"exec"}`), id: "parent-exec", at: f.now}
	o := riskObservation(1)
	o.ParentInstance = "unverified-parent"
	if err := f.e.Process(o); err != nil || len(f.raw) != 1 || strings.Contains(string(f.raw[0]), "context_only") {
		t.Fatal("native risk emitted an unverified exec edge")
	}
}
