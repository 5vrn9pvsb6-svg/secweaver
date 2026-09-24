package behaviorlearning

import (
	"encoding/json"
	"strings"
	"testing"
)

func networkObservation(n int) Observation {
	o := windowsObservation(n)
	o.Context.Operation = &Operation{EventType: "active_connect", Action: "connect", Protocol: "tcp", SourceAddress: "10.0.0.10", Address: "10.0.0.20", Port: 443}
	o.ParentInstance = "executor-guid"
	o.Instance = "executor-guid"
	o.Raw = json.RawMessage(`{"event_type":"active_connect"}`)
	return o
}

// promoteOperations feeds the same actor's separate exact targets over the real
// promotion thresholds, with virtual healthy time instead of a day-long sleep.
func promoteOperations(t *testing.T, f *fixture, makeObservation func(int) Observation) {
	t.Helper()
	f.e.cfg.EventTypes = []string{"exec", "active_connect", "file_op"}
	f.e.cfg.FileRoots = []string{`C:\ProgramData\Example`}
	for i := 0; i < 8; i++ {
		f.e.state.HealthySeconds = float64(i * 3600)
		if err := f.e.Process(makeObservation(i)); err != nil {
			t.Fatal(err)
		}
	}
	f.e.state.HealthySeconds = 86400
	f.e.freeze(f.now)
	if f.e.state.Mode != "enforcing" {
		t.Fatalf("failed promotion: %s", f.e.state.Reason)
	}
	f.raw = nil
}

func TestOperationLearningRepeatedSameProcessAndChangedTarget(t *testing.T) {
	f := newFixture(t)
	promoteOperations(t, f, networkObservation)
	for _, id := range []int{100, 101} {
		if err := f.e.Process(networkObservation(id)); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.raw) != 0 {
		t.Fatal("same process's second network event was not suppressible")
	}
	if len(f.e.evidence) != 0 {
		t.Fatal("network record overwrote exec ancestry cache")
	}
	changed := networkObservation(102)
	changed.Context.Operation.Port = 8443
	if err := f.e.Process(changed); err != nil {
		t.Fatal(err)
	}
	if len(f.raw) != 1 {
		t.Fatal("new destination port was suppressed")
	}
	if err := f.e.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if f.summaries[0].SourceEventType != "active_connect" || f.summaries[0].Suppressed != 2 {
		t.Fatalf("wrong typed summary: %+v", f.summaries[0])
	}
}

func TestFileCreationLearnsExactPathAndRetainsDeletion(t *testing.T) {
	makeEvent := func(n int) Observation {
		o := networkObservation(n)
		o.Context.Operation = &Operation{EventType: "file_op", Action: "create", Path: `C:\ProgramData\Example\worker.log`}
		return o
	}
	f := newFixture(t)
	promoteOperations(t, f, makeEvent)
	if err := f.e.Process(makeEvent(100)); err != nil {
		t.Fatal(err)
	}
	if len(f.raw) != 0 {
		t.Fatal("known ordinary creation did not match")
	}
	for i, change := range []func(*Operation){
		func(op *Operation) { op.Action = "delete" },
		func(op *Operation) { op.Action = "rename" },
		func(op *Operation) { op.Path = `C:\ProgramData\Example\new.log` },
		func(op *Operation) { op.Path = `C:\ProgramData\Other\worker.log` },
		func(op *Operation) { op.Path = `C:\ProgramData\Example\audit.log` },
	} {
		o := makeEvent(101 + i)
		change(o.Context.Operation)
		if err := f.e.Process(o); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.raw) != 5 {
		t.Fatal("unknown or dangerous file change suppressed")
	}
}

func TestOperationPolicyRejectsSensitiveAndAmbiguousEvents(t *testing.T) {
	f := newFixture(t)
	f.e.cfg.EventTypes = []string{"exec", "active_connect", "file_op"}
	f.e.cfg.FileRoots = []string{`C:\ProgramData`}
	for name, op := range map[string]Operation{
		"public":           {EventType: "active_connect", Action: "connect", Protocol: "tcp", Address: "8.8.8.8", Port: 443, SourceAddress: "10.0.0.1"},
		"SMB":              {EventType: "active_connect", Action: "connect", Protocol: "tcp", Address: "10.0.0.2", Port: 445, SourceAddress: "10.0.0.1"},
		"unknown-protocol": {EventType: "active_connect", Action: "connect", Address: "10.0.0.2", Port: 443, SourceAddress: "10.0.0.1"},
		"missing-source":   {EventType: "active_connect", Action: "connect", Protocol: "tcp", Address: "10.0.0.2", Port: 443},
		"credentials":      {EventType: "file_op", Action: "create", Path: `C:\ProgramData\credentials\a.log`},
		"persistence":      {EventType: "file_op", Action: "create", Path: `C:\ProgramData\Microsoft\Windows\Start Menu\Startup\a.log`},
		"executable":       {EventType: "file_op", Action: "create", Path: `C:\ProgramData\Example\x.exe`},
		"ADS":              {EventType: "file_op", Action: "create", Path: `C:\ProgramData\Example\a:payload.log`},
		"traversal":        {EventType: "file_op", Action: "create", Path: `C:\ProgramData\Example\..\a.log`},
		"prefix-confusion": {EventType: "file_op", Action: "create", Path: `C:\ProgramDataOther\a.log`},
		"authentication":   {EventType: "login_success", Action: "success"},
	} {
		t.Run(name, func(t *testing.T) {
			c := windowsObservation(1).Context
			c.Operation = &op
			if f.e.operationReason(c) == "" {
				t.Fatal("protected operation admitted")
			}
		})
	}
}

func TestOperationScopeConfigAndLegacyFingerprint(t *testing.T) {
	legacy, err := Decode(json.RawMessage(`{"enabled":true}`))
	if err != nil || len(legacy.EventTypes) != 1 || legacy.EventTypes[0] != "exec" {
		t.Fatal("upgrade broadened legacy scope")
	}
	for _, body := range []string{
		`{"event_types":["authentication"]}`, `{"event_types":["exec","exec"]}`,
		`{"file_roots":["C:\\"]}`, `{"file_roots":["C:\\ProgramData\\*"]}`, `{"file_roots":["/"]}`,
	} {
		if _, err := Decode(json.RawMessage(body)); err == nil {
			t.Fatalf("invalid policy accepted: %s", body)
		}
	}
	f := newFixture(t)
	a := networkObservation(1).Context
	b := a
	b.Operation = &Operation{EventType: "file_op", Action: "create", Path: `C:\ProgramData\Example\worker.log`}
	if f.e.fingerprint(a) == f.e.fingerprint(b) {
		t.Fatal("network and file fingerprints collided")
	}
	encoded, _ := json.Marshal(observation(1).Context)
	if strings.Contains(string(encoded), `"operation"`) {
		t.Fatal("new field changed legacy exec bytes")
	}
}
