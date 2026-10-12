package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, condition, action string) *Engine {
	t.Helper()
	raw := fmt.Sprintf(`{"schema_version":1,"policy_id":"test","revision":1,"enabled":true,"mode":"enforce","rules":[{"id":"r1","name":"test","kind":"event_filter","enabled":true,"mode":"enforce","action":%q,"priority":1,"scope":{"platforms":["linux"],"modules":["audit-port-execmon"],"event_types":["exec"]},"when":%s}]}`, action, condition)
	p, err := Decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	e, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func sample() Event {
	return Event{Platform: "linux", Module: "audit-port-execmon", EventType: "exec", Fields: map[string]any{"/exe": "/usr/bin/curl", "/listener_port": 443, "/file_paths": []string{"/etc/a", "/etc/b"}}}
}

// Importing two hosts' legacy ports must not turn their union into a fleet rule.
func TestDeviceScopeDoesNotBroadenLegacyImport(t *testing.T) {
	e := fixture(t, `{"field":"/listener_port","op":"eq","value":443}`, "suppress")
	p := e.policy
	p.Rules[0].Scope.DeviceIDs = []string{"host-a"}
	e, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	event := sample()
	event.DeviceID = "host-b"
	if e.Decide(event, time.Now()).Action != "pass" {
		t.Fatal("another device suppressed")
	}
	event.DeviceID = "host-a"
	if e.Decide(event, time.Now()).Action != "suppress" {
		t.Fatal("own device not matched")
	}
}
func TestUnknownCannotSuppressThroughNegation(t *testing.T) {
	for _, c := range []string{`{"not":{"field":"/command_line","op":"eq","value":"safe"}}`, `{"field":"/command_line","op":"neq","value":"safe"}`, `{"field":"/listener_port","op":"neq","value":"443"}`} {
		e := fixture(t, c, "suppress")
		if d := e.Decide(sample(), time.Now()); d.Action != "pass" {
			t.Fatalf("unknown matched: %+v", d)
		}
	}
	e := fixture(t, `{"field":"/exe","op":"eq","value":"/usr/bin/curl"}`, "suppress")
	s := sample()
	s.Incomplete = map[string]bool{"/exe": true}
	if e.Decide(s, time.Now()).Action != "pass" {
		t.Fatal("truncated matched")
	}
}
func TestActionPriorityObserveAndProtection(t *testing.T) {
	e := fixture(t, `{"field":"/exe","op":"prefix","value":"/usr/"}`, "suppress")
	p := e.policy
	keep := p.Rules[0]
	keep.ID = "keep"
	keep.Action = "keep"
	keep.Priority = 0
	p.Rules[0].Priority = 1000
	p.Rules = append(p.Rules, keep)
	e, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if d := e.Decide(sample(), time.Now()); d.Action != "keep" || d.RuleID != "keep" {
		t.Fatal(d)
	}
	p.Rules[1].Mode = "observe"
	e, _ = Compile(p)
	if d := e.Decide(sample(), time.Now()); d.Action != "suppress" || d.PredictedAction != "keep" {
		t.Fatal(d)
	}
	s := sample()
	s.Protected = true
	if d := e.Decide(s, time.Now()); d.Action != "keep" || d.Reason != "protected_event" {
		t.Fatal(d)
	}
	p.Mode = "observe"
	e, _ = Compile(p)
	if e.Decide(sample(), time.Now()).Action != "pass" {
		t.Fatal("observe changed output")
	}
}
func TestArrayCIDRAndGroups(t *testing.T) {
	e := fixture(t, `{"all":[{"field":"/file_paths","op":"array_all","value":{"op":"prefix","value":"/etc/"}},{"field":"/listener_port","op":"between","value":[400,500]}]}`, "suppress")
	if d := e.Decide(sample(), time.Now()); d.Action != "suppress" {
		t.Fatal(d)
	}
	s := sample()
	s.Fields["/file_paths"] = []any{"/etc/a", 12}
	if e.Decide(s, time.Now()).Action != "pass" {
		t.Fatal("mixed array matched")
	}
	s.Fields["/file_paths"] = []string{}
	if e.Decide(s, time.Now()).Action != "pass" {
		t.Fatal("empty array matched")
	}
	e = fixture(t, `{"field":"/connect_ip","op":"cidr","value":"192.0.2.0/24"}`, "keep")
	s.Fields["/connect_ip"] = "192.0.2.3"
	if e.Decide(s, time.Now()).Action != "keep" {
		t.Fatal("CIDR miss")
	}
}
func TestBudgetRetainsEvidence(t *testing.T) {
	e := fixture(t, `{"field":"/exe","op":"regex","value":".*"}`, "suppress")
	s := sample()
	s.Fields["/exe"] = strings.Repeat("x", 32769)
	if d := e.Decide(s, time.Now()); d.Action != "keep" || d.Reason != "work_budget_exceeded" {
		t.Fatal(d)
	}
}
func TestStrictValidation(t *testing.T) {
	if _, err := Decode([]byte(`{"schema_version":1,"schema_version":1}`)); err == nil {
		t.Fatal("duplicate accepted")
	}
	e := fixture(t, `{"field":"/exe","op":"eq","value":"x"}`, "pass")
	p := e.policy
	for _, bad := range []Condition{{Field: "/__source__", Op: "exists"}, {Field: "/exe", Op: "regex", Value: `(?=x)`}, {Field: "/exe", Op: "regex", Value: `(x)\1`}, {All: []Condition{}}, {Field: "/exe", Op: "regex", Value: strings.Repeat("x", 513)}} {
		p.Rules[0].When = bad
		if _, err := Compile(p); err == nil {
			t.Fatalf("invalid accepted %+v", bad)
		}
	}
}
func TestExpiredPolicyDoesNotFilter(t *testing.T) {
	e := fixture(t, `{"field":"/exe","op":"exists"}`, "suppress")
	p := e.policy
	p.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	e, _ = Compile(p)
	if d := e.Decide(sample(), time.Now()); d.Action != "pass" || d.Reason != "policy_inactive" {
		t.Fatal(d)
	}
}
func BenchmarkDecision(b *testing.B) {
	p := Policy{SchemaVersion: 1, PolicyID: "bench", Revision: 1, Enabled: true, Mode: "enforce"}
	for i := 0; i < 256; i++ {
		p.Rules = append(p.Rules, Rule{ID: fmt.Sprint(i), Name: "bench", Kind: "event_filter", Enabled: true, Mode: "enforce", Action: "suppress", Scope: Scope{Platforms: []string{"linux"}, Modules: []string{"audit-port-execmon"}, EventTypes: []string{"exec"}}, When: Condition{Field: "/exe", Op: "eq", Value: "/does/not/match"}})
	}
	raw, _ := json.Marshal(p)
	p, _ = Decode(raw)
	e, err := Compile(p)
	if err != nil {
		b.Fatal(err)
	}
	s := sample()
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Decide(s, now)
	}
}
