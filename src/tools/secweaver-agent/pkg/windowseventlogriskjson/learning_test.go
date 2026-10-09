package windowseventlogriskjson

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/windowseventlog"
)

const safeCDXML = "\n$__cmdletization_ClassName = 'ROOT/StandardCimv2/MSFT_NetTCPConnection'\n" +
	"$__cmdletization_ObjectModelWrapper = [Microsoft.PowerShell.Cmdletization.Cim.CimCmdletAdapter]\n" +
	"function __cmdletization_BindCommonParameters { param($Object) }\n"

// decisionEngine isolates fragment assembly from the real engine's day-long
// state machine, which is tested separately with a controlled clock.
type decisionEngine struct {
	write        func(json.RawMessage) error
	observations []behaviorlearning.Observation
	fault        string
	suppress     bool
}

func (e *decisionEngine) Process(o behaviorlearning.Observation) error {
	e.observations = append(e.observations, o)
	if e.suppress && e.fault == "" && o.Complete && o.Reason == "" {
		return nil
	}
	return e.write(o.Raw)
}
func (e *decisionEngine) Health(bool, bool)                                 {}
func (e *decisionEngine) Fault(reason string)                               { e.fault = reason }
func (e *decisionEngine) Tick() error                                       { return nil }
func (e *decisionEngine) Checkpoint() error                                 { return nil }
func (e *decisionEngine) CloseWithCheckpoint(checkpoint func() error) error { return checkpoint() }

func scriptFixture(out io.Writer, suppress bool) (*riskLearning, *decisionEngine) {
	w := &riskLearning{out: out, pending: map[string]*scriptGroup{}, started: time.Now().Add(-time.Minute)}
	e := &decisionEngine{write: w.emitDecision, suppress: suppress}
	w.engine = e
	return w, e
}

func scriptEvent(record, number, total int, text string) windowseventlog.Event {
	return windowseventlog.Event{System: windowseventlog.SystemData{Provider: "Microsoft-Windows-PowerShell",
		EventID: "4104", Channel: powerShellChannel, UserID: "S-1-5-18", Computer: "test-host", ProcessID: "123",
		EventRecordID: fmt.Sprint(record), TimeCreated: time.Now().UTC().Format(time.RFC3339Nano)}, EventData: []windowseventlog.DataField{
		{Name: "ScriptBlockText", Value: text}, {Name: "ScriptBlockId", Value: "11111111-1111-1111-1111-111111111111"},
		{Name: "MessageNumber", Value: fmt.Sprint(number)}, {Name: "MessageTotal", Value: fmt.Sprint(total)},
	}}
}

func observeScript(t *testing.T, w *riskLearning, event windowseventlog.Event) int {
	t.Helper()
	items := classifyRiskEvent(event, false)
	if len(items) != 1 {
		t.Fatalf("classified %d risk records", len(items))
	}
	n, err := w.observe(event, items[0])
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestScriptAssemblyUsesExactWholeContentNotFragmentBoundaries(t *testing.T) {
	for _, boundary := range []int{1, 47, len(safeCDXML) - 1} {
		var out bytes.Buffer
		w, e := scriptFixture(&out, true)
		if n := observeScript(t, w, scriptEvent(1, 1, 2, safeCDXML[:boundary])); n != 0 || len(e.observations) != 0 {
			t.Fatal("partial block made a decision")
		}
		observeScript(t, w, scriptEvent(2, 2, 2, safeCDXML[boundary:]))
		if len(e.observations) != 1 || !e.observations[0].Complete || out.Len() != 0 || w.suppressed != 2 {
			t.Fatalf("wrong complete decision: %+v", e.observations)
		}
		want := fmt.Sprintf("%x", sha256.Sum256([]byte(safeCDXML)))
		if got := e.observations[0].Context.Risk.ScriptSHA256; got != want {
			t.Fatalf("trimmed/reordered script: %s != %s", got, want)
		}
		if len(w.pending) != 0 || w.pendingBytes != 0 {
			t.Fatal("completed script retained memory")
		}
	}
}

// Ordinary scripts, custom paths and non-SYSTEM users now use exact content
// matching. Changing one of them creates a different tuple instead of bypassing
// learning through the removed CDXML/service heuristics.
func TestSimpleRiskAcceptsOrdinaryScriptsAndAllKnownUsers(t *testing.T) {
	for _, scenario := range []string{"user", "ordinary", "module-path"} {
		t.Run(scenario, func(t *testing.T) {
			var out bytes.Buffer
			w, engine := scriptFixture(&out, true)
			event := scriptEvent(1, 1, 1, safeCDXML)
			switch scenario {
			case "user":
				event.System.UserID = "S-1-5-21-1-2-3-1001"
			case "ordinary":
				event.EventData[0].Value = "Write-Output 'business task'"
			case "module-path":
				event.EventData = append(event.EventData, windowseventlog.DataField{Name: "Path", Value: `C:\Temp\module.psm1`})
			}
			if n := observeScript(t, w, event); n != 0 || len(engine.observations) != 1 || !engine.observations[0].Complete {
				t.Fatalf("complete script rejected: writes=%d observations=%+v", n, engine.observations)
			}
		})
	}
}

func TestRiskLearningPreservesNativeIdentityAndFragments(t *testing.T) {
	var out bytes.Buffer
	w, _ := scriptFixture(&out, false)
	observeScript(t, w, scriptEvent(21, 1, 2, safeCDXML[:47]))
	if n := observeScript(t, w, scriptEvent(22, 2, 2, safeCDXML[47:])); n != 2 {
		t.Fatalf("writes=%d", n)
	}
	decoder := json.NewDecoder(&out)
	var script strings.Builder
	for _, record := range []string{"21", "22"} {
		var item map[string]any
		if err := decoder.Decode(&item); err != nil {
			t.Fatal(err)
		}
		if item["event_id"] != "4104" || item["windows_record_id"] != record || item["user_sid"] != "S-1-5-18" {
			t.Fatalf("lost native identity: %v", item)
		}
		script.WriteString(item["command"].(string))
	}
	if script.String() != safeCDXML {
		t.Fatal("original fragment content changed")
	}
}

func TestIncompleteConflictAndBudgetAlwaysEmit(t *testing.T) {
	for _, scenario := range []string{"incomplete", "duplicate", "oversize", "group-budget"} {
		t.Run(scenario, func(t *testing.T) {
			var out bytes.Buffer
			w, e := scriptFixture(&out, true)
			observeScript(t, w, scriptEvent(1, 1, 2, safeCDXML[:47]))
			switch scenario {
			case "duplicate":
				if n := observeScript(t, w, scriptEvent(2, 1, 2, "different")); n != 2 {
					t.Fatalf("conflict count=%d", n)
				}
			case "oversize":
				observeScript(t, w, scriptEvent(2, 2, 2, strings.Repeat("x", maxScriptBytes)))
			case "group-budget":
				for i := 2; i <= maxPendingScripts+1; i++ {
					event := scriptEvent(i, 1, 2, "partial")
					event.EventData[1].Value = fmt.Sprintf("%08x-1111-1111-1111-111111111111", i)
					observeScript(t, w, event)
				}
			}
			if _, err := w.finishRound(true); err != nil {
				t.Fatal(err)
			}
			if out.Len() == 0 || len(e.observations) != 0 || len(w.pending) != 0 || w.pendingBytes != 0 {
				t.Fatal("partial or budget-exceeded evidence was learned/lost")
			}
			if err := w.Sync(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRiskIdentityAndProtectedScriptNeverTrain(t *testing.T) {
	for _, scenario := range []string{"missing-sid", "provider", "historical", "future", "record", "suspicious-boundary"} {
		t.Run(scenario, func(t *testing.T) {
			var out bytes.Buffer
			w, e := scriptFixture(&out, true)
			event := scriptEvent(1, 1, 1, safeCDXML)
			switch scenario {
			case "missing-sid":
				event.System.UserID = ""
			case "provider":
				event.System.Provider = "Spoofed"
			case "historical":
				event.System.TimeCreated = w.started.Add(-time.Hour).Format(time.RFC3339Nano)
			case "future":
				event.System.TimeCreated = time.Now().Add(time.Hour).Format(time.RFC3339Nano)
			case "record":
				event.System.EventRecordID = "0"
			case "suspicious-boundary":
				text := safeCDXML + "DownloadString('https://example.invalid')"
				boundary := len(safeCDXML) + len("Download")
				observeScript(t, w, scriptEvent(1, 1, 2, text[:boundary]))
				event = scriptEvent(2, 2, 2, text[boundary:])
			}
			observeScript(t, w, event)
			if out.Len() == 0 || w.suppressed != 0 {
				t.Fatal("unqualified event suppressed")
			}
			for _, o := range e.observations {
				if o.Complete || o.Reason == "" {
					t.Fatal("unqualified event trained")
				}
			}
			if scenario == "suspicious-boundary" && strings.Count(out.String(), `"severity":"high"`) != 2 {
				t.Fatal("whole-script suspicious token did not protect both fragments")
			}
		})
	}
}

// Complete two-fragment scripts exercise the actual durable counter. Five
// scripts, not five fragments, are needed; a protected alert still emits after
// the ordinary script baseline has started filtering.
func TestSimpleRiskFifthWholeScriptFiltersThroughRealEngine(t *testing.T) {
	t.Setenv("SECWEAVER_DEVICE_ID", "test-device")
	var out bytes.Buffer
	options := RiskLearningOptions{Enabled: true, StateDir: filepath.Join(t.TempDir(), "risk")}
	wrapped, closeLearning := wrapRiskLearning(&out, options, "", time.Second)
	t.Cleanup(func() {
		if err := closeLearning(); err != nil {
			t.Error(err)
		}
	})
	w, ok := wrapped.(*riskLearning)
	if !ok {
		t.Fatal("real risk engine was not initialized")
	}
	w.engine.Health(true, false)
	script := "Write-Output 'ordinary business task'"
	for i := 0; i < 6; i++ {
		if n := observeScript(t, w, scriptEvent(i*2+1, 1, 2, script[:12])); n != 0 {
			t.Fatal("partial script emitted before assembly")
		}
		n := observeScript(t, w, scriptEvent(i*2+2, 2, 2, script[12:]))
		want := 2
		if i >= 4 {
			want = 0
		}
		if n != want {
			t.Fatalf("script %d wrote %d fragments want %d", i, n, want)
		}
	}
	for i := 0; i < 6; i++ {
		if n := observeScript(t, w, scriptEvent(100+i, 1, 1, "DownloadString('https://example.invalid')")); n != 1 {
			t.Fatal("protected script suppressed")
		}
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	state, err := behaviorlearning.Inspect(options.StateDir, 64)
	if err != nil || len(state.Entries) != 1 {
		t.Fatalf("unexpected risk baseline: %+v %v", state, err)
	}
}

// Fake query pages exercise the production collector barrier without native
// wevtutil, SCM, Sysmon or a real Windows machine.
func TestRiskFragmentsAcrossPagesAndProtectedEvents(t *testing.T) {
	old := queryWindowsEventsAscending
	t.Cleanup(func() { queryWindowsEventsAscending = old })
	logon := windowseventlog.Event{System: windowseventlog.SystemData{EventID: "4624", EventRecordID: "5", Channel: "Security"}}
	queryWindowsEventsAscending = func(_ context.Context, channel string, cursor uint64, _ time.Duration, _ int) ([]windowseventlog.Event, error) {
		if channel == "Security" && cursor == 0 {
			return []windowseventlog.Event{logon}, nil
		}
		if channel == powerShellChannel && cursor < 2 {
			n := int(cursor) + 1
			text := safeCDXML[:47]
			if n == 2 {
				text = safeCDXML[47:]
			}
			return []windowseventlog.Event{scriptEvent(n, n, 2, text)}, nil
		}
		return nil, nil
	}
	var out bytes.Buffer
	w, _ := scriptFixture(&out, true)
	st := &stats{}
	cursors := map[string]uint64{}
	err := collectOnce(context.Background(), runConfig{Channels: []string{powerShellChannel, "Security"}, MaxEvents: 1, MinLevel: "medium"}, w, nil, st, cursors, map[string]bool{})
	if err != nil || st.EventsRead != 3 || st.EventsWritten != 1 || st.RiskLearningSuppressed != 2 || cursors[powerShellChannel] != 2 {
		t.Fatalf("stats=%+v cursor=%v err=%v", st, cursors, err)
	}
	if !strings.Contains(out.String(), "windows_logon_success") || len(w.pending) != 0 {
		t.Fatal("protected event missing")
	}
}

func TestRiskQueryLossAndCheckpointFailure(t *testing.T) {
	old := queryWindowsEventsAscending
	t.Cleanup(func() { queryWindowsEventsAscending = old })
	queryWindowsEventsAscending = func(_ context.Context, channel string, _ uint64, _ time.Duration, _ int) ([]windowseventlog.Event, error) {
		if channel == powerShellChannel {
			return nil, errors.New("query failed")
		}
		return nil, errors.New("optional Sysmon absent")
	}
	var out bytes.Buffer
	w, e := scriptFixture(&out, true)
	if err := collectOnce(context.Background(), runConfig{Channels: []string{"Microsoft-Windows-Sysmon/Operational"}}, w, nil, &stats{}, map[string]uint64{}, map[string]bool{}); err != nil || e.fault != "" {
		t.Fatal("optional Sysmon failure invalidated native risk baseline")
	}
	_ = collectOnce(context.Background(), runConfig{Channels: []string{powerShellChannel}}, w, nil, &stats{}, map[string]uint64{}, map[string]bool{})
	if e.fault != "risk_source_query_failed" {
		t.Fatal("source loss hidden")
	}
	observeScript(t, w, scriptEvent(1, 1, 1, safeCDXML))
	if out.Len() == 0 {
		t.Fatal("source loss continued filtering")
	}
	w.out = &checkpointFailure{}
	if err := w.Sync(); err == nil || e.fault != "risk_output_checkpoint_failed" {
		t.Fatal("checkpoint error hidden")
	}
}

func TestRiskLearningFailOpenAndIndependentState(t *testing.T) {
	var out bytes.Buffer
	t.Setenv("SECWEAVER_DEVICE_ID", "")
	o := RiskLearningOptions{Enabled: true, StateDir: filepath.Join(t.TempDir(), "risk")}
	wrapped, closeLearning := wrapRiskLearning(&out, o, "", time.Second)
	if wrapped != &out || closeLearning() != nil {
		t.Fatal("missing identity did not fail open")
	}
	t.Setenv("SECWEAVER_DEVICE_ID", "swd-test")
	wrapped, closeLearning = wrapRiskLearning(&out, o, "", time.Second)
	if _, ok := wrapped.(*riskLearning); !ok {
		t.Fatal("registered risk learning did not initialize")
	}
	defer closeLearning()
	second, closeSecond := wrapRiskLearning(&out, o, "", time.Second)
	if second != &out || closeSecond() != nil {
		t.Fatal("state lock contention did not fail open")
	}
	status, err := ReadRiskLearningStatus(o, "", filepath.Join(t.TempDir(), "missing.log"), "swd-test")
	if err != nil || status.Mode != "learning" || status.FilteringActive {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

// A failed risk fsync leaves the durable cursor untouched, including incomplete
// fragments flushed by the round barrier. Restart can replay original evidence.
func TestRiskCheckpointFailureDoesNotAdvanceCursor(t *testing.T) {
	t.Setenv("SECWEAVER_DEVICE_ID", "swd-risk-test")
	old := queryWindowsEventsAscending
	t.Cleanup(func() { queryWindowsEventsAscending = old })
	queryWindowsEventsAscending = func(_ context.Context, _ string, _ uint64, _ time.Duration, _ int) ([]windowseventlog.Event, error) {
		return []windowseventlog.Event{scriptEvent(1, 1, 2, safeCDXML[:47])}, nil
	}
	dir := t.TempDir()
	cursor := filepath.Join(dir, "cursor.json")
	out := &checkpointFailure{}
	err := run(context.Background(), runConfig{Channels: []string{powerShellChannel}, StateFile: cursor,
		Once: true, MaxEvents: 10, MinLevel: "medium", RiskLearning: RiskLearningOptions{Enabled: true, StateDir: filepath.Join(dir, "risk")}}, out, nil, &stats{})
	if err == nil {
		t.Fatal("risk checkpoint failure hidden")
	}
	if _, err := os.Stat(cursor); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed risk output advanced cursor")
	}
	if !strings.Contains(out.String(), "risk_script_incomplete") {
		t.Fatal("incomplete evidence not flushed")
	}
}

func TestRiskSummaryContract(t *testing.T) {
	var out bytes.Buffer
	w, _ := scriptFixture(&out, false)
	err := w.emitSummary(behaviorlearning.Summary{Time: time.Now(), EventType: "behavior_summary", SourceEventType: "powershell_script_block", Suppressed: 3})
	var record map[string]any
	if err != nil || json.Unmarshal(out.Bytes(), &record) != nil {
		t.Fatal("invalid summary JSON")
	}
	if record["source_stream"] != "windows_risk" || record["count_unit"] != "script_blocks" || record["risk_level"] != "info" || record["timestamp"] == "" || record["suppressed_count"] != float64(3) {
		t.Fatal("risk summary cannot be distinguished from native security evidence")
	}
}

func BenchmarkRiskScriptExactDecision(b *testing.B) {
	w, _ := scriptFixture(io.Discard, true)
	event := scriptEvent(1, 1, 1, safeCDXML+strings.Repeat("# ordinary definition\n", 500))
	item := classifyRiskEvent(event, false)[0]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.observe(event, item); err != nil {
			b.Fatal(err)
		}
		// The fixture records observations for assertions, not production caching.
		w.engine.(*decisionEngine).observations = nil
	}
}
