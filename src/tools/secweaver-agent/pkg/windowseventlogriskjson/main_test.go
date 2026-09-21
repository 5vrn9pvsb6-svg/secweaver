package windowseventlogriskjson

import (
	"bytes"
	"context"
	"testing"
	"time"

	"secweaver-agent/pkg/windowseventlog"
)

func TestClassifyFailedWindowsLogon(t *testing.T) {
	event := mustParseOne(t, `<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-07-08T01:02:03Z"/>
    <EventRecordID>100</EventRecordID>
    <Channel>Security</Channel>
    <Computer>win-01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">administrator</Data>
    <Data Name="IpAddress">198.51.100.9</Data>
    <Data Name="LogonType">10</Data>
  </EventData>
</Event>`)
	events := classifyRiskEvent(event, false)
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	got := events[0]
	if got.AssetType != "windows_event_log" || got.EventType != "windows_logon_failed" || got.User != "administrator" || got.SrcIP != "198.51.100.9" {
		t.Fatalf("unexpected risk event: %+v", got)
	}
}

func TestClassifySuccessfulWindowsLogonHighRisk(t *testing.T) {
	event := mustParseOne(t, `<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-07-08T01:02:03Z"/>
    <EventRecordID>102</EventRecordID>
    <Channel>Security</Channel>
    <Computer>win-01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">devops</Data>
    <Data Name="IpAddress">192.0.2.91</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>`)
	events := classifyRiskEvent(event, false)
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	got := events[0]
	if got.EventType != "windows_logon_success" || got.User != "devops" || got.SrcIP != "192.0.2.91" || got.Severity != "high" {
		t.Fatalf("unexpected risk event: %+v", got)
	}
}

func TestClassifyPowerShellScriptBlockHighRisk(t *testing.T) {
	event := mustParseOne(t, `<Event>
  <System>
    <Provider Name="Microsoft-Windows-PowerShell"/>
    <EventID>4104</EventID>
    <TimeCreated SystemTime="2026-07-08T01:02:03Z"/>
    <EventRecordID>101</EventRecordID>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
    <Computer>win-01</Computer>
  </System>
  <EventData>
    <Data Name="ScriptBlockText">powershell -EncodedCommand SQBFAFgA</Data>
  </EventData>
</Event>`)
	events := classifyRiskEvent(event, false)
	if len(events) != 1 || events[0].Severity != "high" || events[0].EventType != "powershell_script_block" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestMarkerAloneDoesNotSuppressUnknownPowerShellScript(t *testing.T) {
	event := mustParseOne(t, `<Event><System><Provider Name="Microsoft-Windows-PowerShell"/><EventID>4104</EventID><TimeCreated SystemTime="2026-07-08T01:02:03Z"/><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>win-01</Computer></System><EventData><Data Name="ScriptBlockText">$swMarker='SECWEAVER_INTERNAL_QUERY'; Get-CimInstance Win32_Process</Data></EventData></Event>`)
	if events := classifyRiskEvent(event, false); len(events) != 1 {
		t.Fatalf("unknown script must not bypass detection by copying the marker: %+v", events)
	}
}

func TestCollectOncePaginatesWindowsRiskEvents(t *testing.T) {
	orig := queryWindowsEventsAscending
	defer func() { queryWindowsEventsAscending = orig }()
	pages := [][]windowseventlog.Event{
		{
			mustParseOne(t, logonSuccessPageEventXML("201")),
			mustParseOne(t, logonSuccessPageEventXML("202")),
		},
		{
			mustParseOne(t, logonSuccessPageEventXML("203")),
		},
	}
	calls := 0
	queryWindowsEventsAscending = func(ctx context.Context, channel string, afterRecordID uint64, lookback time.Duration, maxEvents int) ([]windowseventlog.Event, error) {
		page := pages[calls]
		calls++
		return page, nil
	}
	var out bytes.Buffer
	st := &stats{}
	cursors := map[string]uint64{"Security": 200}
	err := collectOnce(context.Background(), runConfig{Channels: []string{"Security"}, MaxEvents: 2, MinLevel: "medium"}, &out, nil, st, cursors, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || cursors["Security"] != 203 || st.Queries != 2 || st.EventsRead != 3 || st.EventsWritten != 3 {
		t.Fatalf("calls=%d cursor=%d stats=%+v output=%s", calls, cursors["Security"], st, out.String())
	}
}

func TestCollectOnceAlsoWritesProcessEvidence(t *testing.T) {
	orig := queryWindowsEventsAscending
	defer func() { queryWindowsEventsAscending = orig }()
	called := false
	queryWindowsEventsAscending = func(ctx context.Context, channel string, afterRecordID uint64, lookback time.Duration, maxEvents int) ([]windowseventlog.Event, error) {
		if called {
			return nil, nil
		}
		called = true
		return []windowseventlog.Event{mustParseOne(t, `<Event>
  <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><TimeCreated SystemTime="2026-07-08T01:02:03Z"/><EventRecordID>301</EventRecordID><Channel>Security</Channel><Computer>win-01</Computer></System>
  <EventData><Data Name="SubjectUserName">alice</Data><Data Name="NewProcessId">0x2a</Data><Data Name="CreatorProcessId">0x10</Data><Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c whoami</Data><Data Name="CreatorProcessName">C:\Windows\explorer.exe</Data></EventData>
</Event>`)}, nil
	}
	var riskOut bytes.Buffer
	var evidenceOut bytes.Buffer
	st := &stats{}
	cursors := map[string]uint64{}
	err := collectOnce(context.Background(), runConfig{Channels: []string{"Security"}, MaxEvents: 10, MinLevel: "medium"}, &riskOut, &evidenceOut, st, cursors, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if st.EvidenceWritten != 1 || cursors["Security"] != 301 {
		t.Fatalf("stats=%+v cursors=%v evidence=%s", st, cursors, evidenceOut.String())
	}
	if !bytes.Contains(evidenceOut.Bytes(), []byte(`"asset_type":"host_exec"`)) {
		t.Fatalf("process evidence missing: %s", evidenceOut.String())
	}
}

func mustParseOne(t *testing.T, text string) windowseventlog.Event {
	t.Helper()
	events, err := windowseventlog.ParseEventsXML(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	return events[0]
}

func logonSuccessPageEventXML(recordID string) string {
	return `<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-07-08T01:02:03Z"/>
    <EventRecordID>` + recordID + `</EventRecordID>
    <Channel>Security</Channel>
    <Computer>win-01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">devops</Data>
    <Data Name="IpAddress">192.0.2.91</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>`
}
