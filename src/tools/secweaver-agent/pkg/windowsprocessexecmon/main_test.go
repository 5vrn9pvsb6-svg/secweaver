package windowsprocessexecmon

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"secweaver-agent/internal/windowsevidence"
	"secweaver-agent/pkg/windowseventlog"
)

func TestClassifySecurity4688AsHostExec(t *testing.T) {
	event := mustParseOne(t, `<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-07-08T01:02:03Z"/>
    <EventRecordID>200</EventRecordID>
    <Channel>Security</Channel>
    <Computer>win-01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">alice</Data>
    <Data Name="NewProcessId">0x2a</Data>
    <Data Name="CreatorProcessId">0x10</Data>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="CreatorProcessName">C:\Windows\explorer.exe</Data>
  </EventData>
</Event>`)
	events := windowsevidence.Classify(event, false)
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	got := events[0]
	if got.AssetType != "host_exec" || got.EventType != "exec" || got.Process != "cmd.exe" || got.Command != "cmd.exe /c whoami" {
		t.Fatalf("unexpected evidence event: %+v", got)
	}
}

func TestDefaultWindowsProcessPollInterval(t *testing.T) {
	if defaultWindowsProcessPollInterval != 5*time.Minute {
		t.Fatalf("default poll interval = %v, want 5m", defaultWindowsProcessPollInterval)
	}
}

func TestClassifySysmonNetworkAsHostConnect(t *testing.T) {
	event := mustParseOne(t, `<Event>
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>3</EventID>
    <TimeCreated SystemTime="2026-07-08T01:02:03Z"/>
    <EventRecordID>201</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-01</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="ProcessId">1234</Data>
    <Data Name="SourceIp">10.0.0.5</Data>
    <Data Name="SourcePort">50000</Data>
    <Data Name="DestinationIp">203.0.113.20</Data>
    <Data Name="DestinationPort">443</Data>
    <Data Name="Protocol">tcp</Data>
  </EventData>
</Event>`)
	events := windowsevidence.Classify(event, false)
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	got := events[0]
	if got.AssetType != "host_connect" || got.EventType != "active_connect" || got.DstIP != "203.0.113.20" || got.DstPort != "443" {
		t.Fatalf("unexpected evidence event: %+v", got)
	}
}

func TestSuppressesAgentAndDirectChildProcessEvents(t *testing.T) {
	for _, xml := range []string{
		`<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><TimeCreated SystemTime="2026-07-08T01:02:03Z"/><Channel>Security</Channel><Computer>win-01</Computer></System><EventData><Data Name="NewProcessName">C:\Program Files\SecWeaver\secweaver-agent.exe</Data><Data Name="CreatorProcessName">C:\Windows\System32\services.exe</Data></EventData></Event>`,
		`<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><TimeCreated SystemTime="2026-07-08T01:02:03Z"/><Channel>Security</Channel><Computer>win-01</Computer></System><EventData><Data Name="NewProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name="CreatorProcessName">C:\Program Files\SecWeaver\secweaver-agent.exe</Data></EventData></Event>`,
	} {
		if events := windowsevidence.Classify(mustParseOne(t, xml), false); len(events) != 0 {
			t.Fatalf("agent-generated process event was not suppressed: %+v", events)
		}
	}
}

func TestCollectOncePaginatesUntilCursorCatchesUp(t *testing.T) {
	orig := queryWindowsEventsAscending
	defer func() { queryWindowsEventsAscending = orig }()
	pages := [][]windowseventlog.Event{
		{
			mustParseOne(t, security4688PageEventXML("101")),
			mustParseOne(t, security4688PageEventXML("102")),
		},
		{
			mustParseOne(t, security4688PageEventXML("103")),
		},
	}
	calls := 0
	queryWindowsEventsAscending = func(ctx context.Context, channel string, afterRecordID uint64, lookback time.Duration, maxEvents int) ([]windowseventlog.Event, error) {
		if channel != "Security" || maxEvents != 2 {
			t.Fatalf("unexpected query args channel=%s max=%d", channel, maxEvents)
		}
		if calls == 0 && afterRecordID != 100 {
			t.Fatalf("first cursor=%d want 100", afterRecordID)
		}
		if calls == 1 && afterRecordID != 102 {
			t.Fatalf("second cursor=%d want 102", afterRecordID)
		}
		page := pages[calls]
		calls++
		return page, nil
	}
	var out bytes.Buffer
	st := &stats{}
	cursors := map[string]uint64{"Security": 100}
	err := collectOnce(context.Background(), runConfig{Channels: []string{"Security"}, MaxEvents: 2}, &out, st, cursors, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || cursors["Security"] != 103 || st.Queries != 2 || st.EventsRead != 3 {
		t.Fatalf("calls=%d cursor=%d stats=%+v", calls, cursors["Security"], st)
	}
	dec := json.NewDecoder(&out)
	count := 0
	for dec.More() {
		var event windowsevidence.Event
		if err := dec.Decode(&event); err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 3 {
		t.Fatalf("written events=%d want 3 output=%s", count, out.String())
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

func security4688PageEventXML(recordID string) string {
	return `<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-07-08T01:02:03Z"/>
    <EventRecordID>` + recordID + `</EventRecordID>
    <Channel>Security</Channel>
    <Computer>win-01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">alice</Data>
    <Data Name="NewProcessId">0x2a</Data>
    <Data Name="CreatorProcessId">0x10</Data>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="CreatorProcessName">C:\Windows\explorer.exe</Data>
  </EventData>
</Event>`
}
