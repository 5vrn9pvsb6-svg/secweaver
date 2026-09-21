package windowseventlog

import (
	"strings"
	"testing"
	"time"
)

func TestParseEventsXMLParsesEventData(t *testing.T) {
	events, err := ParseEventsXML(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-07-08T01:02:03.1234567Z"/>
    <EventRecordID>42</EventRecordID>
    <Channel>Security</Channel>
    <Computer>win-01</Computer>
    <Execution ProcessID="4" ThreadID="8"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">administrator</Data>
    <Data Name="IpAddress">203.0.113.10</Data>
  </EventData>
</Event>`)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	event := events[0]
	if event.System.EventID != "4625" || event.System.Computer != "win-01" || event.Field("IpAddress") != "203.0.113.10" {
		t.Fatalf("unexpected event: %+v fields=%#v", event.System, event.Fields())
	}
	if event.Timestamp() != "2026-07-08T01:02:03.1234567Z" {
		t.Fatalf("timestamp = %s", event.Timestamp())
	}
	if event.RecordIDUint() != 42 {
		t.Fatalf("record id = %d, want 42", event.RecordIDUint())
	}
}

func TestParseEventsXMLParsesMultipleFragments(t *testing.T) {
	events, err := ParseEventsXML(`<Event><System><EventID>1</EventID></System></Event>
<Event><System><EventID>3</EventID></System></Event>`)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].System.EventID != "1" || events[1].System.EventID != "3" {
		t.Fatalf("events = %#v", events)
	}
}

func TestEventQueryUsesRecordIDCursorAndLookback(t *testing.T) {
	query := eventQuery(42, 10*time.Minute)
	for _, expected := range []string{"EventRecordID>42", "TimeCreated[timediff(@SystemTime)<=600000]"} {
		if !strings.Contains(query, expected) {
			t.Fatalf("query %q missing %q", query, expected)
		}
	}
	if !strings.Contains(query, " and ") {
		t.Fatalf("query should combine predicates with and: %q", query)
	}
}
