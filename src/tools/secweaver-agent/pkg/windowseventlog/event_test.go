package windowseventlog

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
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

// 4104 reconstruction must not remove whitespace at fragment edges. The native
// Security SID is the script identity; localized names are not a substitute.
func TestParseScriptPreservesWhitespaceAndNativeSID(t *testing.T) {
	events, err := ParseEventsXML(`<Event><System><EventID>4104</EventID><Security UserID="S-1-5-18"/></System><EventData><Data Name="ScriptBlockText"> leading &amp; trailing &#10;</Data><Data Name="MessageNumber"> 1 </Data></EventData></Event>`)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%v err=%v", events, err)
	}
	if events[0].System.UserID != "S-1-5-18" || events[0].Fields()["ScriptBlockText"] != " leading & trailing \n" || events[0].Field("MessageNumber") != "1" {
		t.Fatal("native SID or exact script text lost")
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

func TestDecodeWEVTUtilOutputParsesUTF16LEChineseEvents(t *testing.T) {
	text := `<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><EventRecordID>401</EventRecordID><Channel>Security</Channel><Computer>中文主机</Computer></System><EventData><Data Name="SubjectUserName">张三</Data><Data Name="CommandLine">cmd.exe /c echo 中文参数</Data></EventData></Event>
<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><EventRecordID>402</EventRecordID><Channel>Security</Channel><Computer>中文主机</Computer></System><EventData><Data Name="SubjectUserName">李四</Data><Data Name="CommandLine">powershell.exe -Command &quot;写入测试&quot;</Data></EventData></Event>`
	decoded, err := decodeWEVTUtilOutput(utf16Bytes(text, binary.LittleEndian, true))
	if err != nil {
		t.Fatal(err)
	}
	events, err := ParseEventsXML(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events len = %d, want 2", len(events))
	}
	if events[0].System.Computer != "中文主机" || events[0].Field("SubjectUserName") != "张三" || events[1].Field("CommandLine") != `powershell.exe -Command "写入测试"` {
		t.Fatalf("localized fields were corrupted: first=%+v second=%+v", events[0], events[1])
	}
}

func TestDecodeWEVTUtilOutputDetectsBOMLessUTF16BE(t *testing.T) {
	text := `<Event><System><EventID>4688</EventID><EventRecordID>403</EventRecordID></System></Event>`
	decoded, err := decodeWEVTUtilOutput(utf16Bytes(text, binary.BigEndian, false))
	if err != nil {
		t.Fatal(err)
	}
	if decoded != text {
		t.Fatalf("decoded text = %q, want %q", decoded, text)
	}
}

func TestParseEventsXMLRetainsValidFragmentsAroundMalformedRecord(t *testing.T) {
	text := `<Event><System><EventID>4688</EventID><EventRecordID>501</EventRecordID></System></Event>
<Event><System><EventID>4688</EventID><EventRecordID>502</EventRecordID></System><EventData></Event>
<Event><System><EventID>4688</EventID><EventRecordID>503</EventRecordID></System></Event>`
	events, err := ParseEventsXML(text)
	if err == nil {
		t.Fatal("expected partial batch parse error")
	}
	batchErr, ok := err.(*BatchParseError)
	if !ok || batchErr.FailedFragments != 1 || batchErr.TotalFragments != 3 {
		t.Fatalf("unexpected parse error: %#v", err)
	}
	if len(events) != 2 || events[0].RecordIDUint() != 501 || events[1].RecordIDUint() != 503 {
		t.Fatalf("valid fragments were not retained: %#v", events)
	}
}

func TestParseEventsXMLRejectsTruncatedPageWithoutValidEvents(t *testing.T) {
	events, err := ParseEventsXML(`<Event><System><EventID>4688</EventID>`)
	if err == nil || len(events) != 0 {
		t.Fatalf("events=%#v err=%v, want a hard parse error", events, err)
	}
	batchErr, ok := err.(*BatchParseError)
	if !ok || batchErr.FailedFragments != 1 || batchErr.TotalFragments != 1 {
		t.Fatalf("unexpected parse error: %#v", err)
	}
}

func TestDecodeWEVTUtilOutputRejectsUnknownInvalidEncoding(t *testing.T) {
	_, err := decodeWEVTUtilOutput([]byte{0x3c, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x3e, 0xff, 0x3c, 0x2f, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x3e})
	if err == nil {
		t.Fatal("expected invalid encoding error")
	}
}

func TestWEVTUtilQueryForcesUnicodeOutput(t *testing.T) {
	args := wevtutilQueryArgs("Security", 0, 10*time.Minute, 10, false)
	if !strings.Contains(strings.Join(args, " "), "/uni:true") {
		t.Fatalf("wevtutil query must force Unicode output: %v", args)
	}
}

func utf16Bytes(text string, order binary.ByteOrder, bom bool) []byte {
	units := utf16.Encode([]rune(text))
	prefix := 0
	if bom {
		prefix = 2
	}
	out := make([]byte, prefix+len(units)*2)
	if bom {
		if order == binary.LittleEndian {
			out[0], out[1] = 0xff, 0xfe
		} else {
			out[0], out[1] = 0xfe, 0xff
		}
	}
	for i, unit := range units {
		order.PutUint16(out[prefix+i*2:], unit)
	}
	return out
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
