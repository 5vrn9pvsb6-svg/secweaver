package windowseventlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

type Event struct {
	System    SystemData
	EventData []DataField
	RawXML    string
}

type SystemData struct {
	Provider      string
	EventID       string
	Level         string
	Task          string
	Opcode        string
	Keywords      string
	TimeCreated   string
	EventRecordID string
	Channel       string
	Computer      string
	ProcessID     string
	ThreadID      string
	UserID        string
}

type DataField struct {
	Name  string
	Value string
}

type eventXML struct {
	XMLName   xml.Name     `xml:"Event"`
	System    systemXML    `xml:"System"`
	EventData eventDataXML `xml:"EventData"`
	UserData  userDataXML  `xml:"UserData"`
}

type systemXML struct {
	Provider struct {
		Name string `xml:"Name,attr"`
	} `xml:"Provider"`
	EventID struct {
		Value string `xml:",chardata"`
	} `xml:"EventID"`
	Level       string `xml:"Level"`
	Task        string `xml:"Task"`
	Opcode      string `xml:"Opcode"`
	Keywords    string `xml:"Keywords"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	EventRecordID string `xml:"EventRecordID"`
	Channel       string `xml:"Channel"`
	Computer      string `xml:"Computer"`
	Execution     struct {
		ProcessID string `xml:"ProcessID,attr"`
		ThreadID  string `xml:"ThreadID,attr"`
	} `xml:"Execution"`
	Security struct {
		UserID string `xml:"UserID,attr"`
	} `xml:"Security"`
}

type eventDataXML struct {
	Data []dataXML `xml:"Data"`
}

type userDataXML struct {
	XMLName xml.Name
	Inner   string `xml:",innerxml"`
}

type dataXML struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// BatchParseError reports malformed event fragments without hiding valid records
// from the same wevtutil page. Callers may process the returned records; a page
// with no valid records remains a hard error so cursors cannot advance silently.
type BatchParseError struct {
	FailedFragments int
	TotalFragments  int
	FirstFragment   int
	Cause           error
}

func (e *BatchParseError) Error() string {
	return fmt.Sprintf(
		"parse event xml fragment %d: %v (failed=%d total=%d)",
		e.FirstFragment, e.Cause, e.FailedFragments, e.TotalFragments,
	)
}

func (e *BatchParseError) Unwrap() error {
	return e.Cause
}

const defaultQueryTimeout = 20 * time.Second

func QueryRecent(ctx context.Context, channel string, lookback time.Duration, maxEvents int) ([]Event, error) {
	return QueryAfter(ctx, channel, 0, lookback, maxEvents)
}

func QueryAfter(ctx context.Context, channel string, afterRecordID uint64, lookback time.Duration, maxEvents int) ([]Event, error) {
	return queryAfter(ctx, channel, afterRecordID, lookback, maxEvents, true)
}

func QueryAfterAscending(ctx context.Context, channel string, afterRecordID uint64, lookback time.Duration, maxEvents int) ([]Event, error) {
	return queryAfter(ctx, channel, afterRecordID, lookback, maxEvents, false)
}

func queryAfter(ctx context.Context, channel string, afterRecordID uint64, lookback time.Duration, maxEvents int, newestFirst bool) ([]Event, error) {
	if strings.TrimSpace(channel) == "" {
		return nil, nil
	}
	if maxEvents <= 0 {
		maxEvents = 200
	}
	args := wevtutilQueryArgs(channel, afterRecordID, lookback, maxEvents, newestFirst)
	queryCtx, cancel := context.WithTimeout(ctx, defaultQueryTimeout)
	defer cancel()
	out, err := exec.CommandContext(queryCtx, "wevtutil", args...).CombinedOutput()
	decoded, decodeErr := decodeWEVTUtilOutput(out)
	if err != nil {
		msg := strings.TrimSpace(decoded)
		if msg == "" {
			msg = err.Error()
			if decodeErr != nil {
				msg += "; output decode failed: " + decodeErr.Error()
			}
		}
		return nil, fmt.Errorf("wevtutil qe %s failed: %s", channel, msg)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("decode wevtutil qe %s output: %w", channel, decodeErr)
	}
	// Preserve valid records alongside BatchParseError. The owning collector
	// records the degraded poll before writing those records and advancing their
	// cursors, so service health cannot silently hide a skipped provider record.
	return ParseEventsXML(decoded)
}

// decodeWEVTUtilOutput normalizes the two encodings emitted by wevtutil. The
// reader requests /uni:true, which is UTF-16 on Windows, but accepts UTF-8 for
// compatibility with test fixtures and older wrappers. Invalid or ambiguous
// bytes are rejected rather than copied into security evidence as mojibake.
func decodeWEVTUtilOutput(raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	if bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		raw = raw[3:]
		if !utf8.Valid(raw) {
			return "", fmt.Errorf("UTF-8 BOM followed by invalid UTF-8")
		}
		return string(raw), nil
	}
	if bytes.HasPrefix(raw, []byte{0xff, 0xfe}) {
		return decodeUTF16(raw[2:], binary.LittleEndian)
	}
	if bytes.HasPrefix(raw, []byte{0xfe, 0xff}) {
		return decodeUTF16(raw[2:], binary.BigEndian)
	}
	// BOM-less UTF-16 XML can also be byte-valid UTF-8 when its current page is
	// ASCII-only, so the alternating-NUL signature must be checked first.
	if order, ok := detectUTF16ByteOrder(raw); ok {
		return decodeUTF16(raw, order)
	}
	if utf8.Valid(raw) {
		return string(raw), nil
	}
	return "", fmt.Errorf("output is neither valid UTF-8 nor recognizable UTF-16")
}

// detectUTF16ByteOrder handles Unicode output from Windows builds that omit a
// BOM on redirected stdout. XML markup is ASCII-heavy, so its alternating NUL
// distribution is a bounded and deterministic byte-order signal.
func detectUTF16ByteOrder(raw []byte) (binary.ByteOrder, bool) {
	if len(raw) < 4 || len(raw)%2 != 0 {
		return nil, false
	}
	sample := raw
	if len(sample) > 512 {
		sample = sample[:512]
	}
	pairs := len(sample) / 2
	evenNUL, oddNUL := 0, 0
	for i := 0; i+1 < len(sample); i += 2 {
		if sample[i] == 0 {
			evenNUL++
		}
		if sample[i+1] == 0 {
			oddNUL++
		}
	}
	minimum := pairs / 4
	if minimum < 1 {
		minimum = 1
	}
	if oddNUL >= minimum && oddNUL > evenNUL*2 {
		return binary.LittleEndian, true
	}
	if evenNUL >= minimum && evenNUL > oddNUL*2 {
		return binary.BigEndian, true
	}
	return nil, false
}

// decodeUTF16 rejects truncated and unpaired surrogate input before converting
// it. Silent replacement would corrupt command lines and weaken forensic value.
func decodeUTF16(raw []byte, order binary.ByteOrder) (string, error) {
	if len(raw)%2 != 0 {
		return "", fmt.Errorf("UTF-16 byte length %d is not even", len(raw))
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = order.Uint16(raw[i*2:])
	}
	for i := 0; i < len(units); i++ {
		u := units[i]
		switch {
		case 0xd800 <= u && u <= 0xdbff:
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", fmt.Errorf("UTF-16 contains an unpaired high surrogate at unit %d", i)
			}
			i++
		case 0xdc00 <= u && u <= 0xdfff:
			return "", fmt.Errorf("UTF-16 contains an unpaired low surrogate at unit %d", i)
		}
	}
	return string(utf16.Decode(units)), nil
}

func wevtutilQueryArgs(channel string, afterRecordID uint64, lookback time.Duration, maxEvents int, newestFirst bool) []string {
	direction := "/rd:false"
	if newestFirst {
		direction = "/rd:true"
	}
	args := []string{"qe", channel, "/f:xml", direction, fmt.Sprintf("/c:%d", maxEvents), "/uni:true"}
	if query := eventQuery(afterRecordID, lookback); query != "" {
		args = append(args, "/q:"+query)
	}
	return args
}

func eventQuery(afterRecordID uint64, lookback time.Duration) string {
	var conditions []string
	if afterRecordID > 0 {
		conditions = append(conditions, "EventRecordID>"+strconv.FormatUint(afterRecordID, 10))
	}
	if lookback > 0 {
		millis := lookback.Milliseconds()
		if millis <= 0 {
			millis = int64(time.Second / time.Millisecond)
		}
		conditions = append(conditions, "TimeCreated[timediff(@SystemTime)<="+strconv.FormatInt(millis, 10)+"]")
	}
	if len(conditions) == 0 {
		return ""
	}
	return "*[System[" + strings.Join(conditions, " and ") + "]]"
}

// ParseEventsXML parses every complete Event fragment independently. It
// returns valid records together with BatchParseError when only part of a page
// is malformed, preventing one localized provider record from erasing the page.
func ParseEventsXML(text string) ([]Event, error) {
	fragments, incompleteTail := splitEventFragments(text)
	totalFragments := len(fragments)
	if incompleteTail {
		totalFragments++
	}
	events := make([]Event, 0, len(fragments))
	var batchErr *BatchParseError
	for i, fragment := range fragments {
		var parsed eventXML
		if err := xml.Unmarshal([]byte(fragment), &parsed); err != nil {
			if batchErr == nil {
				batchErr = &BatchParseError{
					TotalFragments: totalFragments,
					FirstFragment:  i + 1,
					Cause:          err,
				}
			}
			batchErr.FailedFragments++
			continue
		}
		event := Event{
			System: SystemData{
				Provider:      strings.TrimSpace(parsed.System.Provider.Name),
				EventID:       strings.TrimSpace(parsed.System.EventID.Value),
				Level:         strings.TrimSpace(parsed.System.Level),
				Task:          strings.TrimSpace(parsed.System.Task),
				Opcode:        strings.TrimSpace(parsed.System.Opcode),
				Keywords:      strings.TrimSpace(parsed.System.Keywords),
				TimeCreated:   strings.TrimSpace(parsed.System.TimeCreated.SystemTime),
				EventRecordID: strings.TrimSpace(parsed.System.EventRecordID),
				Channel:       strings.TrimSpace(parsed.System.Channel),
				Computer:      strings.TrimSpace(parsed.System.Computer),
				ProcessID:     strings.TrimSpace(parsed.System.Execution.ProcessID),
				ThreadID:      strings.TrimSpace(parsed.System.Execution.ThreadID),
				UserID:        strings.TrimSpace(parsed.System.Security.UserID),
			},
			RawXML: strings.TrimSpace(fragment),
		}
		for idx, field := range parsed.EventData.Data {
			name := strings.TrimSpace(field.Name)
			if name == "" {
				name = fmt.Sprintf("Data%d", idx+1)
			}
			value := strings.TrimSpace(field.Value)
			// Fragment boundaries can split whitespace inside a token. Keep exact
			// script text so reassembly/hash cannot conflate different scripts.
			if name == "ScriptBlockText" {
				value = field.Value
			}
			event.EventData = append(event.EventData, DataField{
				Name:  name,
				Value: value,
			})
		}
		if len(event.EventData) == 0 && strings.TrimSpace(parsed.UserData.Inner) != "" {
			event.EventData = append(event.EventData, DataField{Name: "UserData", Value: strings.TrimSpace(parsed.UserData.Inner)})
		}
		events = append(events, event)
	}
	if incompleteTail {
		if batchErr == nil {
			batchErr = &BatchParseError{
				TotalFragments: totalFragments,
				FirstFragment:  len(fragments) + 1,
				Cause:          fmt.Errorf("incomplete Event fragment"),
			}
		}
		batchErr.FailedFragments++
	}
	if batchErr != nil {
		return events, batchErr
	}
	return events, nil
}

// splitEventFragments reports a non-empty truncated tail separately. The caller
// must not interpret incomplete command output as a healthy empty event page.
func splitEventFragments(text string) ([]string, bool) {
	var fragments []string
	remaining := text
	for {
		start := strings.Index(remaining, "<Event")
		if start < 0 {
			return fragments, len(fragments) == 0 && strings.TrimSpace(remaining) != ""
		}
		remaining = remaining[start:]
		end := strings.Index(remaining, "</Event>")
		if end < 0 {
			return fragments, true
		}
		end += len("</Event>")
		fragments = append(fragments, remaining[:end])
		remaining = remaining[end:]
	}
}

func (e Event) EventIDInt() int {
	id, _ := strconv.Atoi(strings.TrimSpace(e.System.EventID))
	return id
}

func (e Event) RecordIDUint() uint64 {
	id, _ := strconv.ParseUint(strings.TrimSpace(e.System.EventRecordID), 10, 64)
	return id
}

func (e Event) Timestamp() string {
	ts := strings.TrimSpace(e.System.TimeCreated)
	if ts == "" {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return parsed.UTC().Format(time.RFC3339Nano)
	}
	return ts
}

func (e Event) Fields() map[string]string {
	fields := make(map[string]string, len(e.EventData))
	for _, item := range e.EventData {
		if item.Name == "" {
			continue
		}
		fields[item.Name] = item.Value
	}
	return fields
}

func (e Event) Field(names ...string) string {
	fields := e.Fields()
	for _, name := range names {
		if value := strings.TrimSpace(fields[name]); value != "" {
			return value
		}
	}
	return ""
}

func (e Event) RecordKey() string {
	parts := []string{e.System.Channel, e.System.EventRecordID, e.System.EventID, e.System.TimeCreated, e.System.Computer}
	return strings.Join(parts, "|")
}

func EvidenceID(prefix string, e Event) string {
	h := sha256.Sum256([]byte(prefix + "|" + e.RecordKey() + "|" + e.RawXML))
	return prefix + "-" + hex.EncodeToString(h[:8])
}

func SplitCSV(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
