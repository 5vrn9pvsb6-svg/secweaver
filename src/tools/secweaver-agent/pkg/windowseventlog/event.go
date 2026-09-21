package windowseventlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
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
	direction := "/rd:false"
	if newestFirst {
		direction = "/rd:true"
	}
	args := []string{"qe", channel, "/f:xml", direction, fmt.Sprintf("/c:%d", maxEvents)}
	if query := eventQuery(afterRecordID, lookback); query != "" {
		args = append(args, "/q:"+query)
	}
	queryCtx, cancel := context.WithTimeout(ctx, defaultQueryTimeout)
	defer cancel()
	out, err := exec.CommandContext(queryCtx, "wevtutil", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("wevtutil qe %s failed: %s", channel, msg)
	}
	return ParseEventsXML(string(out))
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

func ParseEventsXML(text string) ([]Event, error) {
	fragments := splitEventFragments(text)
	events := make([]Event, 0, len(fragments))
	for i, fragment := range fragments {
		var parsed eventXML
		if err := xml.Unmarshal([]byte(fragment), &parsed); err != nil {
			return nil, fmt.Errorf("parse event xml fragment %d: %w", i+1, err)
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
			},
			RawXML: strings.TrimSpace(fragment),
		}
		for idx, field := range parsed.EventData.Data {
			name := strings.TrimSpace(field.Name)
			if name == "" {
				name = fmt.Sprintf("Data%d", idx+1)
			}
			event.EventData = append(event.EventData, DataField{
				Name:  name,
				Value: strings.TrimSpace(field.Value),
			})
		}
		if len(event.EventData) == 0 && strings.TrimSpace(parsed.UserData.Inner) != "" {
			event.EventData = append(event.EventData, DataField{Name: "UserData", Value: strings.TrimSpace(parsed.UserData.Inner)})
		}
		events = append(events, event)
	}
	return events, nil
}

func splitEventFragments(text string) []string {
	var fragments []string
	remaining := text
	for {
		start := strings.Index(remaining, "<Event")
		if start < 0 {
			break
		}
		remaining = remaining[start:]
		end := strings.Index(remaining, "</Event>")
		if end < 0 {
			break
		}
		end += len("</Event>")
		fragments = append(fragments, remaining[:end])
		remaining = remaining[end:]
	}
	return fragments
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
