// Package windowsevidence owns conversion of a Windows Event Log record into
// SecWeaver host execution, connection, and file-operation evidence.
package windowsevidence

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"secweaver-agent/pkg/windowseventlog"
)

const parserVersion = "0.3.0"

// Event is the stable JSON contract emitted for Windows host evidence.
type Event struct {
	EvidenceID      string            `json:"evidence_id"`
	AssetType       string            `json:"asset_type"`
	Time            string            `json:"time"`
	Timestamp       string            `json:"timestamp"`
	Host            string            `json:"host"`
	HostName        string            `json:"host_name"`
	EventType       string            `json:"event_type"`
	Channel         string            `json:"channel"`
	Provider        string            `json:"provider"`
	WindowsEventID  string            `json:"windows_event_id"`
	WindowsRecordID string            `json:"windows_record_id,omitempty"`
	PID             string            `json:"pid,omitempty"`
	PPID            string            `json:"ppid,omitempty"`
	User            string            `json:"user,omitempty"`
	Process         string            `json:"process,omitempty"`
	Comm            string            `json:"comm,omitempty"`
	Exe             string            `json:"exe,omitempty"`
	Command         string            `json:"command,omitempty"`
	CommandLine     string            `json:"command_line,omitempty"`
	ParentProcess   string            `json:"parent_process,omitempty"`
	SrcIP           string            `json:"src_ip,omitempty"`
	SrcPort         string            `json:"src_port,omitempty"`
	DstIP           string            `json:"dst_ip,omitempty"`
	DstPort         string            `json:"dst_port,omitempty"`
	Protocol        string            `json:"protocol,omitempty"`
	Path            string            `json:"path,omitempty"`
	Action          string            `json:"action,omitempty"`
	Message         string            `json:"message,omitempty"`
	RawXML          string            `json:"raw_xml,omitempty"`
	Fields          map[string]string `json:"fields,omitempty"`
	ParserVersion   string            `json:"parser_version"`
}

// Classify is shared by the unified Windows reader and the compatibility
// standalone reader. Agent and direct-child events are discarded before any
// evidence is returned, preventing self-observation loops.
func Classify(event windowseventlog.Event, includeRaw bool) []Event {
	base := Event{
		EvidenceID: windowseventlog.EvidenceID("win-evidence", event), Time: event.Timestamp(), Timestamp: event.Timestamp(),
		Host: event.System.Computer, HostName: event.System.Computer, Channel: event.System.Channel,
		Provider: event.System.Provider, WindowsEventID: event.System.EventID, WindowsRecordID: event.System.EventRecordID,
		Fields: event.Fields(), ParserVersion: parserVersion,
	}
	if IsAgentEvent(event) {
		return nil
	}
	if includeRaw {
		base.RawXML = event.RawXML
	}
	switch event.EventIDInt() {
	case 4688:
		item := base
		item.AssetType, item.EventType = "host_exec", "exec"
		item.PID = normalizeHexPID(event.Field("NewProcessId", "ProcessId"))
		item.PPID = normalizeHexPID(event.Field("CreatorProcessId", "ParentProcessId"))
		item.User = firstNonEmpty(event.Field("SubjectUserName"), event.Field("TargetUserName"))
		item.Exe = firstNonEmpty(event.Field("NewProcessName"), event.Field("ProcessName"))
		item.Process, item.Comm = windowsBase(item.Exe), windowsBase(item.Exe)
		item.Command = firstNonEmpty(event.Field("CommandLine"), item.Exe)
		item.CommandLine, item.ParentProcess, item.Message = item.Command, event.Field("CreatorProcessName", "ParentProcessName"), "Windows process creation"
		return []Event{item}
	case 1:
		if !isSysmon(event) {
			return nil
		}
		item := base
		item.AssetType, item.EventType, item.PID, item.PPID = "host_exec", "exec", event.Field("ProcessId"), event.Field("ParentProcessId")
		item.User, item.Exe = event.Field("User"), event.Field("Image")
		item.Process, item.Comm = windowsBase(item.Exe), windowsBase(item.Exe)
		item.Command = firstNonEmpty(event.Field("CommandLine"), item.Exe)
		item.CommandLine, item.ParentProcess, item.Message = item.Command, event.Field("ParentImage"), "Sysmon process creation"
		return []Event{item}
	case 3:
		if !isSysmon(event) {
			return nil
		}
		item := base
		item.AssetType, item.EventType, item.PID, item.User, item.Exe = "host_connect", "active_connect", event.Field("ProcessId"), event.Field("User"), event.Field("Image")
		item.Process, item.Comm = windowsBase(item.Exe), windowsBase(item.Exe)
		item.SrcIP, item.SrcPort = normalizeIP(event.Field("SourceIp")), event.Field("SourcePort")
		item.DstIP, item.DstPort, item.Protocol, item.Message = normalizeIP(event.Field("DestinationIp")), event.Field("DestinationPort"), event.Field("Protocol"), "Sysmon network connection"
		return []Event{item}
	case 11, 23:
		if !isSysmon(event) {
			return nil
		}
		item := base
		item.AssetType, item.EventType, item.PID, item.User, item.Exe = "host_file_op", "file_op", event.Field("ProcessId"), event.Field("User"), event.Field("Image")
		item.Process, item.Comm, item.Path = windowsBase(item.Exe), windowsBase(item.Exe), event.Field("TargetFilename")
		if event.EventIDInt() == 23 {
			item.Action, item.Message = "delete", "Sysmon file delete"
		} else {
			item.Action, item.Message = "create", "Sysmon file create"
		}
		return []Event{item}
	}
	return nil
}

// Write classifies and serializes one source record, returning the number of
// evidence records committed to the encoder.
func Write(enc *json.Encoder, event windowseventlog.Event, includeRaw bool) (int, error) {
	written := 0
	for _, item := range Classify(event, includeRaw) {
		if err := enc.Encode(item); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// IsAgentEvent identifies the Agent executable and its direct child process.
func IsAgentEvent(event windowseventlog.Event) bool {
	return isAgentImage(event.Field("NewProcessName", "ProcessName", "Image")) || isAgentImage(event.Field("CreatorProcessName", "ParentProcessName", "ParentImage"))
}

func isAgentImage(path string) bool {
	name := strings.ToLower(windowsBase(path))
	return name == "secweaver-agent.exe" || name == "secweaver-agent"
}

func isSysmon(event windowseventlog.Event) bool {
	return strings.Contains(strings.ToLower(event.System.Provider), "sysmon")
}

func normalizeHexPID(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		return strings.ToLower(value)
	}
	return value
}

func windowsBase(path string) string {
	return filepath.Base(strings.ReplaceAll(strings.TrimSpace(path), `\`, "/"))
}

func normalizeIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "-" || value == "::1" || value == "127.0.0.1" {
		return ""
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" && value != "-" {
			return value
		}
	}
	return ""
}
