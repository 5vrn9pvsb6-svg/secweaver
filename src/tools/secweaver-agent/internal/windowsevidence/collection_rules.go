package windowsevidence

import (
	"secweaver-agent/pkg/eventwhitelist"
	"secweaver-agent/pkg/eventwhitelist/core"
)

// customDecision runs after GUID cache advancement. Display fallbacks remain
// unknown, so missing commands cannot match negated predicates accidentally.
func customDecision(e Event) eventwhitelist.Decision {
	fields := eventwhitelist.SemanticFields(map[string]any{"/pid_name": windowsBase(e.Exe), "/exe": e.Exe, "/command_line": e.CommandLine, "/file_paths": e.FilePaths, "/user": e.User, "/windows_event_id": e.WindowsEventID, "/dst_ip": e.DstIP, "/dst_port": e.DstPort, "/provider": e.Provider, "/channel": e.Channel})
	fields["/listener_process"] = ""
	incomplete := map[string]bool{"/command_line": e.CommandLine == "" || e.CommandLine == e.Exe && e.Fields["CommandLine"] == ""}
	d := eventwhitelist.Decide(core.Event{EventType: e.EventType, AssetType: e.AssetType, Fields: fields, Incomplete: incomplete})
	if d.Action == "alert" {
		eventwhitelist.Alert(d, e.EvidenceID, e.Timestamp, fields)
	}
	return d
}
