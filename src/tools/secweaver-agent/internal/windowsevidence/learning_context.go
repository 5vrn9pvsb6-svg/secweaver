package windowsevidence

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"secweaver-agent/pkg/behaviorlearning"
)

// learningObservation uses native command text from Sysmon 1 or Security 4688.
// Hash, user, parent, path and service-token heuristics no longer gate learning.
// A display fallback to the executable is never evidence of a full command.
func learningObservation(e Event, started, now time.Time) behaviorlearning.Observation {
	o := behaviorlearning.Observation{EventID: e.EvidenceID, Reason: "windows_context_incomplete"}
	o.At, _ = time.Parse(time.RFC3339Nano, e.Time)
	sysmon := e.WindowsEventID == "1" && fileSysmonSource(e)
	security := e.WindowsEventID == "4688" && e.Provider == "Microsoft-Windows-Security-Auditing" && e.Channel == "Security"
	command := e.Fields["CommandLine"]
	if sysmon {
		o.Instance = processInstance(e.HostName, e.Fields["ProcessGuid"])
	}
	if (sysmon || security) && !o.At.Before(started) && !o.At.After(now.Add(time.Minute)) && now.Sub(o.At) <= 10*time.Minute &&
		e.HostName != "" && e.WindowsRecordID != "" && e.Exe != "" && e.Exe != "-" &&
		command != "" && command != "-" && utf8.ValidString(command) && !strings.ContainsRune(command, 0) {
		e.ListenerProcess = new(string)
		e.PIDName, e.Command, e.CommandLine = windowsBase(e.Exe), command, command
		o.Context.Exec = &behaviorlearning.ExecFields{PIDName: e.PIDName, Exe: e.Exe, CommandLine: command}
		o.Complete, o.Reason = true, ""
	}
	o.Raw, _ = json.Marshal(e)
	return o
}

// processInstance uses GUIDs, never bare PIDs, across host reboots and PID reuse.
// It is only a correlation key, never part of the reusable behavior fingerprint.
func processInstance(host, guid string) string {
	v := strings.ReplaceAll(strings.Trim(guid, "{}"), "-", "")
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != 16 || strings.Trim(v, "0") == "" || host == "" {
		return ""
	}
	return strings.ToLower(host + ":" + guid)
}
