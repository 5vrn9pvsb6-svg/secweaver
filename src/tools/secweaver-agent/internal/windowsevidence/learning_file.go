package windowsevidence

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"secweaver-agent/pkg/behaviorlearning"
)

type fileContext struct {
	exe, command     string
	created, touched time.Time
	bytes            int
}

// rememberFileExecution owns the shared file/network command cache under
// Learning.mu. Neither adapter ever uses a display fallback or live PID lookup.
func (w *Learning) rememberFileExecution(e Event, now time.Time) {
	if (w.fileEngine == nil && w.networkEngine == nil) || e.WindowsEventID != "1" || !fileSysmonSource(e) {
		return
	}
	id := processInstance(e.HostName, e.Fields["ProcessGuid"])
	w.forgetFileInstance(id)
	at, err := time.Parse(time.RFC3339Nano, e.Time)
	exe, command := e.Fields["Image"], e.Fields["CommandLine"]
	if id == "" || err != nil || !w.currentFileTime(at, now) || e.WindowsRecordID == "" ||
		exe == "" || exe == "-" || command == "" || command == "-" ||
		!utf8.ValidString(exe) || !utf8.ValidString(command) || strings.ContainsRune(command, 0) || len(id)+len(exe)+len(command) > 32768 {
		return
	}
	cost := len(id) + len(exe) + len(command) + 256
	if len(w.fileContexts) >= 1024 || w.fileContextBytes+cost > activityContextBytes {
		return
	}
	w.fileContexts[id] = fileContext{exe: exe, command: command, created: at, touched: now, bytes: cost}
	w.fileContextBytes += cost
}

// fileObservation keeps the public path alias and fills the exact fields from
// host+GUID evidence only. Empty listener_process is an explicit Windows policy;
// no current-PID lookup or case-insensitive executable guess is permitted.
func (w *Learning) fileObservation(e Event, now time.Time) behaviorlearning.Observation {
	o := behaviorlearning.Observation{EventID: e.EvidenceID, Reason: "file_process_context_unavailable"}
	o.At, _ = time.Parse(time.RFC3339Nano, e.Time)
	id := processInstance(e.HostName, e.Fields["ProcessGuid"])
	c, ok := w.fileContexts[id]
	if ok && (now.Sub(c.touched) > time.Hour || o.At.Before(c.created) || c.exe != e.Exe) {
		w.forgetFileInstance(id)
		ok = false
	}
	if ok && fileSysmonSource(e) && (e.WindowsEventID == "11" || e.WindowsEventID == "23") &&
		w.currentFileTime(o.At, now) && e.WindowsRecordID != "" && e.Path != "" && e.Path != "-" {
		e.Command, e.CommandLine = c.command, c.command
		e.ListenerProcess = new(string)
		e.PIDName, e.FilePaths = windowsBase(e.Exe), []string{e.Path}
		o.Context.File = &behaviorlearning.FileFields{ExecFields: behaviorlearning.ExecFields{
			PIDName: e.PIDName, Exe: e.Exe, CommandLine: e.CommandLine,
		}, FilePaths: e.FilePaths}
		o.Complete, o.Reason = true, ""
		c.touched = now
		w.fileContexts[id] = c
	}
	o.Raw, _ = json.Marshal(e)
	return o
}

func fileSysmonSource(e Event) bool {
	return strings.EqualFold(e.Provider, "Microsoft-Windows-Sysmon") &&
		strings.EqualFold(e.Channel, "Microsoft-Windows-Sysmon/Operational")
}

// Historical/lookback batches cannot accelerate a new online learning period.
func (w *Learning) currentFileTime(at, now time.Time) bool {
	return !at.Before(w.started) && !at.After(now.Add(time.Minute)) && now.Sub(at) <= 10*time.Minute
}

func (w *Learning) forgetFileInstance(id string) {
	if c, ok := w.fileContexts[id]; ok {
		w.fileContextBytes -= c.bytes
		delete(w.fileContexts, id)
	}
}

// clearFileContexts is called under Learning.mu on continuity faults; keeping
// command text after a source gap would associate files with stale evidence.
func (w *Learning) clearFileContexts() {
	clear(w.fileContexts)
	w.fileContextBytes = 0
}
