package windowsevidence

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
)

const activityContextBytes = 4 << 20

// pruneContexts bounds idle command retention. One periodic sweep serves file
// and connection matching; the hot path only looks up a single host+GUID entry.
func (w *Learning) pruneContexts(now time.Time) {
	if now.Sub(w.lastPrune) < time.Minute {
		return
	}
	w.lastPrune = now
	for key, c := range w.fileContexts {
		if now.Sub(c.touched) > time.Hour {
			w.forgetFileInstance(key)
		}
	}
}

// activityObservation joins a complete outgoing Sysmon 3 to its exact Event 1
// image/command using host+GUID. Endpoint differences create different tuples;
// public destinations, management ports and interactive users have no special
// admission rule. Missing correlation always emits the native record.
func (w *Learning) activityObservation(e Event, now time.Time) behaviorlearning.Observation {
	o := behaviorlearning.Observation{EventID: e.EvidenceID, Reason: "operation_process_context_unavailable"}
	o.At, _ = time.Parse(time.RFC3339Nano, e.Time)
	id := processInstance(e.HostName, e.Fields["ProcessGuid"])
	c, ok := w.fileContexts[id]
	if ok && (now.Sub(c.touched) > time.Hour || o.At.Before(c.created) || c.exe != e.Exe) {
		w.forgetFileInstance(id)
		ok = false
	}
	port, err := strconv.Atoi(e.DstPort)
	if ok && fileSysmonSource(e) && e.WindowsEventID == "3" && e.EventType == "active_connect" &&
		strings.EqualFold(e.Fields["Initiated"], "true") && w.currentFileTime(o.At, now) && e.WindowsRecordID != "" && err == nil {
		e.ListenerProcess = new(string)
		e.PIDName, e.Command, e.CommandLine = windowsBase(e.Exe), c.command, c.command
		o.Context.Network = &behaviorlearning.NetworkFields{ExecFields: behaviorlearning.ExecFields{
			PIDName: e.PIDName, Exe: e.Exe, CommandLine: c.command,
		}, Protocol: e.Protocol, Address: e.DstIP, Port: port}
		o.Complete, o.Reason = true, ""
		c.touched = now
		w.fileContexts[id] = c
	}
	o.Raw, _ = json.Marshal(e)
	return o
}
