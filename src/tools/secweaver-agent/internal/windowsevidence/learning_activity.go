package windowsevidence

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
)

const activityContextBytes = 4 << 20

type activityContext struct {
	context          behaviorlearning.Context
	created, touched time.Time
	bytes            int
}

// rememberExecution is called under Learning.mu. Only a fully verified Sysmon
// create can establish GUID ownership; learning network/file events never fills
// missing hashes or credentials from a current PID or a similarly named image.
func (w *Learning) rememberExecution(o behaviorlearning.Observation, now time.Time) {
	if o.Instance == "" {
		return
	}
	w.forgetInstance(o.Instance)
	if !o.Complete || o.Context.Windows == nil || len(o.Raw) > 65536 {
		return
	}
	b, _ := json.Marshal(o.Context)
	if len(b) > 32768 {
		return
	}
	cost := len(b) + len(o.Instance) + 512
	if len(w.contexts) >= 1024 || w.contextBytes+cost > activityContextBytes {
		return
	}
	w.contexts[o.Instance] = activityContext{context: o.Context, created: o.At, touched: now, bytes: cost}
	w.contextBytes += cost
}

// forgetInstance never leaves a stale GUID eligible after observed termination,
// a conflicting create or a source-continuity fault. Caller owns Learning.mu.
func (w *Learning) forgetInstance(instance string) {
	if c, ok := w.contexts[instance]; ok {
		w.contextBytes -= c.bytes
		delete(w.contexts, instance)
	}
}

// pruneContexts runs once per minute, not once per event. An hour with no
// qualifying activity drops identity context; cache pressure always emits raw.
func (w *Learning) pruneContexts(now time.Time) {
	if now.Sub(w.lastPrune) < time.Minute {
		return
	}
	w.lastPrune = now
	for key, c := range w.contexts {
		if now.Sub(c.touched) > time.Hour {
			w.forgetInstance(key)
		}
	}
}

// activityObservation correlates Sysmon 3/11 to a previously observed eligible
// Event 1 by host+GUID. Cached identity is immutable for that process lifetime;
// image or user disagreement invalidates it instead of guessing an attribution.
func (w *Learning) activityObservation(e Event, now time.Time) behaviorlearning.Observation {
	o := learningObservation(e, w.started, now)
	o.Complete, o.Reason = false, "operation_process_context_unavailable"
	o.ParentInstance = o.Instance // Replay the actual executor's exec, not its parent.
	if !strings.EqualFold(e.Provider, "Microsoft-Windows-Sysmon") || !strings.EqualFold(e.Channel, "Microsoft-Windows-Sysmon/Operational") ||
		o.At.Before(w.started) || o.At.After(now.Add(time.Minute)) || now.Sub(o.At) > 10*time.Minute {
		return o
	}
	c, ok := w.contexts[o.Instance]
	if !ok {
		return o
	}
	if now.Sub(c.touched) > time.Hour || o.At.Before(c.created) || !strings.EqualFold(e.Exe, c.context.Executable) ||
		!strings.EqualFold(e.User, c.context.Windows.User) {
		w.forgetInstance(o.Instance)
		return o
	}
	op := &behaviorlearning.Operation{EventType: e.EventType}
	switch e.EventType {
	case "active_connect":
		if e.WindowsEventID != "3" || !strings.EqualFold(e.Fields["Initiated"], "true") {
			o.Reason = "inbound_or_incomplete_connection"
			return o
		}
		address, err := netip.ParseAddr(e.DstIP)
		if err != nil {
			return o
		}
		source, err := netip.ParseAddr(e.SrcIP)
		if err != nil {
			return o
		}
		port, err := strconv.Atoi(e.DstPort)
		if err != nil {
			return o
		}
		op.Action, op.Protocol, op.Address, op.Port, op.SourceAddress = "connect", strings.ToLower(e.Protocol), address.Unmap().String(), port, source.Unmap().String()
	case "file_op":
		// Sysmon FileCreate also covers overwrites. Keep the existing public
		// "create" action contract; eligibility is limited to ordinary .log
		// targets and must not imply content-integrity or create-only evidence.
		if e.WindowsEventID != "11" || e.Action != "create" {
			o.Reason = "destructive_file_action"
			return o
		}
		if !absoluteWindowsPath(e.Path) {
			return o
		}
		op.Action, op.Path = "create", e.Path
	default:
		o.Reason = "protected_event_type"
		return o
	}
	o.Context = c.context
	o.Context.Operation = op
	o.Complete, o.Reason = true, ""
	c.touched = now
	w.contexts[o.Instance] = c
	return o
}
