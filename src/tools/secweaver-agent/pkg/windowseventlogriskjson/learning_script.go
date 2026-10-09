package windowseventlogriskjson

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/windowseventlog"
)

const powerShellChannel = "Microsoft-Windows-PowerShell/Operational"
const maxScriptBytes = 512 << 10
const maxPendingBytes = 8 << 20
const maxScriptFragments = 64
const maxPendingScripts = 64

var scriptGUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type scriptGroup struct {
	total, bytes, cost int
	path               string
	parts              map[int]riskEvent
}

// observe holds only bounded fragments within one complete polling round. A
// completed block makes one decision; incomplete/conflicting blocks fail open.
// Caller updates stats with returned fragment writes, not logical script counts.
func (w *riskLearning) observe(source windowseventlog.Event, event riskEvent) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	before := w.emitted
	fields := event.Fields
	number, errNumber := strconv.Atoi(strings.TrimSpace(fields["MessageNumber"]))
	total, errTotal := strconv.Atoi(strings.TrimSpace(fields["MessageTotal"]))
	id := strings.TrimSpace(fields["ScriptBlockId"])
	at, errTime := time.Parse(time.RFC3339Nano, source.System.TimeCreated)
	now := time.Now()
	// Provider-supplied SID/record/time are mandatory. Any known user may learn;
	// historical lookback still cannot manufacture five new online observations.
	valid := event.EventID == "4104" && source.System.Provider == "Microsoft-Windows-PowerShell" &&
		source.System.Channel == powerShellChannel && source.System.UserID != "" &&
		source.System.Computer != "" && source.System.ProcessID != "" && source.System.ProcessID != "0" &&
		source.RecordIDUint() > 0 && scriptGUID.MatchString(id) && errNumber == nil && errTotal == nil &&
		number >= 1 && number <= total && total <= maxScriptFragments && errTime == nil &&
		!at.Before(w.started) && now.Sub(at) <= 10*time.Minute && !at.After(now.Add(time.Minute))
	if !valid {
		return w.emitUnqualified([]riskEvent{event}, "risk_context_incomplete_or_historical")
	}
	keyBytes, _ := json.Marshal([]string{source.System.Computer, source.System.UserID, source.System.ProcessID, id})
	key := string(keyBytes)
	group := w.pending[key]
	path := fields["Path"]
	if group != nil && (group.total != total || group.path != path || group.parts[number].EvidenceID != "") {
		// A duplicate/conflicting fragment cannot count as another safe sample.
		if _, err := w.flushPending(); err != nil {
			return w.emitted - before, err
		}
		w.engine.Fault("risk_fragment_conflict")
		_, err := w.emitUnqualified([]riskEvent{event}, "risk_fragment_conflict")
		return w.emitted - before, err
	}
	cost := riskRecordCost(event) + len(key)
	if len(event.Command) > maxScriptBytes || w.pendingBytes+cost > maxPendingBytes ||
		(group == nil && len(w.pending) >= maxPendingScripts) || (group != nil && group.bytes+len(event.Command) > maxScriptBytes) {
		if _, err := w.flushPending(); err != nil {
			return w.emitted - before, err
		}
		_, err := w.emitUnqualified([]riskEvent{event}, "risk_fragment_budget")
		return w.emitted - before, err
	}
	if group == nil {
		group = &scriptGroup{total: total, path: path, parts: make(map[int]riskEvent)}
		w.pending[key] = group
	}
	group.parts[number] = event
	group.bytes += len(event.Command)
	group.cost += cost
	w.pendingBytes += cost
	if len(group.parts) != total {
		return 0, nil
	}
	delete(w.pending, key)
	// O(1) removal avoids re-encoding every other retained script on completion.
	w.pendingBytes -= group.cost
	parts, script := group.assemble()
	reason := ""
	if script == "" {
		reason = "risk_script_empty"
	}
	// Classification must inspect the assembled script too: a dangerous token
	// may straddle fragment boundaries and be invisible in each native record.
	if containsSuspiciousCommand(script) {
		for i := range parts {
			parts[i].Severity, parts[i].RiskLevel = "high", "high"
		}
		reason = "protected_security_event"
	}
	for _, part := range parts {
		if severityRank[part.Severity] >= severityRank["high"] {
			reason = "protected_security_event"
		}
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(script)))
	// Script content is exact, including whitespace; only its digest enters the
	// reusable tuple. Known high-severity alerts continue to bypass learning.
	ctx := behaviorlearning.Context{Risk: &behaviorlearning.WindowsRiskContext{
		Provider: source.System.Provider, Channel: source.System.Channel, UserSID: source.System.UserID,
		Path: path, ScriptSHA256: digest}}
	// Only decision metadata enters the Engine; full scripts stay in this
	// bounded adapter and never occupy its exec ancestry replay cache.
	w.current = parts
	defer func() { w.current = nil }()
	raw, _ := json.Marshal(map[string]any{"source_stream": "windows_risk", "script_block_sha256": digest})
	err := w.engine.Process(behaviorlearning.Observation{Context: ctx, Complete: reason == "", Reason: reason,
		EventID: "win-script:" + parts[0].EvidenceID + ":" + parts[len(parts)-1].EvidenceID, Raw: raw, At: at})
	if err == nil && w.emitted == before {
		w.suppressed += len(parts)
	}
	return w.emitted - before, err
}

// assemble preserves exact XML-decoded text, including whitespace at fragment
// boundaries. Every slot is known present before this function is called.
func (g *scriptGroup) assemble() ([]riskEvent, string) {
	parts := make([]riskEvent, 0, g.total)
	var script strings.Builder
	script.Grow(g.bytes)
	for i := 1; i <= g.total; i++ {
		part := g.parts[i]
		parts = append(parts, part)
		script.WriteString(part.Command)
	}
	return parts, script.String()
}

// riskRecordCost reserves worst-case JSON escaping plus struct/map overhead.
// Counting field lengths avoids serializing/copying script bodies solely for
// budgeting on the steady-state suppression path. Overestimation fails open.
func riskRecordCost(event riskEvent) int {
	cost := 2048
	for _, value := range []string{event.EvidenceID, event.AssetType, event.Timestamp, event.Host, event.HostName,
		event.Channel, event.Provider, event.EventID, event.WindowsRecordID, event.EventType, event.Severity,
		event.RiskLevel, event.RuleID, event.RuleName, event.User, event.UserSID, event.SrcIP, event.LogonType,
		event.Process, event.Command, event.ScriptSHA256, event.Message, event.RawXML, event.ParserVersion} {
		cost += 6 * len(value)
	}
	for key, value := range event.Fields {
		cost += 128 + 6*(len(key)+len(value))
	}
	return cost
}

// emitUnqualified preserves native records without training a partial block.
// Called only with mu held; metadata never replaces original event identity.
func (w *riskLearning) emitUnqualified(parts []riskEvent, reason string) (int, error) {
	before := w.emitted
	w.current = parts
	defer func() { w.current = nil }()
	raw, _ := json.Marshal(map[string]string{"learning_decision": "emit", "decision_reason": reason, "source_stream": "windows_risk"})
	err := w.emitDecision(raw)
	return w.emitted - before, err
}

// flushPending is the cursor barrier: fragments are never kept across a durable
// polling-round checkpoint. Late fragments are emitted, not independently learned.
func (w *riskLearning) flushPending() (int, error) {
	before := w.emitted
	keys := make([]string, 0, len(w.pending))
	for key := range w.pending {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := w.pending[key]
		var parts []riskEvent
		for i := 1; i <= group.total; i++ {
			if part, ok := group.parts[i]; ok {
				parts = append(parts, part)
			}
		}
		if _, err := w.emitUnqualified(parts, "risk_script_incomplete"); err != nil {
			return w.emitted - before, err
		}
		delete(w.pending, key)
	}
	w.pendingBytes = 0
	return w.emitted - before, nil
}

// finishRound releases all incomplete evidence before renewing source health.
// Failed PowerShell polls permanently invalidate this risk generation.
func (w *riskLearning) finishRound(healthy bool) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if healthy {
		w.lastPoll = time.Now()
	} else {
		w.lastPoll = time.Time{}
	}
	return w.flushPending()
}
