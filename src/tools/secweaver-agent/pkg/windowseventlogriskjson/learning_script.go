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

// Native generators use script-scoped camel-case names; PowerShell identifiers
// are case-insensitive. Accept literal declarations only, never computed values.
var cdxmlClass = regexp.MustCompile(`(?i)^[\t ]*(?:\[(?:system\.)?string\][\t ]*)?\$(?:(?:script:)?__cmdletization_classname|script:classname)[\t ]*=[\t ]*['"]([^'"\r\n]+)['"][\t ]*;?[\t \r]*$`)

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
	// Provider-supplied SID/record/time are mandatory. Historical lookback data
	// remains evidence but cannot train an installation's fresh baseline.
	valid := event.EventID == "4104" && source.System.Provider == "Microsoft-Windows-PowerShell" &&
		source.System.Channel == powerShellChannel && source.System.UserID == "S-1-5-18" &&
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
	moduleClass := eligibleCDXML(script, path)
	reason := ""
	if moduleClass == "" {
		reason = "risk_script_not_eligible"
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
	ctx := behaviorlearning.Context{Executable: moduleClass, Capability: "windows-powershell-cdxml-v1", Risk: &behaviorlearning.WindowsRiskContext{
		Provider: source.System.Provider, Channel: source.System.Channel, UserSID: source.System.UserID,
		Path: path, ModuleClass: moduleClass, ScriptSHA256: digest}}
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

// eligibleCDXML is a conservative admission heuristic, not signature trust.
// Only stable SYSTEM-generated network/scheduler module definitions may train;
// exact full-content matching, rate checks and security exclusions still apply.
func eligibleCDXML(script, path string) string {
	if containsSuspiciousCommand(script) {
		return ""
	}
	lower := strings.ToLower(script)
	for _, token := range []string{"invoke-expression", "iex ", "iex(", "start-process", "invoke-command", "downloadfile",
		"net.webclient", "reflection.assembly", "writeallbytes", "set-content", "add-content", "remove-item", "set-itemproperty"} {
		if strings.Contains(lower, token) {
			return ""
		}
	}
	// Non-empty paths must be literal protected built-in module paths. Empty
	// paths are normal for generated CDXML; never normalize dot segments/UNC.
	if path != "" {
		p := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
		if len(p) < 3 || p[1:3] != ":/" || p[0] < 'a' || p[0] > 'z' || strings.Contains(p[3:], ":") ||
			!strings.HasPrefix(p[3:], "windows/system32/windowspowershell/v1.0/modules/") || strings.Contains(p, "/../") ||
			strings.Contains(p, "/./") || strings.HasSuffix(p, "/..") || strings.HasSuffix(p, "/.") || strings.ContainsAny(p, "*?\x00") {
			return ""
		}
	}
	className := cdxmlModuleClass(script)
	if className == "" || !strings.Contains(script, "__cmdletization_BindCommonParameters") ||
		!strings.Contains(script, "Microsoft.PowerShell.Cmdletization.Cim.CimCmdletAdapter") {
		return ""
	}
	class := strings.ToLower(strings.ReplaceAll(className, `\`, "/"))
	switch class {
	case "root/standardcimv2/msft_nettcpconnection", "root/standardcimv2/msft_netudpendpoint",
		"root/standardcimv2/msft_netipaddress", "root/standardcimv2/msft_netipinterface",
		"root/standardcimv2/msft_netroute", "root/standardcimv2/msft_netneighbor",
		"root/standardcimv2/msft_netcompartment", "root/standardcimv2/msft_netipv4protocol",
		"root/standardcimv2/msft_netipv6protocol", "root/standardcimv2/msft_netoffloadglobalsetting",
		"root/standardcimv2/msft_netprefixpolicy", "root/standardcimv2/msft_nettcpsetting",
		"root/standardcimv2/msft_nettransportfilter", "root/standardcimv2/msft_netudpsetting",
		"root/microsoft/windows/taskscheduler/msft_scheduledtask",
		"root/microsoft/windows/taskscheduler/ps_scheduledtask",
		"root/microsoft/windows/taskscheduler/ps_clusteredscheduledtask":
		return class
	}
	return ""
}

// cdxmlModuleClass scans lines cheaply and applies the declaration regex only
// to relevant lines. Avoid a whole-body regex over large generated modules;
// repeated/ambiguous declarations still disqualify the entire block.
func cdxmlModuleClass(script string) string {
	class := ""
	for script != "" {
		line, rest, _ := strings.Cut(script, "\n")
		script = rest
		name, _, assignment := strings.Cut(line, "=")
		if !assignment {
			continue
		}
		name = strings.TrimSpace(name)
		if strings.HasPrefix(name, "[") {
			typeName, rest, ok := strings.Cut(name[1:], "]")
			if !ok || (!strings.EqualFold(typeName, "string") && !strings.EqualFold(typeName, "system.string")) {
				continue
			}
			name = strings.TrimSpace(rest)
		}
		if !strings.EqualFold(name, "$script:ClassName") && !strings.EqualFold(name, "$script:__cmdletization_ClassName") && !strings.EqualFold(name, "$__cmdletization_ClassName") {
			continue
		}
		match := cdxmlClass.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		if class != "" {
			return ""
		}
		class = match[1]
	}
	return class
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
