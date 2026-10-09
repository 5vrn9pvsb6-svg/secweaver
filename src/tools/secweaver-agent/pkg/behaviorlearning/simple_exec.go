package behaviorlearning

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const simpleExecStrategy = "linux_exec_four_fields_v1"
const simpleExecWindow = time.Hour
const simpleExecOccurrences = 5

// simpleHash uses separate domains for source IDs and behavior tuples. A local
// secret prevents stored command fingerprints from being offline dictionaries.
func (e *Engine) simpleHash(domain string, value any) string {
	body, _ := json.Marshal(value)
	mac := hmac.New(sha256.New, e.store.Key)
	for _, part := range []string{domain, e.state.Device, e.state.Policy} {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// simpleBudget reserves space for serialization, the checkpoint replacement,
// counters and map overhead. Exact ceilings can be lower than configured counts.
func (e *Engine) simpleBudget(entries, seen int) bool {
	budget := int64(e.cfg.MemoryMB) << 19
	if disk := (int64(e.cfg.StateMB) << 20) / 6; disk < budget {
		budget = disk
	}
	return int64(entries)*2048+int64(seen)*256 <= budget
}

// validateSimpleState bounds authenticated input too: older/corrupt producers
// must not restore unlimited maps or a future window that promotes immediately.
func (e *Engine) validateSimpleState(now time.Time) error {
	if e.state.Strategy != e.cfg.simpleStrategy() || len(e.state.Entries) > e.cfg.MaxEntries ||
		len(e.state.Candidates) > e.cfg.MaxCandidates || len(e.seen) > 65536 ||
		len(e.state.LastSeen) > len(e.state.Entries) ||
		!e.simpleBudget(len(e.state.Entries)+len(e.state.Candidates), len(e.seen)) {
		return fmt.Errorf("incompatible or oversized simple exec state")
	}
	for key, entry := range e.state.Entries {
		if entry == nil || entry.Fingerprint != key || len(key) != 64 || len(entry.Recent) != 0 ||
			entry.EventType != e.cfg.simpleEventType() || entry.Count != simpleExecOccurrences {
			return fmt.Errorf("invalid simple exec entry")
		}
	}
	for key, candidate := range e.state.Candidates {
		if candidate == nil || candidate.Fingerprint != key || len(key) != 64 || len(candidate.Recent) >= simpleExecOccurrences ||
			candidate.EventType != e.cfg.simpleEventType() || len(candidate.Recent) == 0 || candidate.Count != uint64(len(candidate.Recent)) {
			return fmt.Errorf("invalid simple exec candidate")
		}
		for i, at := range candidate.Recent {
			if at.After(now) || (i > 0 && at.Before(candidate.Recent[i-1])) {
				return fmt.Errorf("simple exec clock regression; explicit recovery required")
			}
		}
	}
	for key, at := range e.state.LastSeen {
		if e.state.Entries[key] == nil || at.After(now) {
			return fmt.Errorf("invalid simple exec last-seen state")
		}
	}
	for key, at := range e.seen {
		if len(key) != 64 || at.After(now) {
			return fmt.Errorf("invalid simple exec dedup state")
		}
	}
	return nil
}

// processSimple is called under Engine.mu by the existing bounded adapter.
// Only exact fields and event completeness qualify; PID/UID/ancestry, binaries,
// rate models and live /proc state have no role in this policy.
func (e *Engine) processSimple(o Observation, now time.Time) error {
	if len(o.Raw) > 65536 || len(o.EventID) > 256 {
		return e.original(o.Raw)
	}
	id := e.simpleHash("source", o.EventID)
	if at, ok := e.seen[id]; ok {
		if now.Before(at) {
			e.faultLocked("clock_regression")
		} else if now.Sub(at) <= simpleExecWindow {
			return nil
		}
		delete(e.seen, id)
	}
	reason := o.Reason
	fields, valid := e.cfg.simpleTuple(o.Context)
	qualified := o.Complete && reason == "" && o.EventID != "" && valid
	if reason == "" && !qualified {
		reason = "incomplete_" + e.cfg.simpleEventType() + "_fields"
	}
	if reason == "" {
		reason = e.operationReason(o.Context)
	}
	// When dedup cannot remember this input, emit it and do not train. Repeated
	// reader retries must never manufacture the five distinct executions.
	remember := o.EventID != "" && len(e.seen) < 65536 && e.simpleBudget(len(e.state.Entries)+len(e.state.Candidates), len(e.seen)+1)
	if !remember && reason == "" {
		reason = "dedup_capacity"
	}
	key := ""
	if qualified && reason == "" {
		key = e.simpleHash(e.cfg.simpleEventType(), fields)
	}
	healthy := e.sourceHealthy(now)
	if e.state.Mode == "learning" && key != "" && healthy && e.state.Entries[key] == nil {
		reason = e.learnSimple(key, now)
	}
	entry := e.state.Entries[key]
	suppress := entry != nil && reason == "" && healthy && !e.cfg.Shadow &&
		(e.state.Mode == "learning" || e.state.Mode == "enforcing")
	if e.pendingFault.Load() != nil {
		e.applyFault()
		suppress = false
	}
	if suppress {
		c := e.counter(key, now)
		c.Observed++
		c.Suppressed++
		e.state.LastSeen[key] = now
		e.seen[id] = now
		return nil
	}
	if reason == "" {
		switch {
		case e.state.Mode == "degraded":
			reason = e.state.Reason
		case !healthy:
			reason = "source_unhealthy"
		case e.cfg.Shadow:
			reason = "shadow"
		case e.state.Mode == "enforcing":
			reason = "baseline_miss"
		default:
			reason = "learning"
		}
	}
	if strings.HasSuffix(reason, "_capacity") {
		e.state.Reason = reason
	}
	fingerprintVersion := 2
	if e.cfg.simpleFile {
		fingerprintVersion = 3
	} else if e.cfg.simpleStrategy() != simpleExecStrategy {
		fingerprintVersion = 4
	}
	raw := decorate(o.Raw, map[string]any{"event_id": o.EventID, "behavior_fingerprint": key,
		"baseline_id": e.state.BaselineID, "learning_state": e.state.Mode,
		"learning_decision": "emit", "decision_reason": reason, "fingerprint_version": fingerprintVersion})
	if err := e.original(raw); err != nil {
		e.faultLocked("original_output_failed")
		return err
	}
	if remember {
		e.seen[id] = now
	}
	// Counters start at promotion. The first four already-emitted originals are
	// not recounted; shadow and fault emissions for known entries remain visible.
	if entry != nil {
		c := e.counter(key, now)
		c.Observed++
		c.Emitted++
	}
	return nil
}

// learnSimple keeps only the rolling window's last five distinct inputs. A new
// entry is durable before its fifth event can be suppressed. Journal errors
// invalidate matching and retain that event's original payload.
func (e *Engine) learnSimple(key string, now time.Time) string {
	candidate := e.state.Candidates[key]
	if candidate == nil {
		if len(e.state.Candidates) >= e.cfg.MaxCandidates ||
			!e.simpleBudget(len(e.state.Candidates)+len(e.state.Entries)+1, len(e.seen)+1) {
			return "candidate_capacity"
		}
		candidate = &Entry{EventType: e.cfg.simpleEventType(), Fingerprint: key}
		e.state.Candidates[key] = candidate
	}
	first := 0
	for first < len(candidate.Recent) && now.Sub(candidate.Recent[first]) > simpleExecWindow {
		first++
	}
	candidate.Recent = append(candidate.Recent[:0], candidate.Recent[first:]...)
	if n := len(candidate.Recent); n > 0 && now.Before(candidate.Recent[n-1]) {
		e.faultLocked("clock_regression")
		return "clock_regression"
	}
	candidate.Recent = append(candidate.Recent, now)
	candidate.Count = uint64(len(candidate.Recent))
	if len(candidate.Recent) < simpleExecOccurrences {
		return ""
	}
	if len(e.state.Entries) >= e.cfg.MaxEntries {
		candidate.Recent = candidate.Recent[1:]
		candidate.Count = uint64(len(candidate.Recent))
		return "baseline_capacity"
	}
	entry := &Entry{EventType: e.cfg.simpleEventType(), Fingerprint: key, Count: simpleExecOccurrences}
	if err := e.store.appendAdmission(e.state.BaselineID, entry, now); err != nil {
		candidate.Recent = candidate.Recent[1:]
		candidate.Count = uint64(len(candidate.Recent))
		e.faultLocked("baseline_commit_failed")
		return "baseline_commit_failed"
	}
	e.state.Entries[key] = entry
	e.state.LastSeen[key] = now
	delete(e.state.Candidates, key)
	if strings.HasSuffix(e.state.Reason, "_capacity") {
		e.state.Reason = ""
	}
	return ""
}

// pruneSimple runs once a minute, not once per event or per-second Tick. Removing
// an expired candidate frees capacity; already admitted entries never age out.
func (e *Engine) pruneSimple(now time.Time) {
	if now.Sub(e.lastSimplePrune) < time.Minute {
		return
	}
	e.lastSimplePrune = now
	for id, at := range e.seen {
		if now.Sub(at) > simpleExecWindow {
			delete(e.seen, id)
		}
	}
	for key, candidate := range e.state.Candidates {
		if len(candidate.Recent) == 0 || now.Sub(candidate.Recent[len(candidate.Recent)-1]) > simpleExecWindow {
			delete(e.state.Candidates, key)
		}
	}
}
