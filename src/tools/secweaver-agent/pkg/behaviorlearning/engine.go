package behaviorlearning

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type counters struct {
	Start                                   time.Time
	Observed, Suppressed, Emitted, Replayed uint64
	Complete                                bool
	// Sixty-one 5-second buckets conservatively include the boundary bucket,
	// ensuring a split-window burst cannot receive a double allowance.
	Slots        [61]uint64
	Epochs       [61]int64
	AnomalyUntil time.Time
	Reason       string
}
type evidence struct {
	raw        json.RawMessage
	id, parent string
	at         time.Time
}

// Engine owns its mutable state under mu. I/O is invoked by the bounded adapter
// worker, never the kernel reader. Fault can concurrently invalidate matching.
type Engine struct {
	mu            sync.Mutex
	cfg           Config
	store         *Store
	state         State
	now           func() time.Time
	lastTick      time.Time
	healthUntil   time.Time
	healthySince  time.Time
	warmUntil     time.Time
	lastFlush     time.Time
	lastSave      time.Time
	counters      map[string]*counters
	evidence      map[string]evidence
	evidenceBytes int
	seen          map[string]time.Time
	original      func(json.RawMessage) error
	summary       func(Summary) error
	runID         string
	sequence      uint64
	rateOrigin    time.Time
	closed        bool
	pendingFault  atomic.Pointer[string]
}

// New loads a compatible checkpoint; policy changes require a higher explicit
// generation. The adapter supplies verified device identity and bounded sinks.
func New(cfg Config, device string, original func(json.RawMessage) error, summary func(Summary) error) (*Engine, error) {
	var err error
	cfg, err = cfg.Normalize()
	if err != nil {
		return nil, err
	}
	if device == "" {
		return nil, fmt.Errorf("device identity unavailable")
	}
	s, err := OpenStore(cfg.StateDir, cfg.StateMB)
	if err != nil {
		return nil, err
	}
	runID, err := randomID()
	if err != nil {
		s.Close()
		return nil, err
	}
	e := &Engine{cfg: cfg, store: s, now: time.Now, counters: map[string]*counters{}, evidence: map[string]evidence{}, seen: map[string]time.Time{}, original: original, summary: summary, runID: runID}
	policyCfg := cfg
	policyCfg.StateDir = ""
	policyCfg.OutputLog = ""
	policyCfg.Enabled = false
	policyCfg.Generation = 0
	policyCfg.Shadow = false
	body, _ := json.Marshal(policyCfg)
	hash := sha256.Sum256(body)
	policy := hex.EncodeToString(hash[:])
	prior, err := s.Load()
	if err != nil {
		s.Close()
		return nil, err
	}
	now := e.now()
	if prior == nil || cfg.Generation > prior.Generation {
		if prior != nil && prior.Device != device {
			s.Close()
			return nil, fmt.Errorf("learning state belongs to another device")
		}
		baselineID, err := randomID()
		if err != nil {
			s.Close()
			return nil, err
		}
		e.state = State{Version: 1, Device: device, Policy: policy, Generation: cfg.Generation, BaselineID: baselineID, Mode: "learning", Started: now, Entries: map[string]*Entry{}, Candidates: map[string]*Entry{}, LastSeen: map[string]time.Time{}}
		if err = s.Commit(e.state); err != nil {
			s.Close()
			return nil, err
		}
	} else {
		if prior.Device != device || prior.Policy != policy || prior.Generation != cfg.Generation {
			s.Close()
			return nil, fmt.Errorf("learning state policy/device mismatch; explicit relearn required")
		}
		e.state = *prior
		if !prior.CleanShutdown {
			e.faultLocked("unclean_restart_requires_relearn")
		}
		if e.state.Mode == "enforcing" {
			e.state.Reason = "restart_context_and_counter_gap"
		}
		// Unknown downtime cannot reset idle expiry or outstanding anomaly protection.
		e.warmUntil = now.Add(10 * time.Minute)
	}
	e.state.CleanShutdown = false
	if err := s.Commit(e.state); err != nil {
		s.Close()
		return nil, err
	}
	e.rateOrigin = now
	e.lastTick = now
	e.lastFlush = now.Add(-time.Duration(cfg.SummarySeconds) * time.Second)
	e.lastSave = now
	return e, nil
}

// Health grants only a short lease. Missing status samples stop the learning
// clock and matching; explicit loss permanently disqualifies this generation.
func (e *Engine) Health(healthy bool, loss bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	if loss {
		e.faultLocked("source_event_loss")
		return
	}
	if !healthy {
		e.healthUntil = time.Time{}
		e.healthySince = time.Time{}
		return
	}
	if e.healthySince.IsZero() || !now.Before(e.healthUntil) {
		e.healthySince = now
	}
	e.healthUntil = now.Add(45 * time.Second)
}

// Fault invalidates a generation immediately. Recovery requires an explicit
// relearn, so a restart cannot promote samples collected through a known gap.
func (e *Engine) Fault(reason string) { e.pendingFault.CompareAndSwap(nil, &reason) }

// applyFault runs under mu; producers can invalidate without waiting for disk I/O.
func (e *Engine) applyFault() {
	if reason := e.pendingFault.Load(); reason != nil {
		e.faultLocked(*reason)
	}
}
func (e *Engine) faultLocked(reason string) { e.state.Mode = "degraded"; e.state.Reason = reason }

// fingerprint hashes exact canonical fields, not redacted command text.
func (e *Engine) fingerprint(c Context) string {
	b, _ := json.Marshal(struct {
		Device, Policy string
		Version        int
		Context        Context
	}{e.state.Device, e.state.Policy, 1, c})
	mac := hmac.New(sha256.New, e.store.Key)
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil))
}

// Process never treats missing context as a wildcard. Evidence is cached before
// suppression; memory pressure, failed output and bad health preserve originals.
func (e *Engine) Process(o Observation) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.applyFault()
	now := e.now()
	if len(o.Raw) > 65536 || len(o.EventID) > 256 {
		return e.original(o.Raw)
	}
	if o.EventID != "" {
		if _, ok := e.seen[o.EventID]; ok {
			return nil
		}

	}
	fingerprint := ""
	reason := o.Reason
	if reason == "" {
		reason = e.operationReason(o.Context)
	}
	contextBytes, _ := json.Marshal(o.Context)
	// Full dedup capacity falls back to originals rather than performing a
	// per-event map sweep or claiming complete aggregate counts for retries.
	if len(e.seen) >= 1024 && reason == "" {
		reason = "dedup_capacity"
	}
	qualified := o.Complete && o.EventID != "" && reason == "" && len(contextBytes) <= 32768 && complete(o.Context)
	if o.Context.Operation != nil && (o.Instance == "" || o.ParentInstance == "") {
		qualified = false
	}
	if qualified {
		fingerprint = e.fingerprint(o.Context)
	}
	if reason == "" && !qualified {
		reason = "incomplete_context"
	}
	mode := e.state.Mode
	healthy := now.Before(e.healthUntil) && now.Sub(e.healthySince) >= 10*time.Minute
	if mode == "learning" && qualified && healthy {
		e.learn(fingerprint, o.Context, now)
	}
	entry := e.state.Entries[fingerprint]
	suppress := false
	var c *counters
	if entry != nil {
		c = e.counter(fingerprint, now)
		c.Observed++
		epoch := int64(now.Sub(e.rateOrigin) / (5 * time.Second))
		if epoch < 0 {
			e.faultLocked("clock_regression")
			epoch = 0
		}
		c.Slots[int(epoch%61)] = e.advanceSlot(c, epoch)
		var rate uint64
		for i, n := range c.Slots {
			if epoch-c.Epochs[i] >= 0 && epoch-c.Epochs[i] < 61 {
				rate += n
			}
		}
		if rate > entry.Limit {
			if now.After(c.AnomalyUntil) {
				reason = "rate_anomaly"
			}
			c.Reason = "rate_anomaly"
			c.AnomalyUntil = now.Add(10 * time.Minute)
		}
		last := e.state.LastSeen[fingerprint]
		expired := !last.IsZero() && (now.Before(last) || now.Sub(last) > time.Duration(e.cfg.ExpiryDays)*24*time.Hour)
		if expired {
			reason = "baseline_idle_expired"
		} else {
			e.state.LastSeen[fingerprint] = now
		}
		suppress = qualified && e.state.Mode == "enforcing" && healthy && !expired && now.After(e.warmUntil) && now.After(c.AnomalyUntil) && !e.cfg.Shadow
	}
	// Only exec records occupy ancestor evidence slots. Repeated operations from
	// the same process must not overwrite its execution evidence or consume a
	// second process instance. Their adapters already require a verified exec.
	if suppress && o.Context.Operation == nil && !e.cache(o, now) {
		suppress = false
		reason = "context_budget"
	}
	if e.pendingFault.Load() != nil {
		suppress = false
		reason = "source_degraded"
		e.applyFault()
	}
	if suppress {
		c.Suppressed++
		e.remember(o.EventID, now)
		return nil
	}
	if reason == "" {
		reason = mode
		if entry == nil && mode == "enforcing" {
			reason = "baseline_miss"
		}
		if !healthy {
			reason = "health_warmup"
		}
		if e.cfg.Shadow {
			reason = "shadow"
		}
	}
	replayed, err := e.replay(o.ParentInstance, now)
	if err != nil {
		e.faultLocked("context_output_failed")
		if c != nil {
			c.Complete = false
		}
	}
	raw := decorate(o.Raw, map[string]any{"event_id": o.EventID, "behavior_fingerprint": fingerprint, "baseline_id": e.state.BaselineID, "learning_state": mode, "learning_decision": "emit", "decision_reason": reason, "fingerprint_version": 1, "ancestry_context_missing": o.ParentInstance == "" || (replayed == 0 && !qualified)})
	if err = e.original(raw); err != nil {
		e.faultLocked("original_output_failed")
		if c != nil {
			c.Complete = false
		}
		return err
	}
	e.remember(o.EventID, now)
	if c != nil {
		c.Emitted++
		c.Replayed += replayed
	}
	if reason == "rate_anomaly" {
		if err := e.flush(now); err != nil {
			e.faultLocked("summary_output_failed")
			return err
		}
	}
	return nil
}

// remember acknowledges an event only after successful write or suppression.
// Failed writes remain retryable; deduplication storage has a fixed upper bound.
func (e *Engine) remember(id string, now time.Time) {
	if id != "" && len(e.seen) < 1024 {
		e.seen[id] = now
	}
}

// complete validates the backend-neutral contract again at the trust boundary.
func complete(c Context) bool {
	if w := c.Windows; w != nil {
		return c.Capability == "windows-sysmon-sha256-v1" && c.Service != "" && c.Parent != "" &&
			c.Executable != "" && len(c.Digest) == 64 && len(c.Args) == 1 && c.Args[0] != "" && c.CWD != "" &&
			c.Session == "service_noninteractive" && w.SessionID == "0" && w.User != "" && w.User == w.ParentUser &&
			w.Integrity != "" && (w.LogonID == "0x3e7" || w.LogonID == "0x3e4" || w.LogonID == "0x3e5")
	}
	return c.Service != "" && c.Parent != "" && c.Executable != "" && c.Digest != "" && len(c.Args) > 0 && c.CWD != "" && c.UID != "" && c.EUID != "" && c.GID != "" && c.EGID != "" && c.AUID != "" && c.Session == "service_noninteractive" && c.Capability != "" && c.UID == c.EUID && c.GID == c.EGID
}
func (e *Engine) counter(key string, now time.Time) *counters {
	c := e.counters[key]
	if c == nil {
		c = &counters{Start: now, Complete: true}
		e.counters[key] = c
	}
	return c
}
func (e *Engine) advanceSlot(c *counters, epoch int64) uint64 {
	i := int(epoch % 61)
	if c.Epochs[i] != epoch {
		c.Epochs[i] = epoch
		return 1
	}
	return c.Slots[i] + 1
}

// learn budgets map overhead at its worst configured duration, rather than only
// counting fingerprints. No candidate stores plaintext argv or credentials.
func (e *Engine) learn(key string, ctx Context, now time.Time) {
	candidate := e.state.Candidates[key]
	if candidate == nil {
		perEntry := 4096 + (e.cfg.LearningSeconds/300+1)*64 + (e.cfg.LearningSeconds/3600+1)*48
		if len(e.state.Candidates) >= e.cfg.MaxCandidates || (len(e.state.Candidates)+1)*perEntry > (e.cfg.MemoryMB<<20)/2 {
			return
		}
		candidate = &Entry{EventType: ctx.SourceEventType(), Fingerprint: key, Executable: ctx.Executable, First: e.state.HealthySeconds, Hours: map[int]bool{}, Buckets: map[int]uint32{}}
		e.state.Candidates[key] = candidate
	}
	candidate.Count++
	candidate.Last = e.state.HealthySeconds
	candidate.Hours[int(e.state.HealthySeconds)/3600] = true
	candidate.Buckets[int(e.state.HealthySeconds)/300]++
}

// cache stores only already-owned original events. A bounded cache is a
// prerequisite for suppression, not an excuse to fabricate ancestor evidence.
func (e *Engine) cache(o Observation, now time.Time) bool {
	if o.Instance == "" || o.EventID == "" {
		return false
	}
	cost := len(o.Raw) + len(o.Instance) + len(o.ParentInstance) + 512
	if prev, ok := e.evidence[o.Instance]; ok {
		// Same instance plus another exec must use a different adapter instance key.
		if prev.id == o.EventID {
			return true
		}
		return false
	}
	if e.evidenceBytes+cost > (e.cfg.MemoryMB<<20)/4 {
		return false
	}
	e.evidence[o.Instance] = evidence{raw: append(json.RawMessage(nil), o.Raw...), id: o.EventID, parent: o.ParentInstance, at: now}
	e.evidenceBytes += cost
	return true
}

// replay emits at most 16 real ancestor records. Missing ancestry is not
// invented; originals carry a context marker when replay cannot be completed.
func (e *Engine) replay(parent string, now time.Time) (uint64, error) {
	var count uint64
	for i := 0; i < 16 && parent != ""; i++ {
		ev, ok := e.evidence[parent]
		if !ok {
			break
		}
		if now.Sub(ev.at) > 24*time.Hour {
			break
		}
		raw := decorate(ev.raw, map[string]any{"event_id": ev.id, "context_only": true, "baseline_id": e.state.BaselineID})
		if err := e.original(raw); err != nil {
			return count, err
		}
		count++
		parent = ev.parent
	}
	return count, nil
}

// Tick advances only measured online time with a live health lease. Baseline
// activation follows a durable checkpoint; failures cannot leave memory-only
// suppression enabled. The caller serializes ticks and shutdown.
func (e *Engine) Tick() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.applyFault()
	now := e.now()
	delta := now.Sub(e.lastTick).Seconds()
	e.lastTick = now
	if delta >= 0 {
		e.state.OnlineSeconds += delta
	}
	if delta >= 0 && delta <= 5 {
		if e.state.Mode == "learning" && now.Before(e.healthUntil) && now.Sub(e.healthySince) >= 10*time.Minute {
			e.state.HealthySeconds += delta
		}
	}
	if e.state.Mode == "learning" {
		if e.state.HealthySeconds >= float64(e.cfg.LearningSeconds) {
			e.freeze(now)
		} else if e.state.OnlineSeconds >= float64(e.cfg.OnlineDeadline) {
			e.faultLocked("learning_deadline")
		}
	}
	if now.Sub(e.lastFlush) >= time.Duration(e.cfg.SummarySeconds)*time.Second {
		if err := e.flush(now); err != nil {
			e.faultLocked("summary_output_failed")
			return err
		}
		e.lastFlush = now
	}
	if now.Sub(e.lastSave) >= time.Minute {
		if err := e.store.Commit(e.state); err != nil {
			e.faultLocked("checkpoint_failed")
			return err
		}
		e.lastSave = now
	}
	for id, observed := range e.seen {
		if now.Sub(observed) > time.Minute {
			delete(e.seen, id)
		}
	}
	// Periodic reclamation, not per-event scans, keeps hot-path work bounded.
	for k, v := range e.evidence {
		// Expired entries are removed on ticks, not every source event.
		if now.Sub(v.at) > 24*time.Hour {
			e.evidenceBytes -= len(v.raw) + len(k) + len(v.parent) + 512
			delete(e.evidence, k)
		}
	}
	return nil
}

// freeze deterministically promotes only qualified candidates and commits before
// any subsequent event can match. Sparse buckets include zeros in the P95.
func (e *Engine) freeze(now time.Time) {
	keys := make([]string, 0, len(e.state.Candidates))
	for k := range e.state.Candidates {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := e.state.Candidates[k]
		if c.Count < uint64(e.cfg.MinOccurrences) || len(c.Hours) < e.cfg.MinHours || c.Last-c.First < float64(e.cfg.MinSpan) {
			continue
		}
		if len(e.state.Entries) >= e.cfg.MaxEntries {
			break
		}
		bins := make([]uint32, (e.cfg.LearningSeconds+299)/300)
		for i, n := range c.Buckets {
			if i < len(bins) {
				bins[i] = n
			}
		}
		sort.Slice(bins, func(i, j int) bool { return bins[i] < bins[j] })
		limit := uint64(bins[(len(bins)*95+99)/100-1]) * 3
		if limit < 10 {
			limit = 10
		}
		c.Limit = limit
		c.Buckets = nil
		e.state.Entries[k] = c
		e.state.LastSeen[k] = now
	}
	e.state.Candidates = map[string]*Entry{}
	if len(e.state.Entries) == 0 {
		e.faultLocked("baseline_empty")
	} else {
		e.state.Mode = "enforcing"
	}
	if err := e.store.Commit(e.state); err != nil {
		e.faultLocked("baseline_commit_failed")
	}
}

// flush records successful writes separately from suppression. Sink failures
// invalidate the generation, retaining counters for retry with stable IDs.
func (e *Engine) flush(now time.Time) error {
	if err := e.flushCounters(now); err != nil {
		return err
	}
	status := e.summaryBase(now)
	status.EventType = "behavior_learning_status"
	e.sequence++
	status.SummaryID = fmt.Sprintf("%s:status:%d", e.runID, e.sequence)
	return e.summary(status)
}

// flushCounters lets cursor checkpoints publish only nonempty aggregates; idle
// polling must not turn the five-minute status stream into one record per poll.
func (e *Engine) flushCounters(now time.Time) error {
	for key, c := range e.counters {
		if c.Observed == 0 {
			continue
		}
		s := e.summaryBase(now)
		if entry := e.state.Entries[key]; entry != nil {
			s.SourceEventType = entry.EventType
		}
		if s.SourceEventType == "" {
			s.SourceEventType = "exec"
		}
		s.Fingerprint = key
		s.WindowStart = c.Start
		s.Observed = c.Observed
		s.Suppressed = c.Suppressed
		s.Emitted = c.Emitted
		s.Replayed = c.Replayed
		s.Complete = c.Complete && s.Complete
		if c.Reason != "" {
			s.Reason = c.Reason
		}
		s.SummaryID = fmt.Sprintf("%s:%s:%d", e.runID, key, c.Start.UnixNano())
		if err := e.summary(s); err != nil {
			return err
		}
		c.Start = now
		c.Observed = 0
		c.Suppressed = 0
		c.Emitted = 0
		c.Replayed = 0
		c.Complete = true
		c.Reason = ""
	}
	return nil
}
func (e *Engine) summaryBase(now time.Time) Summary {
	healthy := now.Before(e.healthUntil) && now.Sub(e.healthySince) >= 10*time.Minute
	return Summary{SourceHealthy: healthy, Shadow: e.cfg.Shadow, FilteringActive: healthy && !e.cfg.Shadow && e.state.Mode == "enforcing" && now.After(e.warmUntil), Time: now, EventType: "behavior_summary", AssetType: "host_behavior_summary", DeviceID: e.state.Device, BaselineID: e.state.BaselineID, WindowEnd: now, Mode: e.state.Mode, Reason: e.state.Reason, Complete: e.state.Mode != "degraded", HealthySeconds: e.state.HealthySeconds, Entries: len(e.state.Entries), Candidates: len(e.state.Candidates)}
}

// Close flushes before releasing ownership. A crash cannot silently finish the
// learning clock; restart also uses a ten-minute full-output protection window.
func (e *Engine) Close() error {
	return e.CloseWithCheckpoint(nil)
}

// CloseWithCheckpoint lets cursor-based adapters sync both evidence sinks before
// marking state clean. The callback must not call back into Engine (mu is held).
// A failed final fsync persists degradation while the state lock is still owned.
func (e *Engine) CloseWithCheckpoint(checkpoint func() error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	e.applyFault()
	err := e.flush(e.now())
	if err != nil {
		e.faultLocked("summary_output_failed")
	}
	if checkpoint != nil {
		if syncErr := checkpoint(); syncErr != nil {
			e.faultLocked("shutdown_output_checkpoint_failed")
			if err == nil {
				err = syncErr
			}
		}
	}
	e.state.CleanShutdown = true
	saveErr := e.store.Commit(e.state)
	e.store.Close()
	if err != nil {
		return err
	}
	return saveErr
}

// Checkpoint precedes durable source cursor advancement. Suppressed counts must
// reach the summary sink before an input can be acknowledged; sinks then fsync.
func (e *Engine) Checkpoint() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.applyFault()
	if err := e.flushCounters(e.now()); err != nil {
		e.faultLocked("summary_output_failed")
		return err
	}
	if err := e.store.Commit(e.state); err != nil {
		e.faultLocked("checkpoint_failed")
		return err
	}
	e.lastSave = e.now()
	return nil
}

// decorate only adds learning metadata; original evidence fields remain intact.
func decorate(raw json.RawMessage, extra map[string]any) json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return raw
	}
	for k, v := range extra {
		b, _ := json.Marshal(v)
		obj[k] = b
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return b
}
