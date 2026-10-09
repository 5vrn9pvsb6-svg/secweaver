package windowseventlogriskjson

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/layout"
	agentoutput "secweaver-agent/pkg/output"
)

// RiskLearningOptions isolates risk-log baselines from the Sysmon exec policy.
// Fresh installs opt in explicitly; omission preserves existing upgrade choices.
type RiskLearningOptions struct {
	Enabled, Shadow bool
	Duration        time.Duration
	Generation      uint64
	StateDir        string
}

// RegisterFlags exposes independent relearning without resetting exec history.
func (o *RiskLearningOptions) RegisterFlags(fs *flag.FlagSet) {
	fs.BoolVar(&o.Enabled, "risk-behavior-learning", false, "learn complete PowerShell script blocks: five exact matches in one hour")
	fs.BoolVar(&o.Shadow, "risk-learning-shadow", false, "learn risk behavior while retaining all originals")
	fs.DurationVar(&o.Duration, "risk-learning-duration", 24*time.Hour, "healthy risk learning duration")
	fs.Uint64Var(&o.Generation, "risk-learning-generation", 0, "increase to explicitly relearn the risk baseline")
	fs.StringVar(&o.StateDir, "risk-learning-state-dir", "", "absolute independent risk learning state directory")
}

// policy is also used by doctor; inspection never acquires the writer lock.
func (o RiskLearningOptions) policy(cursor string) (behaviorlearning.Config, error) {
	if o.Duration == 0 {
		o.Duration = 24 * time.Hour
	}
	if o.StateDir == "" {
		dir := filepath.Dir(cursor)
		if cursor == "" {
			dir = layout.WindowsData
		}
		o.StateDir = filepath.Join(dir, "behavior-learning-windows-risk")
	}
	return behaviorlearning.ScriptPolicy(behaviorlearning.Config{Enabled: o.Enabled, Shadow: o.Shadow, Generation: o.Generation,
		StateDir: o.StateDir, LearningSeconds: int(o.Duration / time.Second),
		EventTypes: []string{"powershell_script_block"}}).Normalize()
}

// ReadRiskLearningStatus verifies the authenticated checkpoint without changing
// runtime ownership. An enabled flag alone is never proof of active filtering.
func ReadRiskLearningStatus(o RiskLearningOptions, cursor, output, device string) (behaviorlearning.StatusSnapshot, error) {
	cfg, err := o.policy(cursor)
	if err != nil {
		return behaviorlearning.StatusSnapshot{}, err
	}
	state, err := behaviorlearning.Inspect(cfg.StateDir, cfg.StateMB)
	if err != nil {
		return behaviorlearning.StatusSnapshot{}, err
	}
	if device == "" || state.Device != device {
		return behaviorlearning.StatusSnapshot{}, fmt.Errorf("risk learning device identity mismatch")
	}
	latest, _ := behaviorlearning.ReadLatestSummary(output)
	return behaviorlearning.Snapshot(cfg, state, latest, time.Now()), nil
}

// riskEngine keeps the adapter testable with deterministic decisions; production
// uses the same authenticated, bounded Engine as process behavior learning.
type riskEngine interface {
	Process(behaviorlearning.Observation) error
	Health(bool, bool)
	Fault(string)
	Tick() error
	Checkpoint() error
	CloseWithCheckpoint(func() error) error
}

// riskLearning owns all sink writes and script fragments under mu. Engine
// callbacks are synchronous and must not reacquire mu. No second reader or
// asynchronous evidence queue can outrun the EventRecordID checkpoint.
type riskLearning struct {
	mu                sync.Mutex
	out               io.Writer
	engine            riskEngine
	stop, done        chan struct{}
	started, lastPoll time.Time
	lease             time.Duration
	pending           map[string]*scriptGroup
	pendingBytes      int
	current           []riskEvent
	emitted           int
	suppressed        int
}

// wrapRiskLearning fails open on missing identity, state corruption or lock
// contention. It never substitutes a hostname/IP for the enrolled device ID.
func wrapRiskLearning(out io.Writer, o RiskLearningOptions, cursor string, poll time.Duration) (io.Writer, func() error) {
	noop := func() error { return nil }
	if !o.Enabled {
		return out, noop
	}
	cfg, err := o.policy(cursor)
	device := os.Getenv("SECWEAVER_DEVICE_ID")
	if err == nil && device == "" {
		err = fmt.Errorf("registered device ID unavailable")
	}
	w := &riskLearning{out: out, started: time.Now(), lease: poll + 30*time.Second,
		pending: make(map[string]*scriptGroup), stop: make(chan struct{}), done: make(chan struct{})}
	if w.lease < 45*time.Second {
		w.lease = 45 * time.Second
	}
	if err == nil {
		w.engine, err = behaviorlearning.New(cfg, device, w.emitDecision, w.emitSummary)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: Windows risk learning disabled; originals retained: %v\n", err)
		return out, noop
	}
	go w.tick()
	return w, w.Close
}

// Write serializes ordinary/protected events with background learning summaries.
func (w *riskLearning) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.out.Write(p)
}

// emitDecision applies only learning metadata to the retained native fragments.
// The engine's logical script ID must never overwrite Windows event_id=4104.
func (w *riskLearning) emitDecision(raw json.RawMessage) error {
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return err
	}
	delete(metadata, "event_id")
	delete(metadata, "ancestry_context_missing")
	for _, event := range w.current {
		b, err := json.Marshal(event)
		if err != nil {
			return err
		}
		var record map[string]json.RawMessage
		if err := json.Unmarshal(b, &record); err != nil {
			return err
		}
		for key, value := range metadata {
			record[key] = value
		}
		if err := json.NewEncoder(w.out).Encode(record); err != nil {
			return err
		}
		w.emitted++
	}
	return nil
}

// emitSummary keeps counters in the existing risk stream: no additional Logtail
// route is required. Counts are complete script blocks, not native fragments.
func (w *riskLearning) emitSummary(s behaviorlearning.Summary) error {
	return json.NewEncoder(w.out).Encode(struct {
		behaviorlearning.Summary
		SourceStream  string `json:"source_stream"`
		CountUnit     string `json:"count_unit"`
		Timestamp     string `json:"timestamp"`
		ParserVersion string `json:"parser_version"`
		Severity      string `json:"severity"`
		RiskLevel     string `json:"risk_level"`
		RuleID        string `json:"rule_id"`
		Message       string `json:"message"`
	}{s, "windows_risk", "script_blocks", s.Time.UTC().Format(time.RFC3339Nano), parserVersion,
		"info", "info", "WIN-BEHAVIOR-SUMMARY", "Windows risk behavior counters/status; not a security alert"})
}

// tick advances healthy time only after a successful PowerShell-channel poll.
// Missing Sysmon does not disable this native Event Log capability.
func (w *riskLearning) tick() {
	defer close(w.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.mu.Lock()
			w.engine.Health(!w.lastPoll.IsZero() && time.Since(w.lastPoll) <= w.lease, false)
			if err := w.engine.Tick(); err != nil {
				fmt.Fprintf(os.Stderr, "WARN: Windows risk learning checkpoint failed; originals retained: %v\n", err)
			}
			w.mu.Unlock()
		case <-w.stop:
			return
		}
	}
}

// Sync writes counters/originals before cursor advancement. Incomplete fragments
// must already have been emitted by finishRound, never retained only in memory.
func (w *riskLearning) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) != 0 {
		return fmt.Errorf("risk script fragments were not flushed before checkpoint")
	}
	if err := w.engine.Checkpoint(); err != nil {
		return err
	}
	if err := agentoutput.Checkpoint(w.out); err != nil {
		w.engine.Fault("risk_output_checkpoint_failed")
		return err
	}
	return nil
}

// Close joins the ticker before releasing baseline ownership. The reader must
// stop first; sink errors persist a degraded baseline rather than a clean one.
func (w *riskLearning) Close() error {
	close(w.stop)
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	_, flushErr := w.flushPending()
	if flushErr != nil {
		w.engine.Fault("risk_fragment_output_failed")
	}
	return errors.Join(flushErr, w.engine.CloseWithCheckpoint(func() error { return agentoutput.Checkpoint(w.out) }))
}
