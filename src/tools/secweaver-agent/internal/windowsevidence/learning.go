package windowsevidence

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/layout"
	agentoutput "secweaver-agent/pkg/output"
	"secweaver-agent/pkg/windowseventlog"
)

// LearningOptions is explicit opt-in for upgrades; fresh Windows configs pass
// -behavior-learning. The shared owner, not a second reader, applies filtering.
type LearningOptions struct {
	Enabled, Shadow       bool
	Duration              time.Duration
	Generation            uint64
	StateDir, Output      string
	EventTypes, FileRoots string
}

// RegisterFlags exposes the same learning policy on either evidence owner.
func (o *LearningOptions) RegisterFlags(fs *flag.FlagSet) {
	fs.BoolVar(&o.Enabled, "behavior-learning", false, "learn exact Windows behavior: five matching events in one hour")
	fs.BoolVar(&o.Shadow, "learning-shadow", false, "learn while preserving every original event")
	fs.DurationVar(&o.Duration, "learning-duration", 24*time.Hour, "accumulated healthy learning time")
	fs.Uint64Var(&o.Generation, "learning-generation", 0, "increase to explicitly relearn a readable baseline")
	fs.StringVar(&o.StateDir, "learning-state-dir", "", "absolute learning state directory")
	fs.StringVar(&o.Output, "learning-output", "", "absolute behavior summary log path")
	fs.StringVar(&o.EventTypes, "learning-event-types", "exec", "comma-separated exec,active_connect,file_op learning types")
	fs.StringVar(&o.FileRoots, "learning-file-roots", "", "legacy compatibility option; exact file learning matches all complete file_op tuples")
}

// Learning owns a ticker and the engine; mu serializes source health, source
// output and checkpoints. Windows verification uses only bounded event fields,
// so no per-event process scan, hashing subprocess or asynchronous queue is needed.
type Learning struct {
	io.Writer
	mu                sync.Mutex
	engine            *behaviorlearning.Engine
	fileEngine        *behaviorlearning.Engine
	networkEngine     *behaviorlearning.Engine
	summary           io.Writer
	closeSummary      func()
	stop, done        chan struct{}
	started, lastPoll time.Time
	lease             time.Duration
	emitted           int
	lastPrune         time.Time
	fileContexts      map[string]fileContext
	fileContextBytes  int
}

// WrapLearning returns the original sink on all initialization failures. A
// missing enrolled device identity must not create a reusable hostname baseline.
func WrapLearning(out io.Writer, o LearningOptions, stateFile, eventPath string, poll time.Duration) (io.Writer, func() error) {
	noop := func() error { return nil }
	if out == nil || !o.Enabled {
		return out, noop
	}
	w, err := newLearning(out, o, stateFile, eventPath, poll)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: Windows behavior learning disabled; originals retained: %v\n", err)
		return out, noop
	}
	return w, w.Close
}

// newLearning acquires state ownership before starting the ticker. Failures
// close the summary sink; the caller retains responsibility for the raw sink.
func newLearning(out io.Writer, o LearningOptions, stateFile, eventPath string, poll time.Duration) (*Learning, error) {
	cfg, err := o.policy(stateFile, eventPath)
	if err != nil {
		return nil, err
	}
	device := strings.TrimSpace(os.Getenv("SECWEAVER_DEVICE_ID"))
	if device == "" {
		return nil, fmt.Errorf("registered device ID unavailable")
	}
	summary, closeSummary, err := agentoutput.OpenEventAppend(agentoutput.AppendOptions{Path: cfg.OutputLog, Perm: agentoutput.DefaultFilePerm})
	if err != nil {
		return nil, err
	}
	w := &Learning{Writer: out, summary: summary, closeSummary: closeSummary, stop: make(chan struct{}), done: make(chan struct{}), started: time.Now(), lease: poll + 30*time.Second}
	w.fileContexts = make(map[string]fileContext)
	if w.lease < 45*time.Second {
		w.lease = 45 * time.Second
	}
	writeSummary := func(s behaviorlearning.Summary) error {
		err := json.NewEncoder(summary).Encode(s)
		if err != nil {
			w.fault("summary_output_failed")
		}
		return err
	}
	w.engine, err = behaviorlearning.New(cfg, device, w.writeOriginal, writeSummary)
	if err != nil {
		closeSummary()
		return nil, err
	}
	if filePolicy := behaviorlearning.FilePolicy(cfg, true); filePolicy.Enabled {
		w.fileEngine, err = behaviorlearning.New(filePolicy, device, w.writeOriginal, writeSummary)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: Windows file learning disabled; originals retained: %v\n", err)
		}
	}
	if policy := behaviorlearning.NetworkPolicy(cfg); policy.Enabled {
		w.networkEngine, err = behaviorlearning.New(policy, device, w.writeOriginal, writeSummary)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: Windows connection learning disabled; originals retained: %v\n", err)
		}
	}
	go w.tick()
	return w, nil
}

// policy is shared by runtime and status inspection so defaults and collision
// checks cannot drift. It does not acquire a writer lock or create state files.
func (o LearningOptions) policy(stateFile, eventPath string) (behaviorlearning.Config, error) {
	if o.Duration == 0 {
		o.Duration = 24 * time.Hour
	}
	if o.StateDir == "" {
		dir := filepath.Dir(stateFile)
		if stateFile == "" {
			dir = layout.WindowsData
		}
		o.StateDir = filepath.Join(dir, "behavior-learning-windows")
	}
	if o.Output == "" {
		o.Output = LearningOutputPath(eventPath, "")
	}
	if strings.EqualFold(filepath.Clean(o.Output), filepath.Clean(eventPath)) {
		return behaviorlearning.Config{}, fmt.Errorf("learning summary and original logs must differ")
	}
	return behaviorlearning.WindowsExecPolicy(behaviorlearning.Config{Enabled: o.Enabled, StateDir: o.StateDir, OutputLog: o.Output,
		LearningSeconds: int(o.Duration / time.Second), Generation: o.Generation, Shadow: o.Shadow,
		EventTypes: splitPolicyList(o.EventTypes, ","), FileRoots: splitPolicyList(o.FileRoots, ";")}).Normalize()
}

// LearningOutputPath is shared with descriptors so disk budgeting sees summaries.
func LearningOutputPath(eventPath, override string) string {
	if override != "" {
		return override
	}
	if eventPath == "-" {
		return filepath.Join(layout.WindowsLogs, "behavior-learning.log")
	}
	return filepath.Join(filepath.Dir(eventPath), "behavior-learning.log")
}

// WithLearningOutput declares the extra owned file for collision detection,
// disk protection and diagnostics without opening the baseline state.
func WithLearningOutput(args []string, eventPath string, paths []string) []string {
	enabled, _, err := modulecontract.BoolFlag(args, "behavior-learning")
	if err != nil || !enabled || eventPath == "" {
		return paths
	}
	override, _ := modulecontract.StringFlag(args, "learning-output")
	return append(paths, LearningOutputPath(eventPath, override))
}

// tick renews the engine's short health lease only while a completed source poll
// is recent. Poll failures permanently degrade; a stuck reader cannot keep learning.
func (w *Learning) tick() {
	defer close(w.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.mu.Lock()
			w.pruneContexts(time.Now())
			for _, engine := range w.engines() {
				if engine != nil {
					engine.Health(!w.lastPoll.IsZero() && time.Since(w.lastPoll) <= w.lease, false)
					if err := engine.Tick(); err != nil {
						fmt.Fprintf(os.Stderr, "Windows learning checkpoint: %v\n", err)
					}
				}
			}
			w.mu.Unlock()
		case <-w.stop:
			return
		}
	}
}

// SourcePoll is called after the entire polling round. Failures retain raw
// events and require explicit relearning, including an unavailable Sysmon channel.
func SourcePoll(out io.Writer, healthy bool) {
	if w, ok := out.(*Learning); ok {
		w.mu.Lock()
		defer w.mu.Unlock()
		if healthy {
			w.lastPoll = time.Now()
		} else {
			w.fault("windows_source_query_failed")
			w.lastPoll = time.Time{}
			w.clearFileContexts()
		}
	}
}

// SourceFault invalidates before handling more records from the same polling round.
func SourceFault(out io.Writer, reason string) {
	if w, ok := out.(*Learning); ok {
		w.fault(reason)
		w.mu.Lock()
		w.clearFileContexts()
		w.mu.Unlock()
	}
}

// WriteSource routes each event type to an independent exact baseline. The
// shared reader retains continuity checks and GUID-based command correlation.
func WriteSource(out io.Writer, event windowseventlog.Event, includeRaw bool) (int, error) {
	if w, ok := out.(*Learning); ok {
		// Log clearing, collector restart/config changes and Sysmon errors break
		// source continuity even though they do not classify as process evidence.
		id := event.EventIDInt()
		// A process GUID can survive injected code or image tampering. Observed
		// integrity signals disqualify this generation instead of associating
		// later network/file I/O with the originally observed process command.
		if strings.EqualFold(event.System.Provider, "Microsoft-Windows-Sysmon") && (id == 8 || id == 25) {
			SourceFault(w, "windows_process_integrity_changed")
		}
		if (strings.EqualFold(event.System.Provider, "Microsoft-Windows-Sysmon") && (id == 4 || id == 16 || id == 255)) ||
			(strings.EqualFold(event.System.Channel, "Security") && id == 1102) ||
			(strings.EqualFold(event.System.Provider, "Microsoft-Windows-Eventlog") && id == 104) {
			w.fault("windows_source_continuity_changed")
			w.mu.Lock()
			w.clearFileContexts()
			w.mu.Unlock()
		}
		if strings.EqualFold(event.System.Provider, "Microsoft-Windows-Sysmon") && id == 5 {
			w.mu.Lock()
			w.forgetFileInstance(processInstance(event.System.Computer, event.Field("ProcessGuid")))
			w.mu.Unlock()
		}
		return w.writeSource(event, includeRaw)
	}
	return Write(json.NewEncoder(out), event, includeRaw)
}

// writeSource reports actual original/context writes, not whitelist matches, so
// operational EventsWritten counters do not count suppressed records as output.
func (w *Learning) writeSource(event windowseventlog.Event, includeRaw bool) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	before := w.emitted
	for _, e := range Classify(event, includeRaw) {
		var o behaviorlearning.Observation
		engine := w.engine
		if e.EventType == "exec" {
			o = learningObservation(e, w.started, time.Now())
			w.rememberFileExecution(e, time.Now())
		} else if e.EventType == "file_op" {
			o = w.fileObservation(e, time.Now())
			engine = w.fileEngine
		} else {
			o = w.activityObservation(e, time.Now())
			engine = w.networkEngine
		}
		var err error
		if engine == nil {
			err = w.writeOriginal(o.Raw)
		} else {
			err = engine.Process(o)
		}
		if err != nil {
			return w.emitted - before, err
		}
	}
	return w.emitted - before, nil
}

// splitPolicyList preserves explicit scope; empty input retains legacy defaults.
func splitPolicyList(value, separator string) []string {
	var parts []string
	for _, item := range strings.Split(value, separator) {
		if item = strings.TrimSpace(item); item != "" {
			parts = append(parts, item)
		}
	}
	return parts
}

// Sync commits summaries and originals before the reader persists EventRecordID.
// No asynchronous event queue can be skipped by the cursor checkpoint.
func (w *Learning) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, engine := range w.engines() {
		if engine != nil {
			if err := engine.Checkpoint(); err != nil {
				return err
			}
		}
	}
	if err := agentoutput.Checkpoint(w.summary); err != nil {
		w.fault("summary_checkpoint_failed")
		return err
	}
	err := agentoutput.Checkpoint(w.Writer)
	if err != nil {
		w.fault("original_checkpoint_failed")
	}
	return err
}

// Close joins the ticker before committing clean shutdown and releasing the lock.
// The caller stops the source reader first and closes the original sink last.
func (w *Learning) Close() error {
	close(w.stop)
	<-w.done
	checkpoint := func() error {
		// Try both sinks even when the first fails; failure is persisted as a
		// degraded baseline before the exclusive state handle is released.
		return errors.Join(agentoutput.Checkpoint(w.summary), agentoutput.Checkpoint(w.Writer))
	}
	var err error
	for _, engine := range w.engines() {
		if engine != nil {
			err = errors.Join(err, engine.CloseWithCheckpoint(checkpoint))
		}
	}
	w.closeSummary()
	return err
}

func (w *Learning) engines() [3]*behaviorlearning.Engine {
	return [3]*behaviorlearning.Engine{w.engine, w.fileEngine, w.networkEngine}
}

// fault is safe inside sink callbacks: Engine.Fault is atomic, so it does not
// reenter the engine lock. A shared sink failure invalidates all three baselines.
func (w *Learning) fault(reason string) {
	for _, engine := range w.engines() {
		if engine != nil {
			engine.Fault(reason)
		}
	}
}

// writeOriginal runs under Learning.mu, including direct file fallback, so the
// source reader's emitted count and cursor checkpoint cover every actual write.
func (w *Learning) writeOriginal(raw json.RawMessage) error {
	_, err := fmt.Fprintln(w.Writer, string(raw))
	if err == nil {
		w.emitted++
	} else {
		w.fault("original_output_failed")
	}
	return err
}
