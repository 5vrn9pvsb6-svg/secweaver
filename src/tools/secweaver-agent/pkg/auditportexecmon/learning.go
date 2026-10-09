package auditportexecmon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/layout"
)

// learningOutput is a semantic adapter, not a JSON-parsing generic writer.
// Ownership is bounded: one worker owns matching and queued events are deep
// copies. Overflow writes originals immediately and invalidates learning.
type learningOutput struct {
	io.Writer
	engine       *behaviorlearning.Engine
	fileEngine   *behaviorlearning.Engine
	queue        chan auditEvent
	stop         chan struct{}
	done         chan struct{}
	mu           sync.Mutex
	closed       bool
	closeSummary func()
	backend      string
	health       func() (bool, bool)
}

func learningPaths(c behaviorlearning.Config, eventPath string) behaviorlearning.Config {
	if c.StateDir == "" {
		c.StateDir = filepath.Join(layout.LinuxData, "behavior-learning")
		// Standard custom roots keep sibling logs/data directories together.
		if filepath.Base(filepath.Dir(eventPath)) == "logs" {
			c.StateDir = filepath.Join(filepath.Dir(filepath.Dir(eventPath)), "data", "behavior-learning")
		}
	}
	if c.OutputLog == "" {
		dir := filepath.Dir(eventPath)
		if eventPath == "-" {
			dir = layout.LinuxLogs
		}
		c.OutputLog = filepath.Join(dir, "behavior-learning.log")
	}
	return c
}

// newLearningOutput leaves the ordinary writer in charge on initialization
// errors. No monitoring rule or collector lifetime depends on this feature.
func newLearningOutput(cfg config, eventPath, backend string, out io.Writer, trackerHealth func() (bool, bool)) (*learningOutput, error) {
	c, err := behaviorlearning.DecodeExec(cfg.BehaviorLearning)
	if err != nil || !c.Enabled {
		return nil, err
	}
	c = learningPaths(c, eventPath)
	if filepath.Clean(c.OutputLog) == filepath.Clean(eventPath) {
		return nil, fmt.Errorf("learning summary and original logs must differ")
	}
	// Prefer the registered Agent device ID supplied by the supervisor. Standalone
	// Linux uses a distinct local machine scope, never an IP address.
	device := strings.TrimSpace(os.Getenv("SECWEAVER_DEVICE_ID"))
	if device == "" {
		b, e := os.ReadFile("/etc/machine-id")
		if e != nil || len(strings.TrimSpace(string(b))) < 16 {
			return nil, fmt.Errorf("stable learning device identity unavailable")
		}
		hash := sha256.Sum256(b)
		device = "local-machine:" + hex.EncodeToString(hash[:])
	}
	summary, closeSummary, err := openOutputLog(c.OutputLog)
	if err != nil {
		return nil, err
	}
	w := &learningOutput{Writer: out, queue: make(chan auditEvent, 128), stop: make(chan struct{}), done: make(chan struct{}), closeSummary: closeSummary, backend: backend, health: trackerHealth}
	original := func(raw json.RawMessage) error {
		_, err := fmt.Fprintln(out, string(raw))
		if err != nil {
			w.fault("original_output_failed")
		}
		return err
	}
	writeSummary := func(s behaviorlearning.Summary) error {
		b, err := json.Marshal(s)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(summary, string(b))
		if err != nil {
			w.fault("summary_output_failed")
		}
		return err
	}
	w.engine, err = behaviorlearning.New(c, device, original, writeSummary)
	if err != nil {
		closeSummary()
		return nil, err
	}
	// File state cannot reset exec progress or block collection if it is corrupt.
	if filePolicy := behaviorlearning.FilePolicy(c, false); filePolicy.Enabled {
		w.fileEngine, err = behaviorlearning.New(filePolicy, device, original, writeSummary)
		if err != nil {
			fmt.Fprintf(os.Stderr, "file behavior learning disabled; originals retained: %v\n", err)
		}
	}
	if state, err := behaviorlearning.Inspect(c.StateDir, c.StateMB); err == nil && state.Reason == "simple_exec_policy_migrated" {
		fmt.Fprintln(os.Stderr, "behavior learning: migrated to four-field matching; legacy baseline archived; learning restarted with immediate filtering on admission")
	}
	go w.run()
	return w, nil
}

// emitNormalizedEvent preserves direct writers in tests and disabled installs.
// It is called only after normal tracking and attribution have completed.
func emitNormalizedEvent(out io.Writer, event auditEvent) error {
	if sink, ok := out.(interface{ WriteEvent(auditEvent) error }); ok {
		return sink.WriteEvent(event)
	}
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}

// WriteEvent copies pooled slices/maps before enqueueing either learned stream.
// Disabled file learning bypasses the queue; overflow faults both baselines and
// writes the original immediately so backpressure cannot silently drop evidence.
func (w *learningOutput) WriteEvent(event auditEvent) error {
	if event.EventType != "exec" && (event.EventType != "file_op" || w.fileEngine == nil) {
		return emitNormalizedEvent(w.Writer, event)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(raw) > 65536 {
		w.fault("oversized_event")
		return emitNormalizedEvent(w.Writer, event)
	}
	// audit accumulators return to a pool immediately after this call.
	event.Command = append([]string(nil), event.Command...)
	event.FilePaths = append([]string(nil), event.FilePaths...)
	event.RawRecords = append([]string(nil), event.RawRecords...)
	fields := make(map[string]string, len(event.Fields))
	for k, v := range event.Fields {
		fields[k] = v
	}
	event.Fields = fields
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return emitNormalizedEvent(w.Writer, event)
	}
	select {
	case w.queue <- event:
		return nil
	default:
		w.fault("learning_queue_overflow")
		return emitNormalizedEvent(w.Writer, event)
	}
}

// run owns exact matching and persistence away from the reader. Shutdown drains the
// bounded queue before committing state and closing the summary sink.
func (w *learningOutput) run() {
	defer close(w.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	healthTick := time.NewTicker(30 * time.Second)
	defer healthTick.Stop()
	w.sampleHealth()
	for {
		select {
		case e := <-w.queue:
			w.process(e)
		case <-tick.C:
			for _, engine := range w.engines() {
				if engine != nil {
					if err := engine.Tick(); err != nil {
						fmt.Fprintf(os.Stderr, "behavior learning checkpoint: %v\n", err)
					}
				}
			}
		case <-healthTick.C:
			w.sampleHealth()
		case <-w.stop:
			for {
				select {
				case e := <-w.queue:
					w.process(e)
				default:
					for _, engine := range w.engines() {
						if engine != nil {
							if err := engine.Close(); err != nil {
								fmt.Fprintf(os.Stderr, "behavior learning close: %v\n", err)
							}
						}
					}
					w.closeSummary()
					return
				}
			}
		}
	}
}
func (w *learningOutput) sampleHealth() {
	if w.health != nil {
		healthy, lost := w.health()
		for _, engine := range w.engines() {
			if engine != nil {
				engine.Health(healthy, lost)
			}
		}
	}
}
func (w *learningOutput) process(e auditEvent) {
	engine := w.engine
	var observation behaviorlearning.Observation
	if e.EventType == "file_op" {
		engine = w.fileEngine
		observation = fileLearningObservation(e, w.backend, bootLearningID())
	} else {
		observation = execLearningObservation(e, w.backend, bootLearningID())
	}
	if err := engine.Process(observation); err != nil {
		fmt.Fprintf(os.Stderr, "behavior learning event output: %v\n", err)
	}
}

// engines are immutable after construction; the single worker owns transitions.
// Fault is atomic and may also be called by the source/overflow path.
func (w *learningOutput) engines() [2]*behaviorlearning.Engine {
	return [2]*behaviorlearning.Engine{w.engine, w.fileEngine}
}

func (w *learningOutput) fault(reason string) {
	for _, engine := range w.engines() {
		if engine != nil {
			engine.Fault(reason)
		}
	}
}

// execLearningObservation uses the normalized pre-redaction strings verbatim.
// Unique source IDs partition reboot/backend retries but never change the four
// behavior fields. Missing/truncated argv stays marked as incomplete evidence;
// the Linux exact policy learns the collected strings regardless of that marker.
func execLearningObservation(e auditEvent, backend, boot string) behaviorlearning.Observation {
	raw, _ := json.Marshal(e)
	complete := !e.CommandTruncated && e.Fields["learning_argv_complete"] == "yes"
	reason := ""
	if !complete {
		reason = "incomplete_or_truncated_command"
	}
	eventID := ""
	if boot != "" && e.AuditID != "" {
		eventID = backend + ":" + boot + ":" + e.AuditID + ":" + e.Fields["learning_source_time"]
	}
	return behaviorlearning.Observation{Context: behaviorlearning.Context{Exec: &behaviorlearning.ExecFields{
		ListenerProcess: e.ListenerProcess, PIDName: e.PIDName, Exe: e.Exe, CommandLine: e.CommandLine,
	}}, Complete: complete, Reason: reason, EventID: eventID, Raw: raw, At: e.Time}
}

var learningBootOnce sync.Once
var learningBootID string

func bootLearningID() string {
	learningBootOnce.Do(func() {
		b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
		learningBootID = strings.TrimSpace(string(b))
	})
	return learningBootID
}

// Close excludes new submissions before draining; the source workers must be
// joined before this is called, so no closed-channel race can lose an event.
func (w *learningOutput) Close() {
	w.mu.Lock()
	w.closed = true
	close(w.stop)
	w.mu.Unlock()
	<-w.done
}

// printLearningStatus bypasses audit setup and never contends for the writer lock.
func printLearningStatus(configPath, outputPath string) int {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return failf("learning config: %v", err)
	}
	c, err := behaviorlearning.DecodeExec(cfg.BehaviorLearning)
	if err != nil {
		return failf("learning config: %v", err)
	}
	c, err = c.Normalize()
	if err != nil {
		return failf("learning config: %v", err)
	}
	c = learningPaths(c, resolveOutputLog(outputPath, cfg.OutputLog))
	state, err := behaviorlearning.Inspect(c.StateDir, c.StateMB)
	if err != nil {
		return failf("learning state: %v", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(state); err != nil {
		return failf("learning status output: %v", err)
	}
	return 0
}

func learningFault(out io.Writer, reason string) {
	if w, ok := out.(*learningOutput); ok {
		w.fault(reason)
	}
}
