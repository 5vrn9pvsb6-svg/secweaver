package auditportexecmon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/layout"
)

// learningOutput is a semantic adapter, not a JSON-parsing generic writer.
// Ownership is bounded: one worker owns verification and queued events are deep
// copies. Overflow writes originals immediately and invalidates learning.
type learningOutput struct {
	io.Writer
	engine       *behaviorlearning.Engine
	verifier     *behaviorlearning.Verifier
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
	c, err := behaviorlearning.Decode(cfg.BehaviorLearning)
	if err != nil || !c.Enabled {
		return nil, err
	}
	c = learningPaths(c, eventPath)
	if filepath.Clean(c.OutputLog) == filepath.Clean(eventPath) {
		return nil, fmt.Errorf("learning summary and original logs must differ")
	}
	verifier, err := behaviorlearning.NewVerifier()
	if err != nil {
		return nil, err
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
	w := &learningOutput{Writer: out, verifier: verifier, queue: make(chan auditEvent, 128), stop: make(chan struct{}), done: make(chan struct{}), closeSummary: closeSummary, backend: backend, health: trackerHealth}
	w.engine, err = behaviorlearning.New(c, device, func(raw json.RawMessage) error { _, err := fmt.Fprintln(out, string(raw)); return err }, func(s behaviorlearning.Summary) error {
		b, err := json.Marshal(s)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(summary, string(b))
		return err
	})
	if err != nil {
		closeSummary()
		return nil, err
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

func (w *learningOutput) WriteEvent(event auditEvent) error {
	if event.EventType != "exec" {
		return emitNormalizedEvent(w.Writer, event)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(raw) > 65536 {
		w.engine.Fault("oversized_event")
		return emitNormalizedEvent(w.Writer, event)
	}
	// audit accumulators return to a pool immediately after this call.
	event.Command = append([]string(nil), event.Command...)
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
		w.engine.Fault("learning_queue_overflow")
		return emitNormalizedEvent(w.Writer, event)
	}
}

// run performs all /proc/hash work away from the reader. Shutdown drains the
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
			if err := w.engine.Tick(); err != nil {
				fmt.Fprintf(os.Stderr, "behavior learning checkpoint: %v\n", err)
			}
		case <-healthTick.C:
			w.sampleHealth()
		case <-w.stop:
			for {
				select {
				case e := <-w.queue:
					w.process(e)
				default:
					if err := w.engine.Close(); err != nil {
						fmt.Fprintf(os.Stderr, "behavior learning close: %v\n", err)
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
		w.engine.Health(healthy, lost)
	}
}
func (w *learningOutput) process(e auditEvent) {
	pid, _ := strconv.Atoi(e.PID)
	ppid, _ := strconv.Atoi(e.PPID)
	in := behaviorlearning.Execution{PID: pid, PPID: ppid, RootPID: e.ListenerPID, Exe: e.Exe, Args: e.Command, UID: e.UID, GID: e.Fields["gid"], EUID: e.Fields["euid"], EGID: e.Fields["egid"], AUID: e.AUID, CWD: e.CWD, Address: e.ListenerAddress, Port: e.ListenerPort, Success: e.Success == "yes", Truncated: e.CommandTruncated || e.Fields["learning_argv_complete"] != "yes", HasTTY: e.HasTTY, Backend: "audit"}
	if strings.HasPrefix(e.AuditID, "ebpf:") {
		in.Backend = "ebpf"
	}
	in.Inode = e.Fields["learning_inode"]
	in.Device = e.Fields["learning_dev"]
	in.SourceTime = e.Fields["learning_source_time"]
	in.StartBootNS, _ = strconv.ParseUint(e.Fields["learning_start_boot_ns"], 10, 64)
	ctx, instance, parent, reason := w.verifier.Verify(in)
	// Unknown children still recover available suppressed parent evidence.
	if parent == "" {
		parent = w.verifier.ParentInstance(ppid)
	}
	raw, _ := json.Marshal(e)
	// Audit IDs alone can repeat after reboot; the kernel boot identity is part of
	// the local source identifier even for events with incomplete /proc evidence.
	eventID := w.backend + ":" + bootLearningID() + ":" + e.AuditID + ":" + in.SourceTime
	if err := w.engine.Process(behaviorlearning.Observation{Context: ctx, Complete: reason == "", Reason: reason, EventID: eventID, Instance: instance, ParentInstance: parent, Raw: raw, At: e.Time}); err != nil {
		fmt.Fprintf(os.Stderr, "behavior learning event output: %v\n", err)
	}
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
	c, err := behaviorlearning.Decode(cfg.BehaviorLearning)
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
		w.engine.Fault(reason)
	}
}
