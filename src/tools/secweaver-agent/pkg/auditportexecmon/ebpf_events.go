package auditportexecmon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"secweaver-agent/pkg/processtracker"
	processtrackerebpf "secweaver-agent/pkg/processtracker/ebpf"
)

var processTrackerFactory processtracker.Factory = processtrackerebpf.Factory{}

func startConfiguredProcessTracker(ctx context.Context, cfg processTreeRuntimeConfig, monitorExec, activate bool) (string, processtracker.Tracker, string, error) {
	if !monitorExec {
		return cfg.FallbackBackend, nil, "process exec monitoring is disabled", nil
	}
	if cfg.Backend == processTreeBackendAudit || cfg.Backend == processTreeBackendAuditPID {
		return cfg.Backend, nil, "configured " + cfg.Backend + " backend", nil
	}
	probeErr := processTrackerFactory.Probe()
	if probeErr == nil {
		if !activate {
			return processTreeBackendEBPF, nil, "kernel capability probe succeeded (dry-run did not attach programs)", nil
		}
		tracker, err := processTrackerFactory.New(ctx, processtracker.Options{
			MaxTrackedProcesses:   cfg.MaxTrackedProcesses,
			PerfBufferBytesPerCPU: cfg.PerfBufferBytesPerCPU,
		})
		if err == nil {
			return processTreeBackendEBPF, tracker, "kernel capability probe and program attach succeeded", nil
		}
		probeErr = err
	}
	if cfg.Backend == processTreeBackendEBPF {
		return "", nil, "", fmt.Errorf("eBPF process tree backend is required but unavailable: %w", probeErr)
	}
	return cfg.FallbackBackend, nil, fmt.Sprintf("eBPF unavailable, fallback to %s: %v", cfg.FallbackBackend, probeErr), nil
}

// followProcessTracker consumes only backend-neutral events. Fork and exit keep
// userspace attribution synchronized; exec is serialized into the same stable
// JSON contract as audit-derived command events.
func followProcessTracker(ctx context.Context, tracker processtracker.Tracker, monitor *processTreeMonitor, host hostIdentity, out io.Writer) error {
	if tracker == nil {
		return nil
	}
	lostTicker := time.NewTicker(30 * time.Second)
	defer lostTicker.Stop()
	lastLost := uint64(0)
	events := tracker.Events()
	errorsChannel := tracker.Errors()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-errorsChannel:
			if !ok {
				errorsChannel = nil
				continue
			}
			if ok && err != nil {
				return err
			}
		case event, ok := <-events:
			if !ok {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fmt.Errorf("eBPF process event stream closed unexpectedly")
			}
			listener, owned := monitor.observeEBPFEvent(event)
			if event.Type != processtracker.EventExec || !owned || !monitor.shouldMonitorExec(listener) {
				continue
			}
			if err := emitEBPFExecEvent(event, listener, monitor.execKey, host, out); err != nil {
				return err
			}
		case <-lostTicker.C:
			lost := tracker.LostSamples()
			if lost > lastLost {
				fmt.Fprintf(os.Stderr, "eBPF process event buffer lost samples: delta=%d total=%d; scheduling process-tree reconciliation\n", lost-lastLost, lost)
				monitor.requestRescan()
				lastLost = lost
			}
		}
	}
}

func emitEBPFExecEvent(source processtracker.Event, listener listenerInfo, key string, host hostIdentity, out io.Writer) error {
	return emitEBPFExecEventWithContext(source, listener, key, host, out, readProcExecutionContext(int(source.PID)))
}

// emitEBPFExecEventWithContext keeps kernel lifecycle evidence separate from
// best-effort /proc enrichment. Short-lived processes may disappear before the
// reader runs; empty context therefore means unknown and must not synthesize a
// negative TTY assertion.
func emitEBPFExecEventWithContext(source processtracker.Event, listener listenerInfo, key string, host hostIdentity, out io.Writer, processContext processExecutionContext) error {
	command := append([]string(nil), source.Args...)
	if len(command) == 0 && source.Filename != "" {
		command = []string{source.Filename}
	}
	if len(command) == 0 && source.Comm != "" {
		command = []string{source.Comm}
	}
	if len(command) == 0 {
		return nil
	}
	pid := strconv.FormatUint(uint64(source.PID), 10)
	ppid := strconv.FormatUint(uint64(source.PPID), 10)
	uid := strconv.FormatUint(uint64(source.UID), 10)
	comm := normalizeComm(source.Comm, source.Filename)
	event := auditEvent{
		Time:             time.Now(),
		HostName:         host.HostName,
		HostIP:           host.HostIP,
		EventType:        "exec",
		AuditID:          fmt.Sprintf("ebpf:%d:%d", source.TimestampNS, source.PID),
		PID:              pid,
		PIDName:          comm,
		PPID:             ppid,
		PPIDName:         readProcComm(int(source.PPID)),
		UID:              uid,
		UIDName:          resolveAccountName(uid),
		AUID:             processContext.AUID,
		AUIDName:         resolveAccountName(processContext.AUID),
		Comm:             comm,
		Exe:              source.Filename,
		CWD:              processContext.CWD,
		Command:          command,
		CommandLine:      strings.Join(command, " "),
		CommandTruncated: source.ArgsTruncated,
		Success:          "yes",
		Key:              key,
		TTY:              processContext.TTY,
		HasTTY:           processContext.HasTTY,
		ListenerPID:      listener.PID,
		ListenerProcess:  listener.Process,
		ListenerAddress:  listener.Address,
		ListenerPort:     listener.Port,
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode eBPF exec event: %w", err)
	}
	if _, err := fmt.Fprintln(out, string(encoded)); err != nil {
		return fmt.Errorf("write eBPF exec event: %w", err)
	}
	return nil
}
