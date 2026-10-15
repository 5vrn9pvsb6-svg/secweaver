package auditportexecmon

import (
	"context"
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

// startConfiguredProcessTracker honors explicit backends and verifies actual
// attach before returning an active tracker. Auto fallback is allowed only
// when the product mode still has an available Audit transport.
func startConfiguredProcessTracker(ctx context.Context, cfg processTreeRuntimeConfig, monitorExec, activate bool) (string, processtracker.Tracker, string, error) {
	if cfg.CollectionMode == auditCollectionModeEBPFOnly {
		// eBPF-only is a product contract, not a best-effort process-tree hint.
		// Force the embedded tracker and reject an audit fallback so a host with
		// audit=0 cannot appear healthy while silently collecting nothing.
		if !monitorExec {
			return "", nil, "", fmt.Errorf("eBPF-only mode requires exec.monitor=true")
		}
		cfg.Backend = processTreeBackendEBPF
	}
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
	if cfg.Backend == processTreeBackendEBPF || cfg.CollectionMode == auditCollectionModeEBPFOnly {
		return "", nil, "", fmt.Errorf("eBPF process tree backend is required but unavailable: %w", probeErr)
	}
	return cfg.FallbackBackend, nil, fmt.Sprintf("eBPF unavailable, fallback to %s: %v", cfg.FallbackBackend, probeErr), nil
}

// followEBPFOnly keeps listener reconciliation alive without opening audit.log.
// The tracker remains the sole event producer; the bounded ticker only repairs
// process ownership after lost perf samples or listener replacement.
func followEBPFOnly(ctx context.Context, tracker processtracker.Tracker, monitor *processTreeMonitor, host hostIdentity, out io.Writer, rescanInterval time.Duration) error {
	if tracker == nil {
		return fmt.Errorf("eBPF-only mode started without an eBPF tracker")
	}
	if rescanInterval <= 0 {
		rescanInterval = defaultListenerRescanInterval
	}
	rescanCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	go func() {
		defer close(done)
		ticker := time.NewTicker(rescanInterval)
		defer ticker.Stop()
		for {
			select {
			case <-rescanCtx.Done():
				return
			case <-ticker.C:
				monitor.requestRescan()
			}
		}
	}()
	return followProcessTracker(rescanCtx, tracker, monitor, host, out)
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
			if event.Type != processtracker.EventExec || !owned || listener.AttributionUnknown || !monitor.shouldMonitorExec(listener) {
				continue
			}
			if err := emitEBPFExecEvent(event, listener, monitor.execKey, host, out); err != nil {
				return err
			}
		case <-lostTicker.C:
			monitor.logAttributionStats(false)
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
// negative TTY assertion. The owner must be verified live or restored from a
// bounded, generation/time-checked historical root; otherwise output is rejected.
func emitEBPFExecEventWithContext(source processtracker.Event, listener listenerInfo, key string, host hostIdentity, out io.Writer, processContext processExecutionContext) error {
	if listener.AttributionUnknown || strings.TrimSpace(listener.Process) == "" {
		return nil
	}
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
	// Parent evidence survives process exit and PID reuse. Never replace a
	// missing snapshot with the current /proc/<ppid>/comm: that can name an
	// unrelated replacement. Service ownership stays independently validated.
	event.ParentIdentityStatus = "unavailable"
	event.PPIDExeStatus = "unavailable"
	if source.PPID == 0 {
		event.PPID = ""
	}
	if parent := source.Parent; parent != nil {
		event.PPIDName, event.PPIDExe = parent.Comm, parent.Exe
		event.PPIDStartBootNS, event.PPIDExeStatus = parent.StartBootNS, parent.ExeStatus
		event.ParentIdentityStatus = "partial"
		if parent.Comm != "" && parent.StartBootNS != 0 && parent.ExeStatus == "captured" && parent.Exe != "" {
			event.ParentIdentityStatus = "complete"
		}
	}
	// Identity enrichment remains best effort. Exact-command learning uses argv
	// completeness independently; short-lived processes need no /proc identity.
	if source.IdentityValid {
		event.AUID = strconv.FormatUint(uint64(source.AUID), 10)
		event.AUIDName = resolveAccountName(event.AUID)
		event.Fields = map[string]string{
			"euid":                   strconv.FormatUint(uint64(source.EUID), 10),
			"gid":                    strconv.FormatUint(uint64(source.GID), 10),
			"egid":                   strconv.FormatUint(uint64(source.EGID), 10),
			"learning_inode":         strconv.FormatUint(source.ExecutableInode, 10),
			"learning_dev":           fmt.Sprintf("%x:%x", source.ExecutableDev>>20, source.ExecutableDev&((1<<20)-1)),
			"learning_start_boot_ns": strconv.FormatUint(source.StartBootNS, 10),
		}
	}
	if !source.ArgsTruncated && len(source.Args) > 0 {
		if event.Fields == nil {
			event.Fields = make(map[string]string)
		}
		event.Fields["learning_argv_complete"] = "yes"
	}
	return emitNormalizedEvent(out, event)
}
