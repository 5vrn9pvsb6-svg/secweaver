package hostpersistence

import (
	"context"

	"encoding/json"

	"fmt"
	"io"
	"os"

	"strings"

	"time"

	agentoutput "secweaver-agent/pkg/output"
)

// This file coordinates polling and audit enrichment. It advances persisted state only after a complete scan and durable event checkpoint.

func run(ctx context.Context, cfg runtimeConfig, out io.Writer, st *stats) error {
	host := hostName()
	previous, stateExists, err := loadState(cfg.StatePath)
	if err != nil {
		return err
	}
	auditTracker, cleanupAudit, err := startAuditEnrichment(ctx, cfg)
	if err != nil {
		return err
	}
	defer cleanupAudit()
	enc := json.NewEncoder(out)

	for {
		auditTracker.RefreshWatches()
		now := time.Now().UTC()
		current, scanErrs := scanTargetsWithPrevious(cfg, previous)
		st.Scans++
		st.ScanErrors += scanErrs
		st.FilesTracked = len(current)

		if scanErrs > 0 {
			fmt.Fprintf(os.Stderr, "WARN: host persistence scan incomplete: errors=%d; preserving previous state\n", scanErrs)
			if cfg.Once {
				return fmt.Errorf("host persistence scan incomplete: errors=%d", scanErrs)
			}
		} else {
			var events []persistenceEvent
			if stateExists || cfg.EmitBaseline {
				events = diffStates(previous, current, !stateExists && cfg.EmitBaseline, host, cfg.HostIP, now, cfg, auditTracker)
			}
			for _, event := range events {
				if err := enc.Encode(event); err != nil {
					return err
				}
				st.EventsWritten++
			}
			stateChanged := !stateExists || !fileStatesEqual(previous, current)
			if len(events) > 0 {
				if err := agentoutput.Checkpoint(out); err != nil {
					return fmt.Errorf("checkpoint host persistence output: %w", err)
				}
			}
			if stateChanged {
				if err := saveState(cfg.StatePath, host, current, now); err != nil {
					return err
				}
			}
			previous = current
			stateExists = true
		}

		if cfg.Once {
			return nil
		}
		timer := time.NewTimer(cfg.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case auditErr := <-auditTracker.Errors():
			// Polling could continue without auditd, but doing so would silently
			// degrade actor attribution. Exit instead so the supervisor reattaches a
			// fresh shared audit stream and restarts the module with visible status.
			timer.Stop()
			return fmt.Errorf("host persistence audit reader stopped: %w", auditErr)
		case <-timer.C:
		}
	}
}

func fileStatesEqual(left, right map[string]fileState) bool {
	if len(left) != len(right) {
		return false
	}
	for path, leftState := range left {
		rightState, ok := right[path]
		if !ok || leftState != rightState {
			return false
		}
	}
	return true
}

func hostName() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "unknown"
	}
	return strings.TrimSpace(name)
}
