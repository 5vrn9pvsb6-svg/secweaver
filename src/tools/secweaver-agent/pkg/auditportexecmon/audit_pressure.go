package auditportexecmon

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"
)

func startAuditPressureMonitor(ctx context.Context, monitor *processTreeMonitor, cfg auditPressureRuntimeConfig) func() {
	// Pressure sampling runs independently from audit-log consumption. Invalid
	// or failed samples never count as recovery; otherwise a broken auditctl -s
	// call could incorrectly re-enable expensive rule expansion.
	if monitor == nil || !cfg.Enabled {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(cfg.CheckInterval)
		defer ticker.Stop()
		lastLost := -1
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				status, err := collectAuditStatus()
				if err != nil {
					fmt.Fprintf(os.Stderr, "audit pressure status check failed: %v\n", err)
					continue
				}
				backlog, backlogErr := strconv.Atoi(status["backlog"])
				limit, limitErr := strconv.Atoi(status["backlog_limit"])
				lost, lostErr := strconv.Atoi(status["lost"])
				if backlogErr != nil || limitErr != nil || lostErr != nil || limit <= 0 || backlog < 0 || lost < 0 {
					fmt.Fprintf(os.Stderr, "audit pressure status invalid: backlog=%q backlog_limit=%q lost=%q\n", status["backlog"], status["backlog_limit"], status["lost"])
					continue
				}
				lostDelta := 0
				if lastLost >= 0 && lost >= lastLost {
					lostDelta = lost - lastLost
				} else if lastLost >= 0 {
					fmt.Fprintf(os.Stderr, "audit lost counter reset: previous=%d current=%d\n", lastLost, lost)
				}
				level := classifyAuditPressure(backlog, limit, lostDelta, cfg)
				reason := fmt.Sprintf("backlog=%d/%d lost_delta=%d total_lost=%d", backlog, limit, lostDelta, lost)
				monitor.updateAuditPressure(level, cfg.Cooldown, reason, time.Now())
				lastLost = lost
			}
		}
	}()
	fmt.Fprintf(os.Stderr, "audit pressure adaptive mode enabled: interval=%s backlog=%d/%d/%d%% lost_delta=%d/%d/%d rate_limit=%d/%d recovery=%d cooldown=%s\n",
		cfg.CheckInterval,
		cfg.BacklogHighPercent, cfg.MediumBacklogPercent, cfg.SevereBacklogPercent,
		cfg.LostDelta, cfg.MediumLostDelta, cfg.SevereLostDelta,
		cfg.LightRateLimitPerSecond, cfg.MediumRateLimitPerSecond, cfg.RecoveryRateLimitPerSecond,
		cfg.Cooldown)
	return func() {
		cancel()
		<-done
	}
}

// classifyAuditPressure maps both queue saturation and newly lost records to a
// single monotonic severity. A lost delta can escalate immediately even when the
// sampled backlog has already drained.
func classifyAuditPressure(backlog, limit, lostDelta int, cfg auditPressureRuntimeConfig) auditPressureLevel {
	backlogPercent := 0
	if limit > 0 && backlog > 0 {
		backlogPercent = backlog * 100 / limit
	}
	switch {
	case backlogPercent >= cfg.SevereBacklogPercent || lostDelta >= cfg.SevereLostDelta:
		return auditPressureSevere
	case backlogPercent >= cfg.MediumBacklogPercent || lostDelta >= cfg.MediumLostDelta:
		return auditPressureMedium
	case backlogPercent >= cfg.BacklogHighPercent || lostDelta >= cfg.LostDelta:
		return auditPressureLight
	default:
		return auditPressureNormal
	}
}
