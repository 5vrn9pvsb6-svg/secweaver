package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/agentupdate"
	"secweaver-agent/pkg/metrics"
)

var checkAndRegisterAgentLicense = func(ctx context.Context, cfg agentlicense.Config, enterpriseID, agentVersion string) (agentlicense.Result, error) {
	return (agentlicense.Client{}).CheckAndRegister(ctx, cfg, enterpriseID, agentVersion)
}

const (
	initialLicenseRetryDelay = 5 * time.Second
	maximumLicenseRetryDelay = 5 * time.Minute
)

// checkAgentLicense records the raw control-plane attempt before applying cached
// outage grace. Collection may continue on cache while the success gauge remains
// zero, preserving the distinction between authorization and connectivity.
func checkAgentLicense(ctx context.Context, cfg agentlicense.Config, enterpriseID string, tracker *statusTracker, metricsExporter *metrics.Exporter) error {
	if !cfg.Enabled {
		if metricsExporter != nil {
			metricsExporter.UpdateLicenseMetrics(metrics.LicenseMetrics{Enabled: false})
		}
		if tracker != nil {
			tracker.licenseCheck(agentlicense.Result{}, nil)
		}
		return nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	result, err := checkAndRegisterAgentLicense(checkCtx, cfg, enterpriseID, version)
	if metricsExporter != nil {
		metricsExporter.UpdateLicenseMetrics(metrics.LicenseMetrics{Enabled: true, LastCheckSuccess: err == nil})
	}
	if tracker != nil {
		tracker.licenseCheck(result, err)
	}
	if err != nil {
		var denied agentlicense.DeniedError
		if errors.As(err, &denied) {
			return err
		}
		if !cfg.FailClosedEnabled() {
			fmt.Fprintf(os.Stderr, "license check warning: %v; continuing because fail_closed=false\n", err)
			return nil
		}
		if agentlicense.IsTransient(err) {
			if remaining, ok := cachedAuthorizationGraceRemaining(result.State, cfg, time.Now()); ok {
				fmt.Fprintf(os.Stderr, "license check degraded: %v; continuing with cached authorization for up to %s\n", err, remaining.Round(time.Second))
				return nil
			}
		}
		return err
	}
	fmt.Fprintf(os.Stderr, "license ok: devices=%d/%d expires_at=%s device_id=%s\n",
		result.Response.UsedDevices,
		result.Response.MaxDevices,
		valueOrDash(result.Response.SubscriptionExpiresAt),
		result.State.DeviceID,
	)
	return nil
}

// waitForInitialAgentLicense keeps a correctly configured service alive while
// DNS, routing, or the control plane is temporarily unavailable. Authorization
// denials and other permanent errors still fail immediately; retrying those
// forever would hide operator action that is required before collection can run.
func waitForInitialAgentLicense(ctx context.Context, cfg agentlicense.Config, enterpriseID string, tracker *statusTracker, metricsExporter *metrics.Exporter, initialDelay, maximumDelay time.Duration) error {
	if initialDelay <= 0 {
		initialDelay = initialLicenseRetryDelay
	}
	if maximumDelay < initialDelay {
		maximumDelay = initialDelay
	}
	delay := initialDelay
	failures := 0
	for {
		err := checkAgentLicense(ctx, cfg, enterpriseID, tracker, metricsExporter)
		if err == nil {
			return nil
		}
		if !agentlicense.IsTransient(err) {
			return err
		}
		failures++
		jitter := stableJitter(delay/4, fmt.Sprintf("%s|startup-license|%d", licenseJitterSeed(cfg, enterpriseID), failures))
		wait := delay + jitter
		if wait > maximumDelay {
			wait = maximumDelay
		}
		fmt.Fprintf(os.Stderr, "initial license check unavailable; retrying in %s: %v\n", wait, err)
		if !sleepContext(ctx, wait) {
			return ctx.Err()
		}
		if delay < maximumDelay {
			delay *= 2
			if delay > maximumDelay {
				delay = maximumDelay
			}
		}
	}
}

func cachedAuthorizationGraceRemaining(state agentlicense.State, cfg agentlicense.Config, now time.Time) (time.Duration, bool) {
	grace := cfg.OutageGracePeriod()
	if grace <= 0 || strings.TrimSpace(state.DeviceID) == "" || strings.TrimSpace(state.RegisteredAt) == "" {
		return 0, false
	}
	lastCheck, err := time.Parse(time.RFC3339, strings.TrimSpace(state.LastCheckAt))
	if err != nil || lastCheck.After(now.Add(5*time.Minute)) {
		return 0, false
	}
	remaining := lastCheck.Add(grace).Sub(now)
	if expiresAt := strings.TrimSpace(state.SubscriptionExpiresAt); expiresAt != "" {
		subscriptionDeadline, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil || !subscriptionDeadline.After(now) {
			return 0, false
		}
		if subscriptionRemaining := subscriptionDeadline.Sub(now); subscriptionRemaining < remaining {
			remaining = subscriptionRemaining
		}
	}
	return remaining, remaining > 0
}

// runScheduledLicenseChecker reuses the startup authorization path so status,
// counters, denial handling, and outage grace cannot diverge over time.
func runScheduledLicenseChecker(ctx context.Context, cfg agentlicense.Config, enterpriseID string, tracker *statusTracker, metricsExporter *metrics.Exporter) error {
	interval := time.Duration(cfg.CheckIntervalSeconds) * time.Second
	if interval <= 0 {
		return nil
	}
	initialWait := stableJitter(10*time.Minute, licenseJitterSeed(cfg, enterpriseID)+"|license-check")
	if initialWait > 0 {
		fmt.Fprintf(os.Stderr, "scheduled license check enabled: interval=%s initial_wait=%s\n", interval, initialWait)
		if !sleepContext(ctx, initialWait) {
			return nil
		}
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	nextWait := interval
	retryDelay := initialLicenseRetryDelay
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			if err := checkAgentLicense(ctx, cfg, enterpriseID, tracker, metricsExporter); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				if !agentlicense.IsTransient(err) {
					return err
				}
				nextWait = retryDelay + stableJitter(retryDelay/4, licenseJitterSeed(cfg, enterpriseID)+"|scheduled-license-retry")
				retryDelay = controlPlaneBackoff(retryDelay, initialLicenseRetryDelay, maximumLicenseRetryDelay)
				fmt.Fprintf(os.Stderr, "scheduled license check unavailable; retrying in %s: %v\n", nextWait, err)
			} else {
				nextWait = interval
				retryDelay = initialLicenseRetryDelay
			}
			timer.Reset(nextWait)
		}
	}
}

// runScheduledHeartbeat publishes each raw request outcome before applying retry
// backoff. A denied heartbeat still terminates supervision; transient failures
// remain visible while the loop backs off up to its configured ceiling.
func runScheduledHeartbeat(ctx context.Context, cfg agentlicense.Config, enterpriseID string, tracker *statusTracker, updater *scheduledUpdateConfig, updatePolicies chan agentlicense.UpdatePolicy, metricsExporter *metrics.Exporter) error {
	interval := time.Duration(cfg.HeartbeatSeconds) * time.Second
	if interval <= 0 {
		return nil
	}
	initialWait := stableJitter(interval, licenseJitterSeed(cfg, enterpriseID)+"|heartbeat")
	if updater != nil && updater.HealthCheckPending {
		initialWait = 0
	}
	if initialWait > 0 {
		fmt.Fprintf(os.Stderr, "license heartbeat enabled: interval=%s initial_wait=%s\n", interval, initialWait)
		if !sleepContext(ctx, initialWait) {
			return nil
		}
	}
	nextWait := interval
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			var modules map[string]agentlicense.ModuleHealth
			if tracker != nil {
				modules = tracker.moduleSnapshot()
			}
			resp, err := (agentlicense.Client{}).HeartbeatWithUpdate(
				checkCtx,
				cfg,
				enterpriseID,
				version,
				modules,
				updateHeartbeatReport(updater),
			)
			cancel()
			if metricsExporter != nil {
				metricsExporter.RecordHeartbeat(err == nil)
			}
			if err != nil {
				if tracker != nil {
					tracker.heartbeat(err)
				}
				var denied agentlicense.DeniedError
				if errors.As(err, &denied) {
					return fmt.Errorf("license heartbeat denied: %w", err)
				}
				fmt.Fprintf(os.Stderr, "license heartbeat unavailable; Agent remains active and will reconnect: %v\n", err)
				nextWait = heartbeatBackoff(nextWait, interval)
			} else {
				if tracker != nil {
					tracker.heartbeat(nil)
				}
				fmt.Fprintf(os.Stderr, "license heartbeat ok: devices=%d/%d expires_at=%s\n",
					resp.UsedDevices,
					resp.MaxDevices,
					valueOrDash(resp.SubscriptionExpiresAt),
				)
				nextWait = interval
				if resp.UpdatePolicy != nil && updatePolicies != nil {
					select {
					case <-updatePolicies:
					default:
					}
					select {
					case updatePolicies <- *resp.UpdatePolicy:
					default:
					}
				}
			}
			timer.Reset(nextWait)
		}
	}
}

func updateHeartbeatReport(updater *scheduledUpdateConfig) *agentlicense.UpdateReport {
	if updater == nil {
		return nil
	}
	state, err := agentupdate.LoadState(updater.Options.StateDir)
	if err != nil {
		return &agentlicense.UpdateReport{CurrentVersion: version, Status: "state_read_failed", LastError: err.Error()}
	}
	currentVersion := state.CurrentVersion
	if strings.TrimSpace(currentVersion) == "" {
		currentVersion = version
	}
	return &agentlicense.UpdateReport{
		CurrentVersion:     currentVersion,
		TargetVersion:      state.TargetVersion,
		LatestVersion:      state.LatestVersion,
		Status:             state.LastUpdateStatus,
		LastCheckAt:        state.LastCheckAt,
		LastUpdateAt:       state.LastUpdateAt,
		LastError:          state.LastError,
		HealthPending:      state.HealthPending,
		HealthDeadline:     state.HealthDeadline,
		RollbackReason:     state.RollbackReason,
		AttemptID:          state.AttemptID,
		CampaignID:         state.CampaignID,
		PolicyRevision:     state.PolicyRevision,
		FailureClass:       state.FailureClass,
		Retryable:          state.Retryable,
		NextRetryAt:        state.NextRetryAt,
		ManifestGeneration: state.ManifestGeneration,
	}
}

func heartbeatBackoff(current, base time.Duration) time.Duration {
	return controlPlaneBackoff(current, base, 15*time.Minute)
}

// controlPlaneBackoff is shared by heartbeat and authorization retry loops so
// both recover without synchronized request storms or unbounded retry delays.
func controlPlaneBackoff(current, base, maximum time.Duration) time.Duration {
	if current < base {
		current = base
	}
	next := current * 2
	if next > maximum {
		return maximum
	}
	return next
}

func licenseJitterSeed(cfg agentlicense.Config, enterpriseID string) string {
	return enterpriseID + "|" + cfg.EnrollmentID + "|" + cfg.StatePath
}
