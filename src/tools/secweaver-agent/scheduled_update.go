package main

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/agentupdate"
	"secweaver-agent/pkg/metrics"
)

var errRestartAfterUpdate = errors.New("secweaver-agent update installed; restart required")

const managedUpdateLeaseSafetyMargin = 3 * time.Minute

// runScheduledUpdater records only actual manifest/install attempts as counter
// activity; policy-deferred cycles update the status gauge without pretending an
// update request occurred.
func runScheduledUpdater(ctx context.Context, cfg scheduledUpdateConfig, policies <-chan agentlicense.UpdatePolicy, metricsExporter *metrics.Exporter) error {
	statusOut, closeStatus, err := agentupdate.OpenStatusOutput(cfg.StatusOutput)
	if err != nil {
		return fmt.Errorf("open scheduled update status output: %w", err)
	}
	defer closeStatus()

	cfg.Options = normalizeUpdateOptions(cfg.Options)
	initialWait := cfg.InitialDelay + stableJitter(cfg.Jitter, cfg.Options.DeviceID+"|"+cfg.Options.Channel+"|"+version)
	if initialWait > 0 {
		fmt.Fprintf(os.Stderr, "scheduled update enabled: manifest=%s channel=%s interval=%s initial_wait=%s auto_install=%v\n",
			cfg.Options.ManifestURL, cfg.Options.Channel, cfg.Interval, initialWait, cfg.AutoInstall)
		if !sleepContext(ctx, initialWait) {
			return nil
		}
	}

	var policy *agentlicense.UpdatePolicy
	consecutiveFailures := 0
	for {
		if cfg.RequireServerPolicy && policy == nil {
			fmt.Fprintln(os.Stderr, "scheduled update waiting for Data Cloud policy")
			select {
			case <-ctx.Done():
				return nil
			case next, ok := <-policies:
				if !ok {
					return errors.New("Data Cloud update policy channel closed")
				}
				policy = &next
			}
		}
		effective, allowed, deferred := applyUpdatePolicy(cfg, policy)
		status, err := deferred, error(nil)
		var nextPolicy *agentlicense.UpdatePolicy
		attempted := false
		if allowed {
			attempted = true
			status, err, nextPolicy = runScheduledUpdateOnce(ctx, effective, policies)
		}
		if metricsExporter != nil {
			metricsExporter.UpdateUpdateStatus(status.CurrentVersion, status.LatestVersion, status.Status)
			if attempted {
				metricsExporter.RecordUpdateAttempt(err == nil && status.Status != "failed")
			}
		}
		if writeErr := agentupdate.WriteStatus(statusOut, status); writeErr != nil {
			fmt.Fprintf(os.Stderr, "write scheduled update status failed: %v\n", writeErr)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "scheduled update failed: %v\n", err)
		}
		if updateRequiresRestart(status) {
			return errRestartAfterUpdate
		}
		if nextPolicy != nil {
			policy = nextPolicy
			continue
		}
		wait := cfg.Interval
		if err != nil || status.Status == "failed" {
			consecutiveFailures++
			wait = scheduledUpdateRetryDelay(cfg, consecutiveFailures, err)
			if recordErr := agentupdate.RecordScheduledFailure(
				effective.Options,
				status,
				err,
				time.Now().Add(wait),
			); recordErr != nil {
				fmt.Fprintf(os.Stderr, "record scheduled update retry failed: %v\n", recordErr)
			}
			fmt.Fprintf(os.Stderr, "scheduled update will retry in %s after %d consecutive failure(s)\n", wait, consecutiveFailures)
		} else {
			consecutiveFailures = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case next, ok := <-policies:
			if !timer.Stop() {
				<-timer.C
			}
			if !ok {
				if cfg.RequireServerPolicy {
					return errors.New("Data Cloud update policy channel closed")
				}
				policies = nil
				continue
			}
			policy = &next
		case <-timer.C:
		}
	}
}

func applyUpdatePolicy(cfg scheduledUpdateConfig, policy *agentlicense.UpdatePolicy) (scheduledUpdateConfig, bool, agentupdate.Status) {
	if !cfg.RequireServerPolicy {
		return cfg, true, agentupdate.Status{}
	}
	status := policyDeferredStatus(cfg.Options, "server_policy_missing")
	if policy == nil {
		return cfg, false, status
	}
	if !policy.Enabled {
		status.Reason = firstUpdatePolicyValue(policy.Reason, "server_policy_disabled")
		return cfg, false, status
	}
	if policy.Paused {
		status.Reason = firstUpdatePolicyValue(policy.Reason, "rollout_paused")
		return cfg, false, status
	}
	if policy.MaintenanceWindowOpen != nil && !*policy.MaintenanceWindowOpen {
		status.Reason = firstUpdatePolicyValue(policy.Reason, "outside_maintenance_window")
		return cfg, false, status
	}
	if !policy.Eligible {
		status.Reason = firstUpdatePolicyValue(policy.Reason, "device_not_in_rollout")
		return cfg, false, status
	}
	if !policy.AutoInstall {
		status.Reason = firstUpdatePolicyValue(policy.Reason, "automatic_install_disabled")
		return cfg, false, status
	}
	if strings.TrimSpace(policy.TargetVersion) == "" {
		status.Reason = "server_policy_missing_target_version"
		return cfg, false, status
	}
	if policy.LeaseGranted == nil {
		status.Reason = "server_policy_missing_update_lease"
		return cfg, false, status
	}
	if !*policy.LeaseGranted {
		status.Reason = firstUpdatePolicyValue(policy.Reason, "concurrent_update_limit_reached")
		return cfg, false, status
	}
	leaseExpiresAt, reason := managedUpdateLease(policy.LeaseExpiresAt, time.Now())
	if reason != "" {
		status.Reason = reason
		return cfg, false, status
	}
	cfg.PolicyLeaseExpiresAt = leaseExpiresAt
	if manifestURL := strings.TrimSpace(policy.ManifestURL); manifestURL != "" {
		parsed, err := url.Parse(manifestURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			status.Reason = "server_policy_invalid_manifest_url"
			return cfg, false, status
		}
		cfg.Options.ManifestURL = manifestURL
	}
	if channel := strings.TrimSpace(policy.Channel); channel != "" {
		cfg.Options.Channel = channel
	}
	cfg.Options.DesiredVersion = strings.TrimSpace(policy.TargetVersion)
	cfg.Options.ServerManaged = true
	cfg.Options.CampaignID = strings.TrimSpace(policy.CampaignID)
	cfg.Options.PolicyRevision = policy.PolicyRevision
	cfg.Options.AllowDowngrade = policy.AllowDowngrade
	cfg.Options.PolicyRollbackReason = strings.TrimSpace(policy.RollbackReason)
	return cfg, true, status
}

func firstUpdatePolicyValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func managedUpdateLease(value string, now time.Time) (time.Time, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, "server_policy_missing_lease_expiry"
	}
	expiresAt, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, "server_policy_invalid_lease_expiry"
	}
	if !expiresAt.After(now.Add(managedUpdateLeaseSafetyMargin)) {
		return time.Time{}, "server_policy_lease_expiring"
	}
	return expiresAt, ""
}

func policyDeferredStatus(opts agentupdate.Options, reason string) agentupdate.Status {
	return agentupdate.Status{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		EventType:      "secweaver_agent_update_policy",
		Status:         "policy_deferred",
		Reason:         reason,
		App:            "secweaver-agent",
		Channel:        opts.Channel,
		Platform:       runtime.GOOS + "_" + runtime.GOARCH,
		CurrentVersion: opts.CurrentVersion,
		DeviceID:       opts.DeviceID,
		HostID:         opts.HostID,
		ManifestURL:    opts.ManifestURL,
	}
}

func bindUpdateRuntimeToDevice(updater *scheduledUpdateConfig, licenseCfg agentlicense.Config) error {
	if updater == nil {
		return nil
	}
	if updater.RequireServerPolicy {
		if !licenseCfg.Enabled || !licenseCfg.DeviceAuthEnabled() || licenseCfg.HeartbeatSeconds <= 0 {
			return errors.New("update.require_server_policy requires license protocol device_v2 with heartbeat enabled")
		}
	}
	state, err := agentlicense.LoadState(licenseCfg.StatePath)
	if err != nil {
		return fmt.Errorf("load device identity for update rollout: %w", err)
	}
	if strings.TrimSpace(state.DeviceID) != "" {
		updater.Options.DeviceID = state.DeviceID
		updater.Options.HostID = state.DeviceID
	} else if updater.RequireServerPolicy {
		return errors.New("update.require_server_policy requires an enrolled immutable device_id; run secweaver-agent enroll first")
	}
	return nil
}

func prepareUpdateActivation(updater *scheduledUpdateConfig) error {
	if updater == nil {
		return nil
	}
	pending, status, err := agentupdate.PrepareHealthCheck(updater.Options, updater.HealthTimeout)
	if err != nil {
		return fmt.Errorf("prepare update health check: %w", err)
	}
	updater.HealthCheckPending = pending
	if updateRequiresRestart(status) {
		return errRestartAfterUpdate
	}
	return nil
}

// runUpdateHealthMonitor publishes the terminal probation result before asking
// the service manager to activate a rollback, so the last scrape explains why
// this process generation exited.
func runUpdateHealthMonitor(ctx context.Context, cfg scheduledUpdateConfig, tracker *statusTracker, metricsExporter *metrics.Exporter) error {
	if !cfg.HealthCheckPending {
		return nil
	}
	if !sleepContext(ctx, cfg.HealthTimeout) {
		return nil
	}
	healthStartedAt := time.Now().Add(-cfg.HealthTimeout - time.Second)
	if state, err := agentupdate.LoadState(cfg.Options.StateDir); err == nil {
		if parsed, parseErr := time.Parse(time.RFC3339, state.HealthStartedAt); parseErr == nil {
			healthStartedAt = parsed
		}
	}
	if tracker != nil && tracker.allModulesHealthySince(healthStartedAt) {
		if _, err := agentupdate.MarkHealthy(cfg.Options); err != nil {
			return fmt.Errorf("confirm updated Agent health: %w", err)
		}
		if metricsExporter != nil {
			metricsExporter.UpdateUpdateStatus(cfg.Options.CurrentVersion, "", "healthy")
		}
		fmt.Fprintf(os.Stderr, "Agent update %s passed the %s health check\n", cfg.Options.CurrentVersion, cfg.HealthTimeout)
		return nil
	}
	status, err := agentupdate.RollbackForReason(cfg.Options, "module_health_check_failed")
	if err != nil {
		if metricsExporter != nil {
			metricsExporter.UpdateUpdateStatus(cfg.Options.CurrentVersion, "", "rollback_failed")
		}
		return fmt.Errorf("automatic rollback after failed health check: %w", err)
	}
	if metricsExporter != nil {
		metricsExporter.UpdateUpdateStatus(status.CurrentVersion, status.LatestVersion, status.Status)
	}
	if updateRequiresRestart(status) {
		return errRestartAfterUpdate
	}
	return errors.New("updated Agent failed health check")
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func runScheduledUpdateOnce(ctx context.Context, cfg scheduledUpdateConfig, policies <-chan agentlicense.UpdatePolicy) (agentupdate.Status, error, *agentlicense.UpdatePolicy) {
	if cfg.AutoInstall {
		status, err := agentupdate.Check(cfg.Options)
		if err != nil || status.Status != "update_available" {
			return status, err, nil
		}
		if status.DownloadDelay != nil && *status.DownloadDelay > 0 {
			timer := time.NewTimer(time.Duration(*status.DownloadDelay) * time.Second)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return status, nil, nil
			case next, ok := <-policies:
				if !timer.Stop() {
					<-timer.C
				}
				if ok {
					status.Status = "policy_deferred"
					status.Reason = "server_policy_changed_before_install"
					return status, nil, &next
				}
				if cfg.RequireServerPolicy {
					return status, errors.New("Data Cloud update policy channel closed"), nil
				}
			case <-timer.C:
			}
		}
		if cfg.RequireServerPolicy {
			select {
			case next, ok := <-policies:
				if !ok {
					return status, errors.New("Data Cloud update policy channel closed"), nil
				}
				status.Status = "policy_deferred"
				status.Reason = "server_policy_changed_before_install"
				return status, nil, &next
			default:
			}
			if _, reason := managedUpdateLease(cfg.PolicyLeaseExpiresAt.Format(time.RFC3339), time.Now()); reason != "" {
				status.Status = "policy_deferred"
				status.Reason = reason
				return status, nil, nil
			}
		}
		opts := cfg.Options
		opts.SkipDownloadDelay = true
		if !cfg.RequireServerPolicy {
			status, err = agentupdate.Install(opts)
			return status, err, nil
		}
		return installWithManagedPolicy(ctx, cfg, opts, policies)
	}
	status, err := agentupdate.Check(cfg.Options)
	return status, err, nil
}

type managedInstallResult struct {
	status agentupdate.Status
	err    error
}

// managedInstallCommitGate defines the only point after which a server-side
// policy change may no longer interrupt a local binary transaction.
type managedInstallCommitGate struct {
	mu            sync.Mutex
	revoked       bool
	commitStarted bool
	reason        string
}

func (g *managedInstallCommitGate) begin(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if g.revoked {
		return fmt.Errorf("managed update approval revoked: %s", g.reason)
	}
	g.commitStarted = true
	return nil
}

func (g *managedInstallCommitGate) revoke(reason string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.commitStarted {
		return false
	}
	g.revoked = true
	g.reason = reason
	return true
}

func installWithManagedPolicy(
	ctx context.Context,
	cfg scheduledUpdateConfig,
	opts agentupdate.Options,
	policies <-chan agentlicense.UpdatePolicy,
) (agentupdate.Status, error, *agentlicense.UpdatePolicy) {
	installCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	opts.Context = installCtx
	gate := &managedInstallCommitGate{}
	opts.CommitGuard = gate.begin
	result := make(chan managedInstallResult, 1)
	go func() {
		status, err := agentupdate.Install(opts)
		result <- managedInstallResult{status: status, err: err}
	}()

	leaseTimer := time.NewTimer(timeUntilManagedLeaseDeadline(cfg.PolicyLeaseExpiresAt))
	defer leaseTimer.Stop()
	for {
		select {
		case completed := <-result:
			return completed.status, completed.err, nil
		case <-ctx.Done():
			if gate.revoke("Agent shutdown") {
				cancel()
			}
			completed := <-result
			if completed.status.CommitStarted {
				return completed.status, completed.err, nil
			}
			return completed.status, nil, nil
		case <-leaseTimer.C:
			if gate.revoke("server policy lease expired") {
				cancel()
			}
			completed := <-result
			if completed.status.CommitStarted {
				return completed.status, completed.err, nil
			}
			completed.status.Status = "policy_deferred"
			completed.status.Reason = "server_policy_lease_expired_during_install"
			return completed.status, nil, nil
		case next, ok := <-policies:
			if !ok {
				if gate.revoke("server policy channel closed") {
					cancel()
				}
				completed := <-result
				if completed.status.CommitStarted {
					return completed.status, completed.err, nil
				}
				if cfg.RequireServerPolicy {
					return completed.status, errors.New("Data Cloud update policy channel closed"), nil
				}
				return completed.status, completed.err, nil
			}
			if !sameManagedUpdateApproval(opts, next) {
				if gate.revoke("server policy changed") {
					cancel()
				}
				completed := <-result
				if completed.status.CommitStarted {
					return completed.status, completed.err, &next
				}
				completed.status.Status = "policy_deferred"
				completed.status.Reason = "server_policy_changed_during_install"
				return completed.status, nil, &next
			}
			if expiresAt, reason := managedUpdateLease(next.LeaseExpiresAt, time.Now()); reason == "" {
				if !leaseTimer.Stop() {
					select {
					case <-leaseTimer.C:
					default:
					}
				}
				leaseTimer.Reset(timeUntilManagedLeaseDeadline(expiresAt))
			}
		}
	}
}

func sameManagedUpdateApproval(opts agentupdate.Options, policy agentlicense.UpdatePolicy) bool {
	return policy.Enabled && !policy.Paused && policy.Eligible && policy.AutoInstall &&
		policy.LeaseGranted != nil && *policy.LeaseGranted &&
		strings.TrimSpace(policy.TargetVersion) == strings.TrimSpace(opts.DesiredVersion) &&
		strings.TrimSpace(policy.CampaignID) == strings.TrimSpace(opts.CampaignID) &&
		policy.PolicyRevision == opts.PolicyRevision &&
		policy.AllowDowngrade == opts.AllowDowngrade &&
		strings.TrimSpace(policy.RollbackReason) == strings.TrimSpace(opts.PolicyRollbackReason)
}

func timeUntilManagedLeaseDeadline(expiresAt time.Time) time.Duration {
	delay := time.Until(expiresAt.Add(-managedUpdateLeaseSafetyMargin))
	if delay <= 0 {
		return time.Millisecond
	}
	return delay
}

func scheduledUpdateRetryDelay(cfg scheduledUpdateConfig, failures int, err error) time.Duration {
	base := cfg.RetryInitial
	if base <= 0 {
		base = time.Minute
	}
	maximum := cfg.RetryMax
	if maximum <= 0 {
		maximum = time.Hour
	}
	if maximum < base {
		maximum = base
	}
	if failures < 1 {
		failures = 1
	}
	delay := base
	for attempt := 1; attempt < failures && delay < maximum; attempt++ {
		if delay > maximum/2 {
			delay = maximum
			break
		}
		delay *= 2
	}
	if requested := agentupdate.RetryAfter(err); requested > delay {
		delay = requested
	}
	if delay > maximum {
		delay = maximum
	}
	if delay < maximum {
		jitterLimit := delay / 4
		delay += stableJitter(jitterLimit, fmt.Sprintf("%s|%d|retry", cfg.Options.DeviceID, failures))
		if delay > maximum {
			delay = maximum
		}
	}
	return delay
}

func normalizeUpdateOptions(opts agentupdate.Options) agentupdate.Options {
	if opts.Channel == "" {
		opts.Channel = "stable"
	}
	if opts.CurrentVersion == "" {
		opts.CurrentVersion = version
	}
	if opts.StateDir == "" {
		opts.StateDir = agentupdate.DefaultStateDir()
	}
	if opts.DeviceID == "" && opts.HostID != "" {
		opts.DeviceID = strings.TrimSpace(opts.HostID)
	}
	if opts.HostID == "" && opts.DeviceID != "" {
		opts.HostID = opts.DeviceID
	}
	return opts
}

func updateRequiresRestart(status agentupdate.Status) bool {
	return status.CommitStarted || status.Status == "installed" || status.Status == "install_scheduled" || status.Status == "rolled_back" || status.Status == "rollback_scheduled"
}

func stableJitter(max time.Duration, seed string) time.Duration {
	if max <= 0 {
		return 0
	}
	seconds := int(max / time.Second)
	if seconds <= 0 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(seed))
	return time.Duration(int(h.Sum32())%(seconds+1)) * time.Second
}
