package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/metrics"
	agentoutput "secweaver-agent/pkg/output"
)

const moduleStopGracePeriod = 15 * time.Second
const auditMetricsInterval = 5 * time.Second

// runSupervisor owns every long-lived Agent worker. Metrics synchronization is
// included in the same wait group so its final cumulative audit snapshot is
// published before shutdown completes.
func runSupervisor(ctx context.Context, modules []runtimeModule, updater *scheduledUpdateConfig, remoteCfg *scheduledRemoteConfig, licenseCfg agentlicense.Config, enterpriseID string, tracker *statusTracker, metricsExporter *metrics.Exporter, operations *operationsReportRuntime) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	identity, err := agentoutput.HostIdentityFromEnv()
	if err != nil {
		return fmt.Errorf("resolve host event identity: %w", err)
	}
	for i := range modules {
		modules[i].HostName = identity.HostName
		modules[i].HostIP = identity.HostIP
	}

	auditDemuxes, err := buildAuditDemuxRegistry(modules, tracker)
	if err != nil {
		return err
	}
	ownedTracker := false
	if tracker == nil {
		tracker = newStatusTracker("", enterpriseID, licenseCfg, modules)
		tracker.write()
		tracker.startWriter()
		ownedTracker = true
	}
	if ownedTracker {
		defer func() {
			if err := tracker.closeWriter(); err != nil {
				fmt.Fprintf(os.Stderr, "final status persistence failed: %v\n", err)
			}
		}()
	}
	var operationsReporter *agentOperationsReporter
	if operations != nil && operations.Enabled {
		operationsReporter = newAgentOperationsReporter(*operations, tracker, auditDemuxes, identity, version)
		operationsReporter.start()
		defer func() {
			if err := operationsReporter.close(); err != nil {
				fmt.Fprintf(os.Stderr, "operations report shutdown warning: %v\n", err)
			}
		}()
	}
	if updater != nil && updater.HealthCheckPending && integrationHealthFailureEnabled() {
		return errors.New("integration test forced post-update health failure")
	}

	errCh := make(chan error, len(modules)+5)
	var wg sync.WaitGroup
	if metricsExporter != nil {
		for name, health := range tracker.moduleSnapshot() {
			metricsExporter.UpdateModuleStatus(metrics.ModuleStatus{
				Name:                name,
				Status:              health.Status,
				PID:                 health.PID,
				RestartCount:        health.RestartCount,
				ConsecutiveFailures: health.ConsecutiveFailures,
			}, enterpriseID)
		}
		// Audit metrics are sampled outside the reader path. One immediate sample
		// initializes gauges, then a bounded ticker exports cumulative counters.
		updateAuditMetrics(metricsExporter, auditDemuxes.metricsSnapshot())
		wg.Add(1)
		go func() {
			defer wg.Done()
			runAuditMetrics(ctx, auditDemuxes, metricsExporter)
		}()
	}
	var updatePolicies chan agentlicense.UpdatePolicy
	if updater != nil && updater.RequireServerPolicy {
		updatePolicies = make(chan agentlicense.UpdatePolicy, 1)
	}
	for _, module := range modules {
		module := module
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := superviseModule(ctx, module, auditDemuxes, tracker, metricsExporter, enterpriseID); err != nil {
				errCh <- err
				cancel()
			}
		}()
	}
	if updater != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runScheduledUpdater(ctx, *updater, updatePolicies, metricsExporter); err != nil {
				errCh <- err
				cancel()
			}
		}()
		if updater.HealthCheckPending {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := runUpdateHealthMonitor(ctx, *updater, tracker, metricsExporter); err != nil {
					errCh <- err
					cancel()
				}
			}()
		}
	}
	if remoteCfg != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runScheduledRemoteConfig(ctx, *remoteCfg); err != nil {
				errCh <- err
				cancel()
			}
		}()
	}
	if licenseCfg.Enabled && licenseCfg.CheckIntervalSeconds > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runScheduledLicenseChecker(ctx, licenseCfg, enterpriseID, tracker, metricsExporter); err != nil {
				errCh <- err
				cancel()
			}
		}()
	}
	if licenseCfg.Enabled && licenseCfg.HeartbeatSeconds > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runScheduledHeartbeat(ctx, licenseCfg, enterpriseID, tracker, updater, updatePolicies, metricsExporter); err != nil {
				errCh <- err
				cancel()
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		<-done
		select {
		case err := <-errCh:
			return err
		default:
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			return ctx.Err()
		}
	case err := <-errCh:
		cancel()
		<-done
		return err
	case <-done:
		select {
		case err := <-errCh:
			return err
		default:
			return nil
		}
	}
}

// superviseModule mirrors every lifecycle transition to the durable tracker and
// Prometheus exporter while preserving the existing restart backoff and circuit.
func superviseModule(ctx context.Context, module runtimeModule, auditDemuxes *auditDemuxRegistry, tracker *statusTracker, metricsExporter *metrics.Exporter, enterpriseID string) error {
	policy := restartPolicy(module.Config.Restart)
	restart := normalizeModuleRestartConfig(module.Config)
	failures := 0

	for {
		startedAt := time.Now()
		err := runModuleProcess(ctx, module, auditDemuxes, tracker, metricsExporter, enterpriseID)
		runDuration := time.Since(startedAt)
		if ctx.Err() != nil {
			if tracker != nil {
				tracker.moduleExited(module.Spec.Name, nil, false)
			}
			if metricsExporter != nil {
				metricsExporter.UpdateModuleStatus(metrics.ModuleStatus{
					Name:   module.Spec.Name,
					Status: "stopped",
				}, enterpriseID)
			}
			return nil
		}
		if !shouldRestart(policy, err) {
			if tracker != nil {
				tracker.moduleExited(module.Spec.Name, err, false)
			}
			if metricsExporter != nil {
				status := "stopped"
				if err != nil {
					status = "error"
				}
				metricsExporter.UpdateModuleStatus(metrics.ModuleStatus{
					Name:   module.Spec.Name,
					Status: status,
				}, enterpriseID)
			}
			return err
		}
		if runDuration >= restart.StableAfter {
			failures = 0
			if tracker != nil {
				tracker.moduleFailuresReset(module.Spec.Name)
			}
		}
		failures++

		// Record restart in metrics
		if metricsExporter != nil {
			metricsExporter.RecordModuleRestart(module.Spec.Name, enterpriseID)
		}

		if failures >= restart.FailureLimit {
			if tracker != nil {
				tracker.moduleCircuitOpen(module.Spec.Name, err, restart.CircuitDuration, failures)
			}
			if metricsExporter != nil {
				metricsExporter.UpdateModuleStatus(metrics.ModuleStatus{
					Name:                module.Spec.Name,
					Status:              "degraded",
					ConsecutiveFailures: failures,
				}, enterpriseID)
			}
			fmt.Fprintf(os.Stderr, "module %s failed %d consecutive times; circuit open for %s\n", module.Spec.Name, failures, restart.CircuitDuration)
			if !sleepContext(ctx, restart.CircuitDuration) {
				return nil
			}
			failures = 0
			if tracker != nil {
				tracker.moduleFailuresReset(module.Spec.Name)
			}
			continue
		}
		delay := moduleRestartBackoff(restart.BaseDelay, restart.MaxDelay, failures, module)
		if tracker != nil {
			tracker.moduleRestarting(module.Spec.Name, err, delay, failures)
		}
		if metricsExporter != nil {
			metricsExporter.UpdateModuleStatus(metrics.ModuleStatus{
				Name:                module.Spec.Name,
				Status:              "restarting",
				ConsecutiveFailures: failures,
			}, enterpriseID)
		}
		fmt.Fprintf(os.Stderr, "module %s exited (%v); restarting in %s\n", module.Spec.Name, err, delay)
		if !sleepContext(ctx, delay) {
			return nil
		}
	}
}

type moduleRestartRuntime struct {
	BaseDelay       time.Duration
	MaxDelay        time.Duration
	FailureLimit    int
	StableAfter     time.Duration
	CircuitDuration time.Duration
}

func normalizeModuleRestartConfig(config moduleConfig) moduleRestartRuntime {
	runtimeConfig := moduleRestartRuntime{
		BaseDelay:       3 * time.Second,
		MaxDelay:        5 * time.Minute,
		FailureLimit:    8,
		StableAfter:     5 * time.Minute,
		CircuitDuration: 15 * time.Minute,
	}
	if config.RestartDelaySeconds > 0 {
		runtimeConfig.BaseDelay = time.Duration(config.RestartDelaySeconds) * time.Second
	}
	if config.RestartMaxDelaySeconds > 0 {
		runtimeConfig.MaxDelay = time.Duration(config.RestartMaxDelaySeconds) * time.Second
	}
	if runtimeConfig.MaxDelay < runtimeConfig.BaseDelay {
		runtimeConfig.MaxDelay = runtimeConfig.BaseDelay
	}
	if config.RestartFailureLimit > 0 {
		runtimeConfig.FailureLimit = config.RestartFailureLimit
	}
	if config.RestartStableSeconds > 0 {
		runtimeConfig.StableAfter = time.Duration(config.RestartStableSeconds) * time.Second
	}
	if config.RestartCircuitSeconds > 0 {
		runtimeConfig.CircuitDuration = time.Duration(config.RestartCircuitSeconds) * time.Second
	}
	return runtimeConfig
}

func moduleRestartBackoff(base, maximum time.Duration, failures int, module runtimeModule) time.Duration {
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
	if delay > maximum {
		delay = maximum
	}
	host, _ := os.Hostname()
	jitterMax := delay / 5
	jitter := stableJitter(jitterMax, module.EnterpriseID+"|"+host+"|"+module.Spec.Name+fmt.Sprintf("|%d", failures))
	if delay+jitter > maximum {
		return maximum
	}
	return delay + jitter
}

// runModuleProcess reports running only after cmd.Start returns a real PID. This
// ordering prevents readiness from passing while process creation is still able
// to fail, and keeps inherited audit pipe ownership unchanged.
func runModuleProcess(ctx context.Context, module runtimeModule, auditDemuxes *auditDemuxRegistry, tracker *statusTracker, metricsExporter *metrics.Exporter, enterpriseID string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := append([]string{"module", module.Spec.Name}, module.Config.Args...)
	fmt.Fprintf(os.Stderr, "starting module %s: %s %s\n", module.Spec.Name, exe, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.WaitDelay = moduleStopGracePeriod
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = withEnvValue(os.Environ(), agentoutput.EnterpriseIDEnv, module.EnterpriseID)
	cmd.Env = withEnvValue(cmd.Env, agentoutput.DiskPriorityEnv, moduleDiskPriority(module.Spec.Name))
	processControl, err := prepareModuleProcessControl(cmd)
	if err != nil {
		return err
	}
	defer processControl.close()
	cmd.Cancel = processControl.requestStop
	if module.HostName == "" || module.HostIP == "" {
		identity, identityErr := agentoutput.HostIdentityFromEnv()
		if identityErr != nil {
			return fmt.Errorf("resolve module host event identity: %w", identityErr)
		}
		module.HostName = identity.HostName
		module.HostIP = identity.HostIP
	}
	cmd.Env = withEnvValue(cmd.Env, agentoutput.HostNameEnv, module.HostName)
	cmd.Env = withEnvValue(cmd.Env, agentoutput.HostIPEnv, module.HostIP)
	// attach creates a per-module pipe subscribed to the parent's single audit
	// reader. ExtraFiles starts at child FD 3; auditEnv tells the module to use
	// that inherited descriptor instead of opening audit.log independently.
	auditReader, auditEnv, cleanupAuditStream, err := auditDemuxes.attach(ctx, module)
	if err != nil {
		return err
	}
	if auditReader != nil {
		defer cleanupAuditStream()
		cmd.ExtraFiles = append(cmd.ExtraFiles, auditReader)
		cmd.Env = append(cmd.Env, auditEnv...)
		fmt.Fprintf(os.Stderr, "module %s uses shared audit demux input\n", module.Spec.Name)
	}
	if err := cmd.Start(); err != nil {
		if auditReader != nil {
			_ = auditReader.Close()
		}
		if tracker != nil {
			tracker.moduleStartFailed(module.Spec.Name, err)
		}
		return err
	}
	if tracker != nil {
		tracker.moduleStarting(module.Spec.Name, cmd.Process.Pid)
	}
	if err := processControl.afterStart(cmd.Process); err != nil {
		// Cooperative stop still works when an upstream Windows Job forbids
		// nested assignment; report the containment downgrade explicitly.
		fmt.Fprintf(os.Stderr, "module %s process containment warning: %v\n", module.Spec.Name, err)
	}
	if metricsExporter != nil {
		metricsExporter.UpdateModuleStatus(metrics.ModuleStatus{
			Name:   module.Spec.Name,
			Status: "running",
			PID:    cmd.Process.Pid,
		}, enterpriseID)
	}
	if auditReader != nil {
		// After fork/exec, only the child needs the read end. Keeping the parent's
		// duplicate open would prevent EOF when the demux closes its writer.
		_ = auditReader.Close()
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return err
	}
	return nil
}

// moduleDiskPriority reserves headroom for real-time security evidence before
// periodic inventory snapshots. Unknown future modules use the middle tier.
func moduleDiskPriority(name string) string {
	switch name {
	case "audit-port-execmon", "syslog-risk-json", "host-persistence", "windows-eventlog-risk-json", "windows-process-execmon":
		return agentoutput.DiskPriorityRealtime
	case "host-process-snapshot", "host-state-snapshot":
		return agentoutput.DiskPrioritySnapshot
	default:
		return agentoutput.DiskPriorityStandard
	}
}

// runAuditMetrics keeps Prometheus publication off the audit reader and pipe
// writer goroutines. A five-second observation delay is acceptable for metrics;
// the first overflow diagnostic is queued immediately by the reader and emitted
// by a bounded asynchronous worker so slow status IO cannot stall collection.
func runAuditMetrics(ctx context.Context, registry *auditDemuxRegistry, exporter *metrics.Exporter) {
	if exporter == nil {
		return
	}
	ticker := time.NewTicker(auditMetricsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			updateAuditMetrics(exporter, registry.metricsSnapshot())
			return
		case <-ticker.C:
			updateAuditMetrics(exporter, registry.metricsSnapshot())
		}
	}
}

// updateAuditMetrics is the observability adapter between backend-neutral demux
// state and the Prometheus package.
func updateAuditMetrics(exporter *metrics.Exporter, snapshot auditDemuxMetrics) {
	if exporter == nil {
		return
	}
	exporter.UpdateAuditMetrics(metrics.AuditMetrics{
		BacklogLines:       snapshot.backlogLines,
		Subscribers:        snapshot.subscribers,
		RetiredSubscribers: snapshot.retiredSubscribers,
		LinesProcessed:     snapshot.linesProcessed,
		BacklogOverflows:   snapshot.backlogOverflows,
		Readers:            snapshot.readers,
		ReadersReady:       snapshot.readersReady,
		ReaderFailures:     snapshot.readerFailures,
	})
}

func withEnvValue(environment []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			continue
		}
		result = append(result, entry)
	}
	return append(result, prefix+value)
}

func shouldRestart(policy string, err error) bool {
	switch policy {
	case "always":
		return true
	case "on_failure":
		return err != nil
	case "never":
		return false
	default:
		return false
	}
}

func validateRestartPolicy(policy string) error {
	switch restartPolicy(policy) {
	case "never", "on_failure", "always":
		return nil
	default:
		return fmt.Errorf("restart must be one of never/on_failure/always")
	}
}

func restartPolicy(policy string) string {
	policy = strings.ToLower(strings.TrimSpace(policy))
	switch policy {
	case "", "on-failure":
		return "on_failure"
	case "no", "none", "disabled":
		return "never"
	default:
		return policy
	}
}
