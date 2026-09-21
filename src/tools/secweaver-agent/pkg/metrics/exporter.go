package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Exporter provides Prometheus metrics for secweaver-agent
type Exporter struct {
	registry *prometheus.Registry
	server   *http.Server
	mu       sync.RWMutex
	health   HealthCheck

	// Module metrics
	moduleStatus           *prometheus.GaugeVec
	moduleRestarts         *prometheus.CounterVec
	moduleConsecutiveFails *prometheus.GaugeVec
	modulePID              *prometheus.GaugeVec

	// Audit metrics
	auditBacklog            prometheus.Gauge
	auditLinesProcessed     prometheus.Counter
	auditSubscribers        prometheus.Gauge
	auditRetiredSubscribers prometheus.Counter
	auditBacklogOverflows   prometheus.Counter
	auditReaders            prometheus.Gauge
	auditReadersReady       prometheus.Gauge
	auditReaderFailures     prometheus.Counter
	auditLastLinesProcessed uint64
	auditLastRetired        uint64
	auditLastOverflows      uint64
	auditLastReaderFailures uint64

	// License metrics
	licenseEnabled      prometheus.Gauge
	licenseCheckSuccess prometheus.Gauge
	licenseCheckTotal   prometheus.Counter
	licenseCheckErrors  prometheus.Counter
	heartbeatSuccess    prometheus.Gauge
	heartbeatTotal      prometheus.Counter

	// Update metrics
	updateStatus    *prometheus.GaugeVec
	updateAttempts  prometheus.Counter
	updateSuccesses prometheus.Counter
	updateFailures  prometheus.Counter

	// System metrics
	agentInfo      *prometheus.GaugeVec
	agentUptime    prometheus.Gauge
	agentStartTime prometheus.Gauge
}

// listen is a package boundary so startup error handling can be tested without
// opening real sockets. Production always uses net.Listen; tests replace it
// before Start and restore it before returning.
var listen = net.Listen

// Config holds metrics exporter configuration
type Config struct {
	Enabled       bool   `json:"enabled"`
	ListenAddress string `json:"listen_address"`
	Path          string `json:"path"`
}

// HealthCheck returns whether the Agent is ready to collect and the reason when
// it is not. Exporter copies the callback under its lock and invokes it after
// releasing the lock because readiness may acquire status-tracker locks.
type HealthCheck func() (ready bool, reason string)

// ModuleStatus represents module health state
type ModuleStatus struct {
	Name                string
	Status              string // running, stopped, error, restarting, degraded
	PID                 int
	RestartCount        int
	ConsecutiveFailures int
}

// AuditMetrics represents audit stream metrics
type AuditMetrics struct {
	BacklogLines       int
	Subscribers        int
	RetiredSubscribers uint64
	LinesProcessed     uint64
	BacklogOverflows   uint64
	Readers            int
	ReadersReady       int
	ReaderFailures     uint64
}

// LicenseMetrics represents license check metrics
type LicenseMetrics struct {
	Enabled              bool
	LastCheckSuccess     bool
	LastHeartbeatSuccess bool
}

// NewExporter creates a new Prometheus metrics exporter
func NewExporter(enterpriseID, version string) *Exporter {
	registry := prometheus.NewRegistry()

	e := &Exporter{
		registry: registry,

		moduleStatus: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_module_status",
				Help: "Module status: 1=running, 0=stopped, -1=error, -2=restarting, -3=degraded",
			},
			[]string{"module", "enterprise_id"},
		),

		moduleRestarts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "secweaver_agent_module_restarts_total",
				Help: "Total number of module restarts",
			},
			[]string{"module", "enterprise_id"},
		),

		moduleConsecutiveFails: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_module_consecutive_failures",
				Help: "Number of consecutive module failures",
			},
			[]string{"module", "enterprise_id"},
		),

		modulePID: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_module_pid",
				Help: "Module process ID (0 if not running)",
			},
			[]string{"module", "enterprise_id"},
		),

		auditBacklog: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_audit_backlog_lines",
				Help: "Current number of lines in audit backlog",
			},
		),

		auditLinesProcessed: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "secweaver_agent_audit_lines_processed_total",
				Help: "Total number of audit lines processed",
			},
		),

		auditSubscribers: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_audit_subscribers",
				Help: "Current number of active audit subscribers",
			},
		),

		auditRetiredSubscribers: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "secweaver_agent_audit_retired_subscribers_total",
				Help: "Total number of retired audit subscribers",
			},
		),

		auditBacklogOverflows: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "secweaver_agent_audit_backlog_overflows_total",
				Help: "Total audit lines overwritten after a module backlog reached its fixed capacity",
			},
		),

		auditReaders: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_audit_readers",
				Help: "Number of configured shared audit log readers",
			},
		),

		auditReadersReady: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_audit_readers_ready",
				Help: "Number of shared audit log readers with an open source file",
			},
		),

		auditReaderFailures: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "secweaver_agent_audit_reader_failures_total",
				Help: "Total shared audit reader transitions into an unavailable state",
			},
		),

		licenseCheckSuccess: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_license_check_success",
				Help: "Last license check status: 1=success, 0=failure",
			},
		),

		licenseEnabled: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_license_enabled",
				Help: "Whether Data Cloud authorization is enabled: 1=enabled, 0=disabled",
			},
		),

		licenseCheckTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "secweaver_agent_license_check_total",
				Help: "Total number of license checks",
			},
		),

		licenseCheckErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "secweaver_agent_license_check_errors_total",
				Help: "Total number of license check errors",
			},
		),

		heartbeatSuccess: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_heartbeat_success",
				Help: "Last heartbeat status: 1=success, 0=failure",
			},
		),

		heartbeatTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "secweaver_agent_heartbeat_total",
				Help: "Total number of heartbeats sent",
			},
		),

		updateStatus: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_update_info",
				Help: "Update status and version info: 1=active, 0=inactive",
			},
			[]string{"current_version", "target_version", "status"},
		),

		updateAttempts: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "secweaver_agent_update_attempts_total",
				Help: "Total number of update attempts",
			},
		),

		updateSuccesses: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "secweaver_agent_update_successes_total",
				Help: "Total number of successful updates",
			},
		),

		updateFailures: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "secweaver_agent_update_failures_total",
				Help: "Total number of failed updates",
			},
		),

		agentInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_info",
				Help: "Agent information",
			},
			[]string{"version", "enterprise_id"},
		),

		agentUptime: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_uptime_seconds",
				Help: "Agent uptime in seconds",
			},
		),

		agentStartTime: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "secweaver_agent_start_time_seconds",
				Help: "Agent start time as Unix timestamp",
			},
		),
	}

	// Register all metrics
	registry.MustRegister(
		e.moduleStatus,
		e.moduleRestarts,
		e.moduleConsecutiveFails,
		e.modulePID,
		e.auditBacklog,
		e.auditLinesProcessed,
		e.auditSubscribers,
		e.auditRetiredSubscribers,
		e.auditBacklogOverflows,
		e.auditReaders,
		e.auditReadersReady,
		e.auditReaderFailures,
		e.licenseEnabled,
		e.licenseCheckSuccess,
		e.licenseCheckTotal,
		e.licenseCheckErrors,
		e.heartbeatSuccess,
		e.heartbeatTotal,
		e.updateStatus,
		e.updateAttempts,
		e.updateSuccesses,
		e.updateFailures,
		e.agentInfo,
		e.agentUptime,
		e.agentStartTime,
	)

	// Set static info
	e.agentInfo.WithLabelValues(version, enterpriseID).Set(1)
	e.agentStartTime.Set(float64(time.Now().Unix()))

	return e
}

// NormalizeConfig applies endpoint defaults and rejects patterns that would
// panic http.ServeMux or shadow the fixed health endpoint. It deliberately
// validates syntax without opening a socket so callers may use it during
// configuration preflight.
func NormalizeConfig(config Config) (Config, error) {
	if !config.Enabled {
		return config, nil
	}
	if strings.TrimSpace(config.ListenAddress) == "" {
		config.ListenAddress = "127.0.0.1:9100"
	}
	if _, err := net.ResolveTCPAddr("tcp", config.ListenAddress); err != nil {
		return Config{}, fmt.Errorf("invalid metrics listen_address %q: %w", config.ListenAddress, err)
	}
	if strings.TrimSpace(config.Path) == "" {
		config.Path = "/metrics"
	}
	parsed, err := url.ParseRequestURI(config.Path)
	if err != nil || parsed.Path != config.Path || !strings.HasPrefix(config.Path, "/") {
		return Config{}, fmt.Errorf("invalid metrics path %q: expected an absolute URL path without query or fragment", config.Path)
	}
	if config.Path == "/health" || config.Path == "/live" {
		return Config{}, fmt.Errorf("metrics path %q conflicts with a health endpoint", config.Path)
	}
	if strings.ContainsAny(config.Path, "{}") {
		return Config{}, fmt.Errorf("metrics path %q must not contain ServeMux wildcards", config.Path)
	}
	return config, nil
}

// Start binds the metrics socket synchronously before it launches background
// serving. Returning bind and configuration failures to the Agent avoids a
// false "metrics started" state while keeping the HTTP lifecycle tied to ctx.
func (e *Exporter) Start(ctx context.Context, config Config) error {
	normalized, err := NormalizeConfig(config)
	if err != nil {
		return err
	}
	if !normalized.Enabled {
		return nil
	}
	config = normalized

	mux := e.handler(config.Path)

	e.server = &http.Server{
		Addr:    config.ListenAddress,
		Handler: mux,
	}
	listener, err := listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for metrics on %s: %w", config.ListenAddress, err)
	}

	go func() {
		fmt.Fprintf(os.Stderr, "metrics server listening on %s%s\n", config.ListenAddress, config.Path)
		if err := e.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "metrics server error: %v\n", err)
		}
	}()

	// Start uptime updater
	go e.updateUptime(ctx)

	// Wait for context cancellation
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := e.server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "metrics server shutdown error: %v\n", err)
		}
	}()

	return nil
}

// SetHealthCheck installs the readiness provider used by /health. Callers set
// it before Start; the lock also makes replacement safe in tests and during a
// future supervisor reconfiguration.
func (e *Exporter) SetHealthCheck(check HealthCheck) {
	e.mu.Lock()
	e.health = check
	e.mu.Unlock()
}

// handler keeps HTTP semantics testable without binding a real socket. /live
// proves only that the exporter process can answer; /health is deliberately
// stricter and returns 503 until the supervisor reports a usable collector set.
func (e *Exporter) handler(metricsPath string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		e.mu.RLock()
		check := e.health
		e.mu.RUnlock()
		if check == nil {
			http.Error(w, "NOT READY: health check is not configured", http.StatusServiceUnavailable)
			return
		}
		ready, reason := check()
		if !ready {
			if strings.TrimSpace(reason) == "" {
				reason = "agent is not ready"
			}
			http.Error(w, "NOT READY: "+reason, http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})
	return mux
}

// UpdateModuleStatus updates module status metrics
func (e *Exporter) UpdateModuleStatus(status ModuleStatus, enterpriseID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	labels := prometheus.Labels{"module": status.Name, "enterprise_id": enterpriseID}

	// Map status string to numeric value
	var statusValue float64
	switch status.Status {
	case "running":
		statusValue = 1
	case "stopped":
		statusValue = 0
	case "error":
		statusValue = -1
	case "restarting":
		statusValue = -2
	case "degraded":
		statusValue = -3
	default:
		statusValue = 0
	}

	e.moduleStatus.With(labels).Set(statusValue)
	e.modulePID.With(labels).Set(float64(status.PID))
	e.moduleConsecutiveFails.With(labels).Set(float64(status.ConsecutiveFailures))
}

// RecordModuleRestart records a module restart
func (e *Exporter) RecordModuleRestart(moduleName, enterpriseID string) {
	e.moduleRestarts.WithLabelValues(moduleName, enterpriseID).Inc()
}

// UpdateAuditMetrics applies one cumulative demux snapshot. Counter deltas are
// derived here rather than on the audit hot path; a lower value is treated as a
// source reset and added from zero so exporter restarts do not create negatives.
func (e *Exporter) UpdateAuditMetrics(metrics AuditMetrics) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.auditBacklog.Set(float64(metrics.BacklogLines))
	e.auditSubscribers.Set(float64(metrics.Subscribers))
	e.auditReaders.Set(float64(metrics.Readers))
	e.auditReadersReady.Set(float64(metrics.ReadersReady))
	e.auditLinesProcessed.Add(float64(cumulativeDelta(metrics.LinesProcessed, e.auditLastLinesProcessed)))
	e.auditRetiredSubscribers.Add(float64(cumulativeDelta(metrics.RetiredSubscribers, e.auditLastRetired)))
	e.auditBacklogOverflows.Add(float64(cumulativeDelta(metrics.BacklogOverflows, e.auditLastOverflows)))
	e.auditReaderFailures.Add(float64(cumulativeDelta(metrics.ReaderFailures, e.auditLastReaderFailures)))
	e.auditLastLinesProcessed = metrics.LinesProcessed
	e.auditLastRetired = metrics.RetiredSubscribers
	e.auditLastOverflows = metrics.BacklogOverflows
	e.auditLastReaderFailures = metrics.ReaderFailures
}

// cumulativeDelta handles a restarted or replaced source without generating a
// negative Prometheus counter delta.
func cumulativeDelta(current, previous uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return current
}

// UpdateLicenseMetrics updates license check metrics
func (e *Exporter) UpdateLicenseMetrics(metrics LicenseMetrics) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if metrics.Enabled {
		e.licenseEnabled.Set(1)
	} else {
		e.licenseEnabled.Set(0)
		return
	}
	e.licenseCheckTotal.Inc()
	if metrics.LastCheckSuccess {
		e.licenseCheckSuccess.Set(1)
	} else {
		e.licenseCheckSuccess.Set(0)
		e.licenseCheckErrors.Inc()
	}
}

// RecordHeartbeat records a heartbeat attempt
func (e *Exporter) RecordHeartbeat(success bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.heartbeatTotal.Inc()
	if success {
		e.heartbeatSuccess.Set(1)
	} else {
		e.heartbeatSuccess.Set(0)
	}
}

// UpdateUpdateStatus updates update status metrics
func (e *Exporter) UpdateUpdateStatus(currentVersion, targetVersion, status string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Clear old labels
	e.updateStatus.Reset()

	// Set new status
	e.updateStatus.WithLabelValues(currentVersion, targetVersion, status).Set(1)
}

// RecordUpdateAttempt records an update attempt
func (e *Exporter) RecordUpdateAttempt(success bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.updateAttempts.Inc()
	if success {
		e.updateSuccesses.Inc()
	} else {
		e.updateFailures.Inc()
	}
}

// updateUptime periodically updates the uptime metric
func (e *Exporter) updateUptime(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.agentUptime.Set(time.Since(startTime).Seconds())
		}
	}
}

// Shutdown stops the metrics server gracefully
func (e *Exporter) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.server != nil {
		return e.server.Shutdown(ctx)
	}
	return nil
}
