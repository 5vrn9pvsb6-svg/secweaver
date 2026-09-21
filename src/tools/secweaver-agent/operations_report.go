package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"secweaver-agent/pkg/layout"
	agentoutput "secweaver-agent/pkg/output"
)

const operationsReportAssetType = "secweaver_agent_health"
const operationsReportSchemaVersion = "1.0"

// defaultOperationsReportPath keeps operations telemetry beside all other
// Agent-owned logs. Windows resolves redirected ProgramData at runtime.
func defaultOperationsReportPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(layout.WindowsRootDir(), "logs", "secweaver-agent-health.log")
	}
	return filepath.Join(layout.LinuxLogs, "secweaver-agent-health.log")
}

type agentOperationsReporter struct {
	mu         sync.Mutex
	config     operationsReportRuntime
	tracker    *statusTracker
	audit      *auditDemuxRegistry
	identity   agentoutput.HostIdentity
	version    string
	jitterSeed string
	started    time.Time
	writer     interface {
		Write([]byte) (int, error)
		Close() error
		Flush() error
	}
	cleanup func()
	wake    <-chan struct{}
	stop    chan struct{}
	done    chan struct{}
	lastKey string
	seq     uint64
}

type operationsReportEvent struct {
	SchemaVersion string                   `json:"schema_version"`
	Time          string                   `json:"time"`
	Timestamp     string                   `json:"timestamp"`
	AssetType     string                   `json:"asset_type"`
	EventType     string                   `json:"event_type"`
	Severity      string                   `json:"severity"`
	HealthStatus  string                   `json:"health_status"`
	Sequence      uint64                   `json:"sequence"`
	EnterpriseID  string                   `json:"enterprise_id"`
	EvidenceID    string                   `json:"evidence_id"`
	DeviceID      string                   `json:"device_id,omitempty"`
	HostName      string                   `json:"host_name"`
	Host          string                   `json:"host"`
	HostIP        string                   `json:"host_ip"`
	AgentVersion  string                   `json:"agent_version"`
	OS            string                   `json:"os"`
	Arch          string                   `json:"arch"`
	PID           int                      `json:"pid"`
	UptimeSeconds int64                    `json:"uptime_seconds"`
	Modules       []operationsModuleHealth `json:"modules"`
	Audit         operationsAuditHealth    `json:"audit"`
	License       operationsLicenseHealth  `json:"license"`
	Persistence   operationsPersistence    `json:"persistence"`
	Resources     *operationsResource      `json:"resources,omitempty"`
	Shipper       *operationsShipper       `json:"shipper,omitempty"`
	ReasonCodes   []string                 `json:"reason_codes,omitempty"`
	Component     string                   `json:"component,omitempty"`
	StateFrom     string                   `json:"state_from,omitempty"`
	StateTo       string                   `json:"state_to,omitempty"`
	Message       string                   `json:"message,omitempty"`
}

type operationsModuleHealth struct {
	Name                string `json:"name"`
	Status              string `json:"status"`
	PID                 int    `json:"pid,omitempty"`
	RestartCount        int    `json:"restart_count,omitempty"`
	ConsecutiveFailures int    `json:"consecutive_failures,omitempty"`
	LastStartAt         string `json:"last_start_at,omitempty"`
	LastExitAt          string `json:"last_exit_at,omitempty"`
	OutputAgeSeconds    int64  `json:"output_age_seconds,omitempty"`
	OutputSizeBytes     int64  `json:"output_size_bytes,omitempty"`
}

type operationsAuditHealth struct {
	Backend               string `json:"backend"`
	ReaderReady           bool   `json:"reader_ready"`
	Readers               int    `json:"readers"`
	Subscribers           int    `json:"subscribers"`
	BacklogLines          int    `json:"backlog_lines"`
	LinesProcessedTotal   uint64 `json:"lines_processed_total"`
	ReaderFailuresTotal   uint64 `json:"reader_failures_total"`
	BacklogOverflowsTotal uint64 `json:"backlog_overflows_total"`
}

type operationsLicenseHealth struct {
	Enabled         bool   `json:"enabled"`
	LastCheckAt     string `json:"last_check_at,omitempty"`
	LastHeartbeatAt string `json:"last_heartbeat_at,omitempty"`
	Status          string `json:"status"`
}

type operationsPersistence struct {
	LastAttemptAt string `json:"last_attempt_at,omitempty"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	ErrorCount    uint64 `json:"error_count,omitempty"`
}

type operationsResource struct {
	Goroutines       int    `json:"goroutines"`
	GoHeapAllocBytes uint64 `json:"go_heap_alloc_bytes"`
	GoSysBytes       uint64 `json:"go_sys_bytes"`
	GoGCCount        uint32 `json:"go_gc_count"`
}

type operationsShipper struct {
	Type          string `json:"type"`
	Configuration string `json:"configuration"`
}

// newAgentOperationsReporter binds jitter to the durable device identity when
// enrollment is available. Host identity is a stable fallback for unmanaged or
// not-yet-enrolled installations, so fleet snapshots do not synchronize.
func newAgentOperationsReporter(config operationsReportRuntime, tracker *statusTracker, audit *auditDemuxRegistry, identity agentoutput.HostIdentity, agentVersion string) *agentOperationsReporter {
	jitterSeed := identity.HostName + "|" + identity.HostIP
	if tracker != nil {
		if deviceID := strings.TrimSpace(tracker.operationsSnapshot().DeviceID); deviceID != "" {
			jitterSeed = deviceID
		}
	}
	return &agentOperationsReporter{
		config: config, tracker: tracker, audit: audit, identity: identity, version: agentVersion,
		jitterSeed: jitterSeed, wake: tracker.healthSignal, stop: make(chan struct{}), done: make(chan struct{}), started: time.Now(),
	}
}

// start opens the private rotating stream before module supervision. A health
// stream failure disables only telemetry; it must never stop evidence capture.
func (r *agentOperationsReporter) start() {
	if r == nil {
		return
	}
	writer, cleanup, err := agentoutput.OpenAppend(agentoutput.AppendOptions{
		Path: r.config.Output, Perm: agentoutput.DefaultFilePerm,
		BufferSize: agentoutput.DefaultBufferSize, FlushInterval: agentoutput.DefaultFlushInterval,
		MaxSizeBytes: r.config.MaxSizeBytes, MaxBackups: r.config.MaxBackups,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "operations report disabled: %v\n", err)
		close(r.done)
		return
	}
	managed, ok := writer.(interface {
		Write([]byte) (int, error)
		Close() error
		Flush() error
	})
	if !ok {
		cleanup()
		fmt.Fprintln(os.Stderr, "operations report disabled: output writer lifecycle is unavailable")
		close(r.done)
		return
	}
	r.writer, r.cleanup = managed, cleanup
	go r.run()
}

// run serializes lifecycle transitions and periodic snapshots. The one-slot
// status signal collapses rapid restarts while the ticker covers quiet hosts.
func (r *agentOperationsReporter) run() {
	defer close(r.done)
	r.emit("agent_lifecycle", "info", "healthy", "agent_started", "", "running", "Agent started")
	initial := r.config.SnapshotInterval + stableJitter(r.config.Jitter, r.jitterSeed)
	timer := time.NewTimer(initial)
	defer timer.Stop()
	for {
		select {
		case <-r.wake:
			r.emitHealthTransition()
		case <-timer.C:
			r.emit("health_snapshot", "", "", "", "", "", "")
			timer.Reset(r.config.SnapshotInterval)
		case <-r.stop:
			r.emit("agent_lifecycle", "info", "", "agent_stopped", "running", "stopped", "Agent stopped")
			return
		}
	}
}

// emitHealthTransition suppresses duplicate notifications caused by the
// coalesced status channel while retaining the newest complete state.
func (r *agentOperationsReporter) emitHealthTransition() {
	snapshot := r.tracker.operationsSnapshot()
	key := operationsStateKey(snapshot)
	r.mu.Lock()
	changed := key != r.lastKey
	r.mu.Unlock()
	if changed {
		r.emit("health_transition", "", "", "state_changed", "", "", "Agent health state changed")
	}
}

// close stops the reporter before status persistence closes, so the final
// lifecycle record still contains the last module and license state.
func (r *agentOperationsReporter) close() error {
	if r == nil {
		return nil
	}
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	<-r.done
	if r.cleanup != nil {
		r.cleanup()
	}
	return nil
}

// emit snapshots all component state before encoding one bounded JSON record.
// The writer is private to the reporter goroutine, except for shutdown after
// done is closed, so evidence collectors never contend on this output lock.
func (r *agentOperationsReporter) emit(eventType, severity, healthStatus, reason, from, to, message string) {
	if r.writer == nil {
		return
	}
	snapshot := r.tracker.operationsSnapshot()
	audit := auditDemuxMetrics{}
	if r.audit != nil {
		audit = r.audit.metricsSnapshot()
	}
	health, derivedSeverity, reasons := operationsHealth(snapshot, audit)
	if healthStatus == "" {
		healthStatus = health
	}
	if severity == "" {
		severity = derivedSeverity
	}
	if reason != "" && !containsOperationsString(reasons, reason) {
		reasons = append(reasons, reason)
		sort.Strings(reasons)
	}
	r.mu.Lock()
	r.seq++
	r.lastKey = operationsStateKey(snapshot)
	sequence := r.seq
	r.mu.Unlock()

	event := operationsReportEvent{
		SchemaVersion: operationsReportSchemaVersion, Time: time.Now().UTC().Format(time.RFC3339Nano),
		AssetType: operationsReportAssetType, EventType: eventType, Severity: severity, HealthStatus: healthStatus,
		Sequence: sequence, EnterpriseID: snapshot.EnterpriseID, DeviceID: snapshot.DeviceID,
		HostName: r.identity.HostName, HostIP: r.identity.HostIP, AgentVersion: r.version,
		OS: runtime.GOOS, Arch: runtime.GOARCH, PID: os.Getpid(), UptimeSeconds: int64(time.Since(r.started).Seconds()),
		Modules: operationModules(snapshot, r.tracker), Audit: operationAudit(audit),
		License: operationsLicense(snapshot), Persistence: operationsPersistence{LastAttemptAt: snapshot.Persistence.LastAttemptAt, LastSuccessAt: snapshot.Persistence.LastSuccessAt, ErrorCount: snapshot.Persistence.ErrorCount},
		ReasonCodes: reasons, Component: componentForEvent(eventType), StateFrom: from, StateTo: to, Message: truncateOperationsMessage(message),
	}
	event.Timestamp = event.Time
	event.Host = event.HostName
	event.EvidenceID = operationsEvidenceID(event)
	if r.config.IncludeResourceUsage {
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		event.Resources = &operationsResource{Goroutines: runtime.NumGoroutine(), GoHeapAllocBytes: memory.HeapAlloc, GoSysBytes: memory.Sys, GoGCCount: memory.NumGC}
	}
	if r.config.IncludeShipperStatus {
		shipper := detectOperationsShipper()
		event.Shipper = &shipper
	}
	body, err := json.Marshal(event)
	if err != nil {
		return
	}
	body = append(body, '\n')
	if _, err := r.writer.Write(body); err != nil {
		fmt.Fprintf(os.Stderr, "operations report write failed: %v\n", err)
		return
	}
	if eventType != "health_snapshot" {
		_ = r.writer.Flush()
	}
}

// operationsHealth converts internal component state into the small public
// health contract. Historical audit overflow remains unhealthy because lost
// evidence cannot be reconstructed after the pressure has recovered.
func operationsHealth(snapshot agentStatusFile, audit auditDemuxMetrics) (string, string, []string) {
	// Audit transport is unhealthy only when a reader exists and is unavailable;
	// pure eBPF or non-audit deployments legitimately report zero readers.
	status, severity := "healthy", "info"
	reasons := []string{}
	for name, module := range snapshot.Modules {
		code := "module_" + strings.ReplaceAll(name, "-", "_")
		switch {
		case module.Status == "error" || module.Status == "degraded":
			status, severity = "unhealthy", "high"
			reasons = append(reasons, code+"_unhealthy")
		case module.Status != "running":
			if status == "healthy" {
				status, severity = "degraded", "medium"
			}
			reasons = append(reasons, code+"_not_running")
		}
	}
	if snapshot.License.Enabled && snapshot.License.LastError != "" {
		status, severity = "unhealthy", "high"
		reasons = append(reasons, "license_error")
	}
	if snapshot.Persistence.LastError != "" {
		status, severity = "unhealthy", "high"
		reasons = append(reasons, "status_persistence_error")
	}
	for name, diagnostic := range snapshot.Diagnostics {
		if strings.EqualFold(diagnostic.Level, "error") {
			status, severity = "unhealthy", "high"
			reasons = append(reasons, "diagnostic_"+strings.NewReplacer("/", "_", " ", "_").Replace(name))
		} else if status == "healthy" && strings.EqualFold(diagnostic.Level, "warn") {
			status, severity = "degraded", "medium"
		}
	}
	if audit.readers > 0 && !auditReaderReady(audit) {
		status, severity = "unhealthy", "high"
		reasons = append(reasons, "audit_reader_unavailable")
	}
	if audit.backlogOverflows > 0 {
		status, severity = "unhealthy", "high"
		reasons = append(reasons, "audit_backlog_overflow")
	}
	sort.Strings(reasons)
	return status, severity, reasons
}

func auditReaderReady(metrics auditDemuxMetrics) bool { return metrics.readersReady == metrics.readers }

// operationAudit exposes only shared-demux counters; it deliberately avoids
// querying auditctl or reconstructing per-process rules during a snapshot.
func operationAudit(metrics auditDemuxMetrics) operationsAuditHealth {
	// Keep the backend label coarse and stable. Detailed backend capability is
	// already reported by the audit module and must not create high-cardinality
	// fields in the operations index.
	backend := "none"
	if metrics.readers > 0 {
		backend = "audit_shared_reader"
	}
	return operationsAuditHealth{Backend: backend, ReaderReady: metrics.readers == 0 || auditReaderReady(metrics), Readers: metrics.readers, Subscribers: metrics.subscribers, BacklogLines: metrics.backlogLines, LinesProcessedTotal: metrics.linesProcessed, ReaderFailuresTotal: metrics.readerFailures, BacklogOverflowsTotal: metrics.backlogOverflows}
}

// operationsLicense maps authorization state without copying server error text
// into the remotely shipped operations stream.
func operationsLicense(snapshot agentStatusFile) operationsLicenseHealth {
	// Never copy LastError into the remote record: errors can contain URLs or
	// server details. The normalized status and reason code are sufficient.
	status := "disabled"
	if snapshot.License.Enabled {
		status = "authorized"
		if snapshot.License.LastError != "" {
			status = "degraded"
		}
	}
	return operationsLicenseHealth{Enabled: snapshot.License.Enabled, LastCheckAt: snapshot.License.LastCheckAt, LastHeartbeatAt: snapshot.License.LastHeartbeatAt, Status: status}
}

func operationModules(snapshot agentStatusFile, tracker *statusTracker) []operationsModuleHealth {
	// Output freshness is collected with stat only. No log content is read, so
	// this five-minute observation cannot compete with collector readers.
	modules := make([]operationsModuleHealth, 0, len(snapshot.Modules))
	for name, health := range snapshot.Modules {
		item := operationsModuleHealth{Name: name, Status: health.Status, PID: health.PID, RestartCount: health.RestartCount, ConsecutiveFailures: health.ConsecutiveFailures, LastStartAt: health.LastStartAt, LastExitAt: health.LastExitAt}
		if tracker != nil {
			tracker.mu.Lock()
			paths := append([]string(nil), tracker.moduleOutputs[name]...)
			tracker.mu.Unlock()
			// Stat output paths after releasing the tracker lock. A slow or
			// temporarily missing mount must not delay lifecycle mutations.
			for _, path := range paths {
				if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
					age := int64(time.Since(info.ModTime()).Seconds())
					if age > item.OutputAgeSeconds {
						item.OutputAgeSeconds = age
					}
					item.OutputSizeBytes += info.Size()
				}
			}
		}
		modules = append(modules, item)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Name < modules[j].Name })
	return modules
}

func detectOperationsShipper() operationsShipper {
	// Configuration presence is portable and cheap. Actual shipper delivery
	// latency belongs to Filebeat/native shipper metrics and server-side alerts.
	paths := []struct{ kind, path string }{
		{"filebeat", filepath.Join(layout.LinuxShipper, "filebeat.yml")},
		{"native", filepath.Join(layout.LinuxShipper, "shipper.json")},
		{"fluent_bit", filepath.Join(layout.LinuxShipper, "fluent-bit.conf")},
	}
	if runtime.GOOS == "windows" {
		paths = []struct{ kind, path string }{{"native", filepath.Join(layout.WindowsShipper, "shipper.json")}, {"fluent_bit", filepath.Join(layout.WindowsShipper, "fluent-bit.conf")}}
	}
	for _, candidate := range paths {
		if info, err := os.Stat(candidate.path); err == nil && info.Mode().IsRegular() {
			return operationsShipper{Type: candidate.kind, Configuration: "configured"}
		}
	}
	return operationsShipper{Type: "unknown", Configuration: "not_detected"}
}

func componentForEvent(eventType string) string {
	// Components are a small allow-list for stable dashboard grouping.
	if eventType == "agent_lifecycle" {
		return "agent"
	}
	return "agent_health"
}

func operationsStateKey(snapshot agentStatusFile) string {
	// The key includes only state transitions, not timestamps, preventing a
	// periodic status rewrite from producing duplicate transition records.
	parts := make([]string, 0, len(snapshot.Modules)+len(snapshot.Diagnostics)+1)
	for name, health := range snapshot.Modules {
		parts = append(parts, fmt.Sprintf("m:%s:%s:%d:%d", name, health.Status, health.PID, health.RestartCount))
	}
	for name, diagnostic := range snapshot.Diagnostics {
		parts = append(parts, "d:"+name+":"+diagnostic.Level+":"+diagnostic.Message)
	}
	sort.Strings(parts)
	persistenceState := "ok"
	if snapshot.Persistence.LastError != "" {
		persistenceState = "error"
	}
	return strings.Join(parts, "|") + "|license:" + snapshot.License.LastError + "|persistence:" + persistenceState
}

func containsOperationsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func truncateOperationsMessage(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 1024 {
		return value[:1024]
	}
	return value
}

// operationsEvidenceID is stable for one emitted record and does not expose
// command lines, credentials, or raw error text. The sequence prevents a
// restarted writer from accidentally reusing an ID in the same timestamp.
func operationsEvidenceID(event operationsReportEvent) string {
	seed := fmt.Sprintf("%s|%s|%s|%d|%d", event.DeviceID, event.EventType, event.Time, event.Sequence, event.PID)
	digest := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("agent-health-%x", digest[:16])
}
