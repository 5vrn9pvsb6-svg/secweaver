package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/layout"
)

const (
	statusWriteInterval         = time.Second
	statusWriteErrorLogInterval = time.Minute
)

type agentStatusFile struct {
	SchemaVersion string                               `json:"schema_version"`
	Time          string                               `json:"time"`
	AgentVersion  string                               `json:"agent_version"`
	EnterpriseID  string                               `json:"enterprise_id"`
	DeviceID      string                               `json:"device_id,omitempty"`
	License       statusLicense                        `json:"license"`
	Modules       map[string]agentlicense.ModuleHealth `json:"modules"`
	Diagnostics   map[string]statusDiagnostic          `json:"diagnostics,omitempty"`
	Persistence   statusPersistence                    `json:"persistence"`
}

type statusLicense struct {
	Enabled         bool   `json:"enabled"`
	LastCheckAt     string `json:"last_check_at,omitempty"`
	LastHeartbeatAt string `json:"last_heartbeat_at,omitempty"`
	LastError       string `json:"last_error,omitempty"`
}

type statusTracker struct {
	mu            sync.Mutex
	path          string
	enterpriseID  string
	statePath     string
	modules       map[string]agentlicense.ModuleHealth
	moduleOutputs map[string][]string
	license       statusLicense
	diagnostics   map[string]statusDiagnostic
	persistence   statusPersistence
	deviceID      string
	writeInterval time.Duration
	writeSignal   chan struct{}
	writeStop     chan struct{}
	writeDone     chan struct{}
	writerStarted bool
	writerClosed  bool
	writeFile     func(string, interface{}, os.FileMode) error
	lastErrorLog  time.Time
	healthSignal  chan struct{}
}

type statusDiagnostic struct {
	Level     string            `json:"level"`
	Message   string            `json:"message"`
	UpdatedAt string            `json:"updated_at"`
	Metrics   map[string]uint64 `json:"metrics,omitempty"`
}

// statusPersistence exposes failures of the status channel itself. The writer
// retries while LastError is non-empty; ErrorCount is cumulative for the current
// Agent process and survives in the next successful status snapshot.
type statusPersistence struct {
	LastAttemptAt string `json:"last_attempt_at,omitempty"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	ErrorCount    uint64 `json:"error_count,omitempty"`
}

func defaultStatusPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(layout.WindowsRootDir(), "data", "status.json")
	}
	return layout.LinuxData + "/status.json"
}

func newStatusTracker(path, enterpriseID string, licenseCfg agentlicense.Config, modules []runtimeModule) *statusTracker {
	if strings.TrimSpace(path) == "" {
		path = defaultStatusPath()
	}
	tracker := &statusTracker{
		path:          path,
		enterpriseID:  enterpriseID,
		statePath:     licenseCfg.Normalize().StatePath,
		modules:       make(map[string]agentlicense.ModuleHealth),
		moduleOutputs: make(map[string][]string),
		license:       statusLicense{Enabled: licenseCfg.Enabled},
		diagnostics:   make(map[string]statusDiagnostic),
		writeInterval: statusWriteInterval,
		writeSignal:   make(chan struct{}, 1),
		writeStop:     make(chan struct{}),
		writeDone:     make(chan struct{}),
		writeFile:     writeJSONAtomic,
		healthSignal:  make(chan struct{}, 1),
	}
	for _, module := range modules {
		tracker.modules[module.Spec.Name] = agentlicense.ModuleHealth{Status: "configured"}
		if module.Spec.UpgradeOutputRequired && module.Spec.OutputPaths != nil {
			for _, output := range module.Spec.OutputPaths(module.Config.Args) {
				if output = strings.TrimSpace(output); output != "" && output != "-" {
					tracker.moduleOutputs[module.Spec.Name] = append(tracker.moduleOutputs[module.Spec.Name], output)
				}
			}
		}
	}
	return tracker
}

func (s *statusTracker) allModulesHealthySince(since time.Time) bool {
	if !s.allModulesRunning() {
		return false
	}
	s.mu.Lock()
	outputs := make(map[string][]string, len(s.moduleOutputs))
	for name, paths := range s.moduleOutputs {
		outputs[name] = append([]string(nil), paths...)
	}
	license := s.license
	s.mu.Unlock()
	if license.Enabled {
		heartbeatAt, err := time.Parse(time.RFC3339, license.LastHeartbeatAt)
		if err != nil || heartbeatAt.Before(since) || license.LastError != "" {
			return false
		}
	}
	for _, paths := range outputs {
		if len(paths) == 0 {
			return false
		}
		for _, path := range paths {
			info, err := os.Stat(filepath.Clean(path))
			if err != nil || !info.Mode().IsRegular() || info.ModTime().Before(since) || info.Size() == 0 {
				return false
			}
		}
	}
	return true
}

func (s *statusTracker) write() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeLocked()
}

// startWriter switches production mutations to one coalescing writer. Tests and
// one-shot tools that do not start it retain synchronous persistence, while the
// long-lived Agent never performs filesystem IO under its state lock.
func (s *statusTracker) startWriter() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.writerStarted || s.writerClosed {
		s.mu.Unlock()
		return
	}
	s.writerStarted = true
	s.mu.Unlock()
	go s.runWriter()
}

// closeWriter stops accepting persistence work and forces the newest snapshot
// to disk before returning. A final error is returned to the service log because
// no later retry is possible after process shutdown.
func (s *statusTracker) closeWriter() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if !s.writerStarted {
		s.writerClosed = true
		err := errors.New(s.persistence.LastError)
		if s.persistence.LastError == "" {
			err = nil
		}
		s.mu.Unlock()
		return err
	}
	if !s.writerClosed {
		s.writerClosed = true
		close(s.writeStop)
	}
	done := s.writeDone
	s.mu.Unlock()
	<-done
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.persistence.LastError != "" {
		return errors.New(s.persistence.LastError)
	}
	return nil
}

func (s *statusTracker) moduleStarting(name string, pid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	health := s.modules[name]
	health.Status = "running"
	health.PID = pid
	health.LastStartAt = time.Now().UTC().Format(time.RFC3339)
	health.LastError = ""
	health.NextRestartAt = ""
	health.CircuitOpenUntil = ""
	s.modules[name] = health
	s.writeLocked()
}

func (s *statusTracker) moduleStartFailed(name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	health := s.modules[name]
	health.Status = "error"
	health.PID = 0
	health.LastExitAt = time.Now().UTC().Format(time.RFC3339)
	health.LastError = errorString(err)
	s.modules[name] = health
	s.writeLocked()
}

func (s *statusTracker) moduleExited(name string, err error, restarting bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	health := s.modules[name]
	if restarting {
		health.Status = "restarting"
		health.RestartCount++
	} else if err != nil {
		health.Status = "error"
	} else {
		health.Status = "stopped"
	}
	health.PID = 0
	health.LastExitAt = time.Now().UTC().Format(time.RFC3339)
	health.LastError = errorString(err)
	s.modules[name] = health
	s.writeLocked()
}

func (s *statusTracker) moduleRestarting(name string, err error, delay time.Duration, failures int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	health := s.modules[name]
	health.Status = "restarting"
	health.PID = 0
	health.RestartCount++
	health.ConsecutiveFailures = failures
	health.LastExitAt = time.Now().UTC().Format(time.RFC3339)
	health.NextRestartAt = time.Now().UTC().Add(delay).Format(time.RFC3339)
	health.CircuitOpenUntil = ""
	health.LastError = errorString(err)
	s.modules[name] = health
	s.writeLocked()
}

func (s *statusTracker) moduleCircuitOpen(name string, err error, wait time.Duration, failures int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	health := s.modules[name]
	health.Status = "degraded"
	health.PID = 0
	health.RestartCount++
	health.ConsecutiveFailures = failures
	health.LastExitAt = time.Now().UTC().Format(time.RFC3339)
	health.NextRestartAt = ""
	health.CircuitOpenUntil = time.Now().UTC().Add(wait).Format(time.RFC3339)
	health.LastError = errorString(err)
	s.modules[name] = health
	s.writeLocked()
}

func (s *statusTracker) moduleFailuresReset(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	health := s.modules[name]
	health.ConsecutiveFailures = 0
	health.NextRestartAt = ""
	health.CircuitOpenUntil = ""
	s.modules[name] = health
	s.writeLocked()
}

func (s *statusTracker) licenseCheck(result agentlicense.Result, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.license.LastCheckAt = time.Now().UTC().Format(time.RFC3339)
	s.license.LastError = errorString(err)
	s.writeLockedWithDevice(result.State.DeviceID)
}

func (s *statusTracker) heartbeat(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.license.LastHeartbeatAt = time.Now().UTC().Format(time.RFC3339)
		s.license.LastError = ""
	} else {
		s.license.LastError = errorString(err)
	}
	s.writeLocked()
}

func (s *statusTracker) moduleSnapshot() map[string]agentlicense.ModuleHealth {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneModuleHealth(s.modules)
}

// readiness is the live service contract used by the metrics health endpoint.
// Unlike the stricter post-update probation check, a recovered module may be
// ready after a restart; historical restart counters therefore do not fail this
// check. Recoverable diagnostics, such as an unavailable audit reader, are
// cleared by their owner. Evidence-loss diagnostics remain sticky because
// records already overwritten by an audit backlog cannot be reconstructed.
func (s *statusTracker) readiness() (bool, string) {
	if s == nil {
		return false, "status tracker is unavailable"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.modules) == 0 {
		return false, "no collector modules are configured"
	}
	moduleNames := make([]string, 0, len(s.modules))
	for name := range s.modules {
		moduleNames = append(moduleNames, name)
	}
	sort.Strings(moduleNames)
	for _, name := range moduleNames {
		health := s.modules[name]
		if health.Status != "running" || health.PID <= 0 {
			return false, "module " + name + " is " + firstNonEmptyStatus(health.Status)
		}
	}
	if s.license.Enabled && strings.TrimSpace(s.license.LastError) != "" {
		return false, "authorization is degraded: " + s.license.LastError
	}
	if strings.TrimSpace(s.persistence.LastError) != "" {
		return false, "status persistence is degraded: " + s.persistence.LastError
	}
	diagnosticNames := make([]string, 0, len(s.diagnostics))
	for name := range s.diagnostics {
		diagnosticNames = append(diagnosticNames, name)
	}
	sort.Strings(diagnosticNames)
	for _, name := range diagnosticNames {
		diagnostic := s.diagnostics[name]
		if strings.EqualFold(strings.TrimSpace(diagnostic.Level), "error") {
			return false, "diagnostic " + name + ": " + diagnostic.Message
		}
	}
	return true, ""
}

func firstNonEmptyStatus(status string) string {
	if status = strings.TrimSpace(status); status != "" {
		return status
	}
	return "unknown"
}

func (s *statusTracker) allModulesRunning() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.modules) == 0 {
		return false
	}
	for _, health := range s.modules {
		if health.Status != "running" || health.PID <= 0 || health.RestartCount > 0 || health.ConsecutiveFailures > 0 {
			return false
		}
	}
	return true
}

func (s *statusTracker) setDiagnostic(name, level, message string, metrics map[string]uint64) {
	if s == nil || strings.TrimSpace(name) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.diagnostics[name] = statusDiagnostic{
		Level:     strings.TrimSpace(level),
		Message:   strings.TrimSpace(message),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Metrics:   metrics,
	}
	s.writeLocked()
}

// clearDiagnostic removes a recovered runtime condition and persists the same
// snapshot that readiness reads. Evidence-loss diagnostics intentionally never
// call this method because those failures cannot be repaired in-process.
func (s *statusTracker) clearDiagnostic(name string) {
	if s == nil || strings.TrimSpace(name) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.diagnostics[name]; !exists {
		return
	}
	delete(s.diagnostics, name)
	s.writeLocked()
}

func (s *statusTracker) writeLocked() {
	s.writeLockedWithDevice("")
}

// operationsSnapshot copies the status contract for the append-only health
// stream. The caller may inspect and encode the copy after releasing the lock.
func (s *statusTracker) operationsSnapshot() agentStatusFile {
	if s == nil {
		return agentStatusFile{}
	}
	s.mu.Lock()
	deviceID := s.deviceID
	statePath := s.statePath
	snapshot := s.snapshotLocked(deviceID, time.Now().UTC().Format(time.RFC3339), s.persistence)
	s.mu.Unlock()
	// Device state is read outside the status lock because it is a filesystem
	// operation and can be slow on encrypted or network-backed data directories.
	if snapshot.DeviceID == "" {
		if state, err := agentlicense.LoadState(statePath); err == nil {
			snapshot.DeviceID = state.DeviceID
		}
	}
	return snapshot
}

func (s *statusTracker) writeLockedWithDevice(deviceID string) {
	// Health publication is signaled without doing file IO under this lock. The
	// reporter takes a later copy, so rapid lifecycle and license changes are
	// coalesced into one later observation.
	s.signalHealthLocked()
	// An explicit result is used for this generation; later mutations clear the
	// hint and reload the durable license state, which remains device identity's
	// source of truth across enrollment replacement and process restarts.
	s.deviceID = strings.TrimSpace(deviceID)
	if s.writerStarted {
		if !s.writerClosed {
			select {
			case s.writeSignal <- struct{}{}:
			default:
			}
		}
		return
	}
	s.writeSynchronouslyLocked()
}

// signalHealthLocked performs a non-blocking edge notification while the
// tracker mutex is owned. The single buffered slot bounds transition pressure:
// the reporter always reads a fresh snapshot instead of replaying stale states.
func (s *statusTracker) signalHealthLocked() {
	if s.healthSignal == nil {
		return
	}
	select {
	case s.healthSignal <- struct{}{}:
	default:
	}
}

// writeSynchronouslyLocked preserves deterministic behavior before the
// long-lived writer starts. It is used for the initial status file and focused
// tests only; production state transitions use runWriter instead.
func (s *statusTracker) writeSynchronouslyLocked() {
	if strings.TrimSpace(s.path) == "" {
		return
	}
	deviceID := s.deviceID
	if deviceID == "" {
		if state, err := agentlicense.LoadState(s.statePath); err == nil {
			deviceID = state.DeviceID
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	persistence := s.persistence
	persistence.LastAttemptAt = now
	persistence.LastSuccessAt = now
	persistence.LastError = ""
	payload := s.snapshotLocked(deviceID, now, persistence)
	err := s.writeFile(s.path, payload, 0600)
	_ = s.recordWriteResultLocked(now, err)
}

// runWriter is the sole production owner of status-file IO. A failed write
// remains dirty and retries every interval; successful writes clear readiness
// degradation. Stop always performs one final attempt even if no tick is due.
func (s *statusTracker) runWriter() {
	interval := s.writeInterval
	if interval <= 0 {
		interval = statusWriteInterval
	}
	ticker := time.NewTicker(interval)
	defer func() {
		ticker.Stop()
		close(s.writeDone)
	}()
	dirty := false
	for {
		select {
		case <-s.writeSignal:
			dirty = true
		case <-ticker.C:
			if dirty {
				dirty = s.flushSnapshot() != nil
			}
		case <-s.writeStop:
			// State may have changed just before close without its signal being
			// selected, so shutdown deliberately flushes unconditionally.
			_ = s.flushSnapshot()
			return
		}
	}
}

// flushSnapshot copies state under the lock and performs state lookup and disk
// IO after releasing it. The payload records the success it is about to become;
// if the write fails, the old on-disk snapshot remains authoritative.
func (s *statusTracker) flushSnapshot() error {
	now := time.Now().UTC().Format(time.RFC3339)
	s.mu.Lock()
	deviceID := s.deviceID
	statePath := s.statePath
	persistence := s.persistence
	persistence.LastAttemptAt = now
	persistence.LastSuccessAt = now
	persistence.LastError = ""
	payload := s.snapshotLocked(deviceID, now, persistence)
	path := s.path
	writeFile := s.writeFile
	s.mu.Unlock()

	if payload.DeviceID == "" {
		if state, err := agentlicense.LoadState(statePath); err == nil {
			payload.DeviceID = state.DeviceID
		}
	}
	err := writeFile(path, payload, 0600)
	s.mu.Lock()
	shouldLog := s.recordWriteResultLocked(now, err)
	s.mu.Unlock()
	if err != nil && shouldLog {
		fmt.Fprintf(os.Stderr, "status persistence failed; retrying: path=%s err=%v\n", path, err)
	}
	return err
}

func (s *statusTracker) snapshotLocked(deviceID, now string, persistence statusPersistence) agentStatusFile {
	return agentStatusFile{
		SchemaVersion: "1",
		Time:          now,
		AgentVersion:  version,
		EnterpriseID:  s.enterpriseID,
		DeviceID:      deviceID,
		License:       s.license,
		Modules:       cloneModuleHealth(s.modules),
		Diagnostics:   cloneDiagnostics(s.diagnostics),
		Persistence:   persistence,
	}
}

func (s *statusTracker) recordWriteResultLocked(attemptAt string, err error) bool {
	wasFailing := s.persistence.LastError != ""
	s.persistence.LastAttemptAt = attemptAt
	if err == nil {
		s.persistence.LastSuccessAt = attemptAt
		s.persistence.LastError = ""
		s.lastErrorLog = time.Time{}
		if wasFailing {
			s.signalHealthLocked()
		}
		return false
	}
	s.persistence.LastError = err.Error()
	s.persistence.ErrorCount++
	if !wasFailing {
		s.signalHealthLocked()
	}
	now := time.Now()
	if s.lastErrorLog.IsZero() || now.Sub(s.lastErrorLog) >= statusWriteErrorLogInterval {
		s.lastErrorLog = now
		return true
	}
	return false
}

func writeJSONAtomic(path string, payload interface{}, perm os.FileMode) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		return os.Rename(tmpName, path)
	}
	return nil
}

func cloneModuleHealth(in map[string]agentlicense.ModuleHealth) map[string]agentlicense.ModuleHealth {
	out := make(map[string]agentlicense.ModuleHealth, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneDiagnostics(in map[string]statusDiagnostic) map[string]statusDiagnostic {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]statusDiagnostic, len(in))
	for key, value := range in {
		if value.Metrics != nil {
			metrics := make(map[string]uint64, len(value.Metrics))
			for metricKey, metricValue := range value.Metrics {
				metrics[metricKey] = metricValue
			}
			value.Metrics = metrics
		}
		out[key] = value
	}
	return out
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
