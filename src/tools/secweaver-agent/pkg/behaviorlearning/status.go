package behaviorlearning

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"
)

// StatusSnapshot is the bounded operational view sent in the managed heartbeat.
// It intentionally contains progress and mode only; baseline fingerprints and
// command arguments never leave the host through this status object.
type StatusSnapshot struct {
	Enabled          bool    `json:"enabled"`
	Mode             string  `json:"mode"`
	Shadow           bool    `json:"shadow"`
	StartedAt        string  `json:"started_at,omitempty"`
	RemainingSeconds int64   `json:"remaining_seconds,omitempty"`
	FilteringActive  bool    `json:"filtering_active"`
	HealthySeconds   float64 `json:"healthy_seconds,omitempty"`
	BaselineEntries  int     `json:"baseline_entries,omitempty"`
	CandidateEntries int     `json:"candidate_entries,omitempty"`
	Reason           string  `json:"reason,omitempty"`
	UpdatedAt        string  `json:"updated_at,omitempty"`
}

// policyHash excludes installation paths and activation choices. Switching
// shadow/enabled preserves a qualified baseline; changing matching semantics
// requires an explicit new generation, in both the engine and diagnostics.
func policyHash(cfg Config) string {
	if cfg.simpleExec {
		// Unused legacy admission controls cannot invalidate a simple baseline.
		cfg.MinOccurrences, cfg.MinHours, cfg.MinSpan, cfg.ExpiryDays = 0, 0, 0, 0
	}
	cfg.StateDir, cfg.OutputLog = "", ""
	cfg.Enabled, cfg.Shadow, cfg.Generation = false, false, 0
	body, _ := json.Marshal(cfg)
	if cfg.simpleExec {
		body = append(body, []byte(cfg.simpleStrategy())...)
	}
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

// legacyPolicyHash is only used to authenticate an automatic one-time migration
// of an otherwise unchanged Linux/Windows policy. It never permits foreign state.
func legacyPolicyHash(cfg Config) string {
	cfg.simpleExec = false
	return policyHash(cfg)
}

// Inspect reads an atomic authenticated checkpoint without taking the writer
// lock. It never creates files or resets progress while the collector is live.
func Inspect(dir string, budgetMB int) (*State, error) {
	if budgetMB < 8 || budgetMB > 256 {
		return nil, fmt.Errorf("invalid state budget")
	}
	s := &Store{dir: dir, limit: int64(budgetMB) << 20}
	key, err := s.read("key", 32)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("learning key unavailable")
	}
	s.Key = key
	state, err := s.Load()
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, fmt.Errorf("learning has not initialized")
	}
	return state, nil
}

// ReadLatestSummary reads only a bounded tail of the summary file. Heartbeats
// run periodically, so scanning the complete rotating log would turn a status
// probe into an avoidable disk and CPU cost on busy hosts.
func ReadLatestSummary(path string) (*Summary, error) {
	return ReadBaselineSummary(path, "")
}

// WriteLatestSummary replaces one local runtime observation instead of appending
// an uploadable log. The adapter must hold its learning-state directory lock;
// the file inherits protected Windows ACLs and uses mode 0600 on Unix. Only the
// bounded status record is allowed, never per-behavior aggregates or commands.
func WriteLatestSummary(path string, summary Summary) error {
	if summary.EventType != "behavior_learning_status" || summary.Fingerprint != "" {
		return fmt.Errorf("latest learning summary must be a runtime status")
	}
	body, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	if len(body) > 16<<10 {
		return fmt.Errorf("latest learning status exceeds 16 KiB")
	}
	return writeStateFile(path, append(body, '\n'))
}

// ReadBaselineSummary selects one independent baseline from a shared rotating
// summary log. An empty baseline preserves the legacy unfiltered status reader.
func ReadBaselineSummary(path, baseline string) (*Summary, error) {
	// Reject nonregular paths before opening: a misconfigured FIFO must not
	// block a heartbeat waiting for a writer.
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("learning summary must be a regular file")
	}
	f, err := openSummaryFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("learning summary must be a regular file")
	}
	const tailBytes int64 = 128 << 10
	if info.Size() > tailBytes {
		if _, err := f.Seek(-tailBytes, io.SeekEnd); err != nil {
			return nil, err
		}
	}
	// Fix the read budget even if the collector appends while we inspect it.
	scanner := bufio.NewScanner(io.LimitReader(f, tailBytes))
	scanner.Buffer(make([]byte, 4096), 128<<10)
	var latest *Summary
	for scanner.Scan() {
		var candidate Summary
		if json.Unmarshal(scanner.Bytes(), &candidate) != nil {
			continue
		}
		if candidate.EventType != "behavior_learning_status" && candidate.EventType != "behavior_summary" {
			continue
		}
		if baseline != "" && candidate.BaselineID != baseline {
			continue
		}
		if latest == nil || candidate.Time.After(latest.Time) {
			copy := candidate
			latest = &copy
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if latest == nil {
		return nil, fmt.Errorf("learning summary has no status record")
	}
	return latest, nil
}

// InspectStatus combines independent state with its own summary, without a
// writer lock or full log scan. Disabled streams do not require state files.
func InspectStatus(cfg Config) (StatusSnapshot, error) {
	if !cfg.Enabled {
		return Snapshot(cfg, nil, nil, time.Now()), nil
	}
	state, err := Inspect(cfg.StateDir, cfg.StateMB)
	if err != nil {
		return Snapshot(cfg, nil, nil, time.Now()), err
	}
	latest, _ := ReadBaselineSummary(cfg.OutputLog, state.BaselineID)
	return Snapshot(cfg, state, latest, time.Now()), nil
}

// Snapshot combines authenticated state with the latest runtime summary. A
// missing or stale summary never claims filtering is active, which prevents a
// SaaS inventory page from displaying a false sense of protection after a
// collector failure.
func Snapshot(cfg Config, state *State, latest *Summary, now time.Time) StatusSnapshot {
	if !cfg.Enabled {
		return StatusSnapshot{Mode: "disabled", Reason: "disabled"}
	}
	result := StatusSnapshot{Enabled: true, Shadow: cfg.Shadow, Mode: "unknown", Reason: "state_unavailable"}
	if state == nil {
		return result
	}
	if state.Generation != cfg.Generation || state.Policy != policyHash(cfg) {
		result.Reason = "policy_changed_explicit_relearn_required"
		return result
	}
	result.Mode = state.Mode
	result.Shadow = cfg.Shadow
	if !state.Started.IsZero() {
		result.StartedAt = state.Started.UTC().Format(time.RFC3339)
	}
	result.HealthySeconds = state.HealthySeconds
	result.BaselineEntries = len(state.Entries)
	result.CandidateEntries = len(state.Candidates)
	result.Reason = strings.TrimSpace(state.Reason)
	if result.Mode == "learning" {
		remaining := int64(math.Ceil(float64(cfg.LearningSeconds) - state.HealthySeconds))
		if remaining > 0 {
			result.RemainingSeconds = remaining
		}
	}
	// Rotation and explicit relearning can leave an older generation in the
	// log. Only a matching device/baseline may qualify the runtime observation.
	if latest == nil || latest.DeviceID != state.Device || latest.BaselineID != state.BaselineID {
		return result
	}
	result.UpdatedAt = latest.Time.UTC().Format(time.RFC3339)
	if strings.TrimSpace(latest.Reason) != "" {
		result.Reason = latest.Reason
	}
	// A stale status is never treated as proof that filtering remains active.
	age := now.Sub(latest.Time)
	if !state.CleanShutdown && !latest.Time.IsZero() && age >= 0 && age <= 2*time.Duration(cfg.SummarySeconds)*time.Second {
		filterable := state.Mode == "enforcing" || (cfg.simpleExec && state.Mode == "learning")
		result.FilteringActive = latest.FilteringActive && latest.SourceHealthy && !cfg.Shadow && !latest.Shadow && filterable && latest.Mode == state.Mode
	}
	return result
}
