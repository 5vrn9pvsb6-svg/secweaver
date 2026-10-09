// Package behaviorlearning implements bounded, per-device behavior baselines.
// It never controls kernel collection; source or storage faults restore original
// output. Linux exec command-quality diagnostics alone do not prevent matching.
package behaviorlearning

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
)

// Config is an opt-in contract for existing installations. Packaged new-install
// configurations explicitly enable it; omission must not change upgrade behavior.
type Config struct {
	// Simple policies are adapter-selected, never user-supplied JSON switches.
	// simpleExec enables the shared exact engine; simpleKind selects the stable
	// tuple. Keeping this selector private prevents an untrusted config from
	// bypassing the adapter that selects and validates the stream's tuple.
	simpleExec         bool
	simpleFile         bool
	fileWindows        bool
	simpleKind         string
	eventTypesExplicit bool
	Enabled            bool     `json:"enabled"`
	StateDir           string   `json:"state_dir,omitempty"`
	OutputLog          string   `json:"output_log,omitempty"`
	LearningSeconds    int      `json:"learning_duration_seconds"`
	OnlineDeadline     int      `json:"learning_online_deadline_seconds"`
	Activation         string   `json:"activation"`
	EventTypes         []string `json:"event_types"`
	// FileRoots remains parseable for legacy policies. Exact file matching does
	// not use roots or suffixes as an admission gate.
	FileRoots      []string `json:"file_roots,omitempty"`
	MinOccurrences int      `json:"min_occurrences"`
	MinHours       int      `json:"min_distinct_hours"`
	MinSpan        int      `json:"min_span_seconds"`
	SummarySeconds int      `json:"summary_interval_seconds"`
	ExpiryDays     int      `json:"baseline_idle_expiry_days"`
	MaxEntries     int      `json:"max_baseline_entries"`
	MaxCandidates  int      `json:"max_candidate_entries"`
	MemoryMB       int      `json:"memory_budget_mb"`
	StateMB        int      `json:"state_budget_mb"`
	OnError        string   `json:"on_error"`
	// Generation is an explicit relearn request. It must increase, never decrease.
	Generation uint64 `json:"generation,omitempty"`
	Shadow     bool   `json:"shadow,omitempty"`
}

// Decode rejects unknown learning fields without rejecting the outer collector
// configuration. The caller reports the error and retains full collection.
func Decode(raw json.RawMessage) (Config, error) {
	return decode(raw, false)
}

// DecodeExec selects the Linux four-field policy for both old and new configs.
// Omitted enabled still means disabled; old admission knobs remain parseable.
func DecodeExec(raw json.RawMessage) (Config, error) {
	c, err := decode(raw, true)
	if err != nil {
		return c, err
	}
	c.simpleKind = "exec"
	return c.Normalize()
}

func decode(raw json.RawMessage, simpleExec bool) (Config, error) {
	c := Config{simpleExec: simpleExec}
	if len(raw) == 0 {
		return c, nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, fmt.Errorf("trailing learning configuration")
	}
	c.eventTypesExplicit = len(c.EventTypes) > 0
	return c.Normalize()
}

// Normalize applies defaults and bounds all user-controlled allocations.
func (c Config) Normalize() (Config, error) {
	defaults := []struct {
		p *int
		v int
	}{
		{&c.LearningSeconds, 86400}, {&c.OnlineDeadline, 259200}, {&c.MinOccurrences, 5},
		{&c.MinHours, 3}, {&c.MinSpan, 21600}, {&c.SummarySeconds, 300}, {&c.ExpiryDays, 30},
		{&c.MaxEntries, 10000}, {&c.MaxCandidates, 20000}, {&c.MemoryMB, 64}, {&c.StateMB, 64},
	}
	for _, d := range defaults {
		if *d.p == 0 {
			*d.p = d.v
		}
	}
	if c.Activation == "" {
		c.Activation = "auto_eligible"
	}
	if c.OnError == "" {
		c.OnError = "emit"
	}
	if len(c.EventTypes) == 0 {
		c.EventTypes = []string{"exec"}
	}
	seen := map[string]bool{}
	for _, eventType := range c.EventTypes {
		if (eventType != "exec" && eventType != "active_connect" && eventType != "file_op" && eventType != "powershell_script_block") || seen[eventType] {
			return c, fmt.Errorf("invalid or duplicate learning event type %q", eventType)
		}
		seen[eventType] = true
	}
	// Canonical ordering prevents a cosmetic reorder from invalidating state.
	c.EventTypes = append([]string(nil), c.EventTypes...)
	sort.Strings(c.EventTypes)
	if len(c.FileRoots) > 16 {
		return c, fmt.Errorf("too many learning file roots")
	}
	for _, root := range c.FileRoots {
		if !validFileRoot(root) {
			return c, fmt.Errorf("learning file roots must be absolute non-root directories without wildcards")
		}
	}
	// The simple policy always uses five occurrences within 3600 seconds. Old
	// bucket/span settings must not prevent a one-hour learning duration.
	invalidLegacy := !c.simpleExec && (c.MinOccurrences < 2 || c.MinHours < 2 || c.MinHours > 168 ||
		c.MinHours*3600 > c.LearningSeconds || c.MinSpan < 3600 || c.MinSpan > c.LearningSeconds)
	if c.LearningSeconds < 3600 || c.LearningSeconds > 604800 || c.OnlineDeadline < c.LearningSeconds || c.OnlineDeadline > 2592000 ||
		invalidLegacy || c.SummarySeconds < 60 || c.SummarySeconds > 3600 ||
		c.ExpiryDays < 1 || c.ExpiryDays > 365 || c.MaxEntries < 1 || c.MaxEntries > 10000 ||
		c.MaxCandidates < c.MaxEntries || c.MaxCandidates > 20000 || c.MemoryMB < 8 || c.MemoryMB > 256 ||
		c.StateMB < 8 || c.StateMB > 256 || c.Activation != "auto_eligible" || c.OnError != "emit" {
		return c, fmt.Errorf("invalid behavior_learning thresholds or unsupported policy")
	}
	for _, p := range []string{c.StateDir, c.OutputLog} {
		if p != "" && !filepath.IsAbs(p) {
			return c, fmt.Errorf("learning paths must be absolute")
		}
	}
	return c, nil
}
