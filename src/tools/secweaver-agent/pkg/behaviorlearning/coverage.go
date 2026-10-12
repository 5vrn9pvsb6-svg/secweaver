package behaviorlearning

import (
	"encoding/json"
	"time"
)

// EngineCoverage counts calls to one exact-policy engine since its startup.
// It excludes adapter bypasses/queue overflow and upstream loss, so it is not
// a host-wide collection denominator. Values are cumulative, not additive
// across status samples; RunID changes on restart without resetting a baseline.
// Engine.mu owns all counters; no command, path or fingerprint is recorded.
type EngineCoverage struct {
	RunID          string `json:"run_id"`
	StartedAt      string `json:"started_at"`
	Inputs         uint64 `json:"inputs"`
	Duplicates     uint64 `json:"duplicates"`
	Qualified      uint64 `json:"qualified"`
	Rejected       uint64 `json:"rejected"`
	BaselineMisses uint64 `json:"baseline_misses"`
	Suppressed     uint64 `json:"suppressed"`
	Emitted        uint64 `json:"emitted"`
	OutputErrors   uint64 `json:"output_errors"`
}

// coverageSnapshot copies under Engine.mu so later events cannot mutate an
// already published summary. Legacy engine counters keep their old contract.
func (e *Engine) coverageSnapshot() *EngineCoverage {
	if !e.cfg.simpleExec {
		return nil
	}
	snapshot := e.coverage
	return &snapshot
}

// emitCoveredOriginal counts successful sink writes separately from attempts.
// It does not alter the caller's existing fault/degradation policy.
func (e *Engine) emitCoveredOriginal(raw json.RawMessage) error {
	err := e.original(raw)
	if err != nil {
		e.coverage.OutputErrors++
	} else {
		e.coverage.Emitted++
	}
	return err
}

func newEngineCoverage(runID string, now time.Time) EngineCoverage {
	return EngineCoverage{RunID: runID, StartedAt: now.UTC().Format(time.RFC3339)}
}
