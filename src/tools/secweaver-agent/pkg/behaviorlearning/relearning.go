package behaviorlearning

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"secweaver-agent/pkg/learningoperation"
)

// RelearningWindow is part of authenticated checkpoint v2, never a remote
// configuration. Bases do not reset lifetime counters or the policy hash.
type RelearningWindow struct {
	OperationID     string    `json:"operation_id"`
	Sequence        string    `json:"sequence"`
	Digest          string    `json:"digest"`
	Stream          string    `json:"stream"`
	State           string    `json:"state"`
	Reason          string    `json:"reason,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	Deadline        time.Time `json:"deadline"`
	HealthyBase     float64   `json:"healthy_base"`
	OnlineBase      float64   `json:"online_base"`
	RetainedEntries int       `json:"retained_entries"`
}

// baselineToken identifies the intact generation/policy without exporting any
// individual fingerprint or scanning the entries on each heartbeat.
func baselineToken(s *State) string {
	if s == nil {
		return ""
	}
	b, _ := json.Marshal([]any{s.Device, s.BaselineID, s.Generation, s.Policy, s.Strategy})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// validateRelearningState prevents an unknown format/window being mistaken for
// a fresh installation, including on downgrade and damaged local state.
func validateRelearningState(s State) error {
	if s.Version == 1 && s.Relearning == nil {
		return nil
	}
	w := s.Relearning
	if s.Version != 2 || w == nil {
		return fmt.Errorf("incompatible relearning checkpoint")
	}
	if _, err := learningoperation.SequenceValue(w.Sequence); err != nil {
		return err
	}
	digest, digestErr := hex.DecodeString(w.Digest)
	if w.OperationID == "" || !learningoperation.StreamKnown(w.Stream) || digestErr != nil || len(digest) != 32 || w.StartedAt.IsZero() ||
		!w.Deadline.After(w.StartedAt) || w.Deadline.Sub(w.StartedAt) > 7*24*time.Hour ||
		math.IsNaN(w.HealthyBase) || math.IsInf(w.HealthyBase, 0) || w.HealthyBase < 0 ||
		math.IsNaN(w.OnlineBase) || math.IsInf(w.OnlineBase, 0) || w.OnlineBase < 0 ||
		w.HealthyBase > s.HealthySeconds || w.OnlineBase > s.OnlineSeconds || w.RetainedEntries < 0 ||
		(w.State != "learning" && w.State != "completed" && w.State != "expired" && w.State != "failed") {
		return fmt.Errorf("invalid relearning checkpoint")
	}
	return nil
}

// RelearningEligibility is called by the existing bounded worker. It neither
// mutates state nor grants permission; ApplyRelearning rechecks under the lock.
func (e *Engine) RelearningEligibility() (token, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return baselineToken(&e.state), e.relearningReason(e.now())
}

func (e *Engine) relearningReason(now time.Time) string {
	switch {
	case e.closed:
		return "collector_stopped"
	case !e.cfg.Enabled:
		return "disabled"
	case e.cfg.Shadow:
		return "shadow"
	case !e.cfg.simpleExec || !simpleStrategyKnown(e.state.Strategy):
		return "unsupported_policy"
	case e.pendingFault.Load() != nil || e.persistenceErr != nil:
		return "degraded"
	case e.state.Relearning != nil && e.state.Relearning.State == "learning":
		return "learning"
	case e.state.Mode != "enforcing":
		return e.state.Mode
	case !e.sourceHealthy(now):
		return "source_unhealthy"
	default:
		return ""
	}
}

// ApplyRelearning is invoked only by the sole evidence-owner worker, never by
// the parent process or source reader. Signatures/binding are rechecked here so
// a forged inbox cannot acquire the writer's authority. All disk I/O owns mu
// and the lifetime Store lock; no service/collector restart is involved.
func (e *Engine) ApplyRelearning(g learningoperation.Grant, stream, public, eid, installation string) (learningoperation.StreamResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := g.VerifyIdentity(public, eid, e.state.Device, installation); err != nil {
		return learningoperation.StreamResult{}, err
	}
	seq, _ := learningoperation.SequenceValue(g.Sequence)
	if prior := e.state.Relearning; prior != nil {
		old, _ := learningoperation.SequenceValue(prior.Sequence)
		if seq == old {
			if prior.OperationID != g.OperationID || prior.Digest != g.Digest || prior.Stream != stream {
				return learningoperation.StreamResult{}, fmt.Errorf("relearning replay conflict")
			}
			// Expired transport is valid only for returning an already durable fact.
			return relearningResult(e.state), nil
		}
		if seq < old {
			return learningoperation.StreamResult{}, fmt.Errorf("stale relearning sequence")
		}
	}
	now := e.now()
	if !g.CanStart(now) {
		return learningoperation.StreamResult{}, fmt.Errorf("relearning start permission expired")
	}
	if reason := e.relearningReason(now); reason != "" {
		return learningoperation.StreamResult{}, fmt.Errorf("relearning not eligible: %s", reason)
	}
	if stream != relearningStream(e.state.Strategy) {
		return learningoperation.StreamResult{}, fmt.Errorf("relearning stream mismatch")
	}
	targetToken := ""
	for _, target := range g.Targets {
		if target.Stream == stream {
			targetToken = target.BaselineToken
		}
	}
	if targetToken == "" || targetToken != baselineToken(&e.state) {
		return learningoperation.StreamResult{}, fmt.Errorf("relearning baseline changed")
	}
	if err := e.store.backupRelearning(e.state); err != nil {
		return learningoperation.StreamResult{}, err
	}
	deadline := now.Add(7 * 24 * time.Hour)
	if g.RunNotAfter.Before(deadline) {
		deadline = g.RunNotAfter
	}
	// Copy the state header; never mutate the trusted entries/key. Candidates
	// belong to this window, while native source-ID dedup must survive it.
	next := e.state
	// Enforcing time before acceptance is lifetime online time, not additional
	// learning time. Align the timer origin with this exact acceptance instant.
	if elapsed := now.Sub(e.lastTick).Seconds(); elapsed >= 0 {
		next.OnlineSeconds += elapsed
	} else {
		return learningoperation.StreamResult{}, fmt.Errorf("relearning clock regression")
	}
	next.Version, next.Mode, next.Reason = 2, "learning", ""
	next.Candidates = map[string]*Entry{}
	next.Relearning = &RelearningWindow{OperationID: g.OperationID, Sequence: g.Sequence, Digest: g.Digest, Stream: stream,
		State: "learning", StartedAt: now, Deadline: deadline, HealthyBase: next.HealthySeconds, OnlineBase: next.OnlineSeconds, RetainedEntries: len(next.Entries)}
	if err := e.store.Commit(next); err != nil {
		// A rename may already have succeeded before fsync/compaction failed.
		// Invalidate this writer rather than issue a second start with ambiguity.
		e.faultLocked("relearning_checkpoint_failed")
		return learningoperation.StreamResult{}, e.persistenceFailed(err, now)
	}
	e.state, e.lastSave = next, now
	e.lastTick = now
	return relearningResult(e.state), nil
}

// relearningStream binds the native engine policy, not merely a caller-supplied
// label. A valid grant for another collector cannot mutate this engine.
func relearningStream(strategy string) string {
	switch strategy {
	case simpleExecStrategy, simpleWindowsExecStrategy:
		return "exec"
	case simpleLinuxFileStrategy, simpleWindowsFileStrategy:
		return "file"
	case simpleNetworkStrategy:
		return "network"
	case simpleScriptStrategy:
		return "risk"
	default:
		return ""
	}
}

// finishRelearning runs under the engine lock on both timer and event paths.
// Checking the hard deadline before admission prevents a delayed timer from
// admitting new tuples after the signed window has ended.
func (e *Engine) finishRelearning(now time.Time) {
	w := e.state.Relearning
	if w == nil || w.State != "learning" || e.state.Mode != "learning" {
		return
	}
	if now.Before(e.lastTick) {
		e.faultLocked("clock_regression")
		return
	}
	if !now.Before(w.Deadline) || e.state.OnlineSeconds-w.OnlineBase >= 259200 {
		w.State, w.Reason = "expired", "relearning_deadline"
		e.freeze(now)
	} else if e.state.HealthySeconds-w.HealthyBase >= 86400 {
		w.State = "completed"
		e.freeze(now)
	}
}

// relearningResult projects only persisted counters when called by Inspect.
// Runtime faults override a stale learning label, never manufacture completion.
func relearningResult(s State) learningoperation.StreamResult {
	w := s.Relearning
	if w == nil {
		return learningoperation.StreamResult{}
	}
	healthy := int64(math.Floor(math.Max(0, s.HealthySeconds-w.HealthyBase)))
	if healthy > 86400 {
		healthy = 86400
	}
	state, reason := w.State, w.Reason
	if s.Mode == "degraded" {
		state, reason = "failed", s.Reason
	}
	return learningoperation.StreamResult{State: state, Reason: reason, StartedAt: w.StartedAt, HealthySeconds: healthy,
		RemainingSeconds: 86400 - healthy, RetainedEntries: w.RetainedEntries, AddedEntries: max(0, len(s.Entries)-w.RetainedEntries)}
}

// ReadRelearningResult uses the authenticated checkpoint, not an in-memory
// acknowledgement. Readers never take another writer lock or initialize state.
func ReadRelearningResult(cfg Config) (*RelearningWindow, learningoperation.StreamResult, error) {
	s, err := Inspect(cfg.StateDir, cfg.StateMB)
	if err != nil {
		return nil, learningoperation.StreamResult{}, err
	}
	return s.Relearning, relearningResult(*s), nil
}

// backupRelearning keeps one self-contained, private pre-window recovery bundle
// including the HMAC key and journal. Existing trusted files are never deleted
// to make space. Include old+replacement backup and a replacement checkpoint in
// the preflight budget; atomic replacement verifies durability before success.
func (s *Store) backupRelearning(state State) error {
	state.CleanShutdown = true // maintenance restore has no uncheckpointed writer
	checkpoint, err := json.Marshal(state)
	if err != nil {
		return err
	}
	journal, err := s.read("admissions.jsonl", s.limit/3)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err != nil && simpleStrategyKnown(state.Strategy) {
		return err
	}
	payload, err := json.Marshal(struct {
		Version int             `json:"backup_version"`
		State   json.RawMessage `json:"state"`
		Key     []byte          `json:"key"`
		Journal []byte          `json:"journal"`
	}{1, checkpoint, s.Key, journal})
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, s.Key)
	mac.Write(payload)
	bundle, err := json.Marshal(struct {
		Payload json.RawMessage `json:"payload"`
		MAC     string          `json:"hmac_sha256"`
	}{payload, hex.EncodeToString(mac.Sum(nil))})
	if err != nil {
		return err
	}
	// Reserve a complete replacement checkpoint as well as both backup copies.
	// Later journal/checkpoint writes continue enforcing this aggregate budget.
	if err := s.relearningBudget(int64(len(bundle)) + s.limit/3); err != nil {
		return err
	}
	return s.atomic("relearning-backup.json", bundle)
}

var (
	errLearningStateLayout = errors.New("unexpected learning state file")
	errRelearningBudget    = errors.New("relearning state budget exceeded")
)

// independentChildStore recognizes only adapter-defined child stores of exec.
// They have separate locks and budgets: never traverse, charge, or clean their
// contents while holding the parent lock. Other policies/coordination stay flat.
func (s *Store) independentChildStore(name string) bool {
	switch s.strategy {
	case simpleExecStrategy:
		return name == fileStoreDirectory
	case simpleWindowsExecStrategy:
		return name == fileStoreDirectory || name == networkStoreDirectory
	default:
		return false
	}
}

// relearningBudget counts this writer's files, old backups and replacement
// peaks without deleting trusted state. Known child stores are independent;
// Lstat still rejects symlinks, unexpected directories and special files. The
// lifetime Store lock serializes this stream's writes, not child-store writes.
func (s *Store) relearningBudget(extra int64) error {
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	used := extra
	if s.limit >= 8<<20 {
		used += 128 << 10
	} // fixed shared inbox/outbox peak reservation
	for _, file := range files {
		info, err := os.Lstat(filepath.Join(s.dir, file.Name()))
		if err != nil {
			return err
		}
		if s.independentChildStore(file.Name()) && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: %s", errLearningStateLayout, file.Name())
		}
		used += info.Size()
	}
	if used > s.limit {
		return errRelearningBudget
	}
	return nil
}
