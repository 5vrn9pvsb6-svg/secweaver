package behaviorlearning

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"secweaver-agent/pkg/learningoperation"
)

// RelearningDataEnv binds workers to the supervisor-owned installation data root.
const RelearningDataEnv = "SECWEAVER_RELEARNING_DATA"

// RelearningInstallationEnv prevents grants following a replaced installation.
const RelearningInstallationEnv = "SECWEAVER_RELEARNING_INSTALLATION"

// operationDirectory accepts only an installation-owned data root. The wire
// format has no path field. Readers never create/chmod directories or follow a
// symlink; writers establish the same private ACL contract as learning stores.
func operationDirectory(data string, create bool) (string, error) {
	if !filepath.IsAbs(data) {
		return "", fmt.Errorf("invalid operation data root")
	}
	dir := filepath.Join(data, "learning-operations")
	if create {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return "", err
		}
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("invalid operation directory")
	}
	if create {
		if err := protectStateDirectory(dir); err != nil {
			return "", err
		}
	}
	if !operationDirectoryPrivate(dir, st) {
		return "", fmt.Errorf("insecure operation directory")
	}
	return dir, nil
}

// ReadOperationFile reads a fixed bounded coordination file, never an Agent key or
// engine checkpoint. The coordinator has no learning-store writer authority.
func ReadOperationFile(data, name string) ([]byte, error) {
	limit := operationFileLimit(name)
	if limit == 0 {
		return nil, fmt.Errorf("invalid operation file")
	}
	dir, err := operationDirectory(data, false)
	if err != nil {
		return nil, err
	}
	s := Store{dir: dir, limit: 64 << 10}
	return s.read(name, int64(limit))
}

// WriteOperationFile is called under the parent's config mutation lock. Both
// fixed files and their replacement peaks fit a reserved 128-KiB budget; no
// cleanup deletes the last trusted file on failure.
func WriteOperationFile(data, name string, body []byte) error {
	limit := operationFileLimit(name)
	if limit == 0 || len(body) > limit {
		return fmt.Errorf("invalid operation file")
	}
	dir, err := operationDirectory(data, true)
	if err != nil {
		return err
	}
	s := Store{dir: dir, limit: 128 << 10}
	if err := s.relearningBudget(int64(len(body))); err != nil {
		return err
	}
	return writeStateFile(filepath.Join(dir, name), body)
}

// Fixed per-file maxima bound concurrent replacement peaks even though parent
// and four independent sole-writer collectors do not share a process mutex.
func operationFileLimit(name string) int {
	switch name {
	case "current.json":
		return 16 << 10
	case "receipt.json":
		return 8 << 10
	case "exec.json", "file.json", "network.json", "risk.json":
		return 4 << 10
	default:
		return 0
	}
}

// RelearningRefusal is written only after a valid bound permit was refused by
// its sole engine owner. Absence is unknown, not proof of non-execution.
type RelearningRefusal struct {
	OperationID string                         `json:"operation_id"`
	Sequence    string                         `json:"sequence"`
	Digest      string                         `json:"digest"`
	Result      learningoperation.StreamResult `json:"result"`
}

// PollRelearningInbox runs on an existing bounded collector worker, not the
// native source reader. A five-second cadence fits the 30-second permit and a
// content watermark avoids repeated signature verification or disk commits.
// Missing environment/inbox is the backwards-compatible unmanaged mode.
func (e *Engine) PollRelearningInbox() error {
	data := os.Getenv(RelearningDataEnv)
	if data == "" {
		return nil
	}
	now := e.now()
	if now.Before(e.inboxPollAfter) {
		return nil
	}
	e.inboxPollAfter = now.Add(5 * time.Second)
	body, err := ReadOperationFile(data, "current.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if sum == e.inboxDigest {
		return nil
	}
	g, err := learningoperation.Decode(body)
	if err != nil {
		return err
	}
	public, eid, installation := os.Getenv("SECWEAVER_COLLECTION_PUBLIC_KEY"), os.Getenv("SECWEAVER_ENTERPRISE_ID"), os.Getenv(RelearningInstallationEnv)
	if err := g.VerifyIdentity(public, eid, e.state.Device, installation); err != nil {
		return err
	}
	stream := relearningStream(e.state.Strategy)
	wanted := false
	for _, target := range g.Targets {
		if target.Stream == stream {
			wanted = true
		}
	}
	if !wanted {
		e.inboxDigest = sum
		return nil
	}
	// A durable refusal is terminal for this identity, including after restart
	// or transport renewal. A later healthy collector must not turn an already
	// reported rejection into an untracked start of the same operation.
	if raw, readErr := ReadOperationFile(data, stream+".json"); readErr == nil {
		var prior RelearningRefusal
		if json.Unmarshal(raw, &prior) != nil {
			return fmt.Errorf("invalid relearning refusal")
		}
		if prior.OperationID == g.OperationID && prior.Sequence == g.Sequence && prior.Digest == g.Digest && prior.Result.State == "rejected" {
			e.inboxDigest = sum
			return nil
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	_, err = e.ApplyRelearning(g, stream, public, eid, installation)
	if err != nil {
		refusal := RelearningRefusal{OperationID: g.OperationID, Sequence: g.Sequence, Digest: g.Digest,
			Result: learningoperation.StreamResult{State: "rejected", Reason: "engine_refused", RemainingSeconds: 86400}}
		raw, _ := json.Marshal(refusal)
		if writeErr := WriteOperationFile(data, stream+".json", raw); writeErr != nil {
			return errors.Join(err, writeErr)
		}
	}
	// Rejection is not a license/collector fault. Existing durable checkpoints
	// are authoritative; after permit expiry the parent can report no acceptance.
	e.inboxDigest = sum
	return err
}
