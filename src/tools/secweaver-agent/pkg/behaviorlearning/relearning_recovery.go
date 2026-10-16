package behaviorlearning

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RestoreRelearningBackup stages a verified pre-window store in a NEW directory.
// It never replaces live state, clears an operation, or swaps installation
// identity. The source lifetime lock requires its collector to be stopped.
// Operators retain the source and explicitly switch directories only after
// disabling rollout and letting outstanding 30-second permissions expire.
// A failed staging directory is deliberately retained for offline inspection;
// its partial initialization cannot silently initialize a fresh baseline.
func RestoreRelearningBackup(source, destination string, budgetMB int) error {
	if budgetMB < 8 || budgetMB > 256 || !filepath.IsAbs(source) || !filepath.IsAbs(destination) {
		return fmt.Errorf("absolute paths and an 8..256 MiB budget required")
	}
	source, destination = filepath.Clean(source), filepath.Clean(destination)
	if source == destination || strings.HasPrefix(destination, source+string(filepath.Separator)) || strings.HasPrefix(source, destination+string(filepath.Separator)) {
		return fmt.Errorf("recovery directories must be disjoint")
	}
	// Do not let OpenStore initialize a nonexistent source during maintenance.
	if st, err := os.Lstat(filepath.Join(source, "initialized")); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("initialized recovery source required")
	}
	s, err := OpenStore(source, budgetMB)
	if err != nil {
		return err
	}
	defer s.Close()
	body, err := s.read("relearning-backup.json", s.limit)
	if err != nil {
		return err
	}
	var envelope struct {
		Payload json.RawMessage `json:"payload"`
		MAC     string          `json:"hmac_sha256"`
	}
	if err = json.Unmarshal(body, &envelope); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, s.Key)
	mac.Write(envelope.Payload)
	provided, err := hex.DecodeString(envelope.MAC)
	if err != nil || !hmac.Equal(provided, mac.Sum(nil)) {
		return fmt.Errorf("relearning backup integrity failure")
	}
	var backup struct {
		Version int    `json:"backup_version"`
		State   State  `json:"state"`
		Key     []byte `json:"key"`
		Journal []byte `json:"journal"`
	}
	if err = json.Unmarshal(envelope.Payload, &backup); err != nil {
		return err
	}
	if backup.Version != 1 || !bytes.Equal(backup.Key, s.Key) || backup.State.Entries == nil || backup.State.Candidates == nil || backup.State.LastSeen == nil || !backup.State.CleanShutdown {
		return fmt.Errorf("incompatible relearning backup")
	}
	if err = validateRelearningState(backup.State); err != nil {
		return err
	}
	if int64(len(backup.Journal)) > s.limit/3 {
		return fmt.Errorf("backup journal budget exceeded")
	}
	// Exclusive creation forbids overwriting any existing recovery or live path.
	if err = os.Mkdir(destination, 0700); err != nil {
		return err
	}
	out, err := OpenStore(destination, budgetMB)
	if err != nil {
		return err
	}
	defer out.Close()
	out.Key = backup.Key
	if err = out.atomic("key", backup.Key); err != nil {
		return err
	}
	if err = out.commitFile("state.json", backup.State); err != nil {
		return err
	}
	if err = out.atomic("admissions.jsonl", backup.Journal); err != nil {
		return err
	}
	verified, err := out.Load()
	if err != nil {
		return err
	}
	if simpleStrategyKnown(verified.Strategy) {
		if err = out.replayAdmissions(verified); err != nil {
			return err
		}
	}
	// Compact the authenticated journal only after the encompassing checkpoint
	// is durably staged, matching normal crash-safe Store.Commit ordering.
	return out.Commit(*verified)
}
