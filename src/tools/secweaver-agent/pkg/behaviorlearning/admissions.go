package behaviorlearning

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type admission struct {
	Baseline string    `json:"baseline_id"`
	Entry    *Entry    `json:"entry"`
	At       time.Time `json:"at"`
}

// appendAdmission runs under the Engine lock and Store's lifetime file lock.
// One small fsynced record replaces a full checkpoint rewrite per promotion.
// The fixed journal is compacted only after the encompassing state is durable.
func (s *Store) appendAdmission(baseline string, entry *Entry, at time.Time) error {
	body, err := json.Marshal(admission{Baseline: baseline, Entry: entry, At: at})
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, s.Key)
	mac.Write(body)
	line, err := json.Marshal(struct {
		Data json.RawMessage `json:"data"`
		MAC  string          `json:"hmac_sha256"`
	}{body, hex.EncodeToString(mac.Sum(nil))})
	if err != nil {
		return err
	}
	line = append(line, '\n')
	path := filepath.Join(s.dir, "admissions.jsonl")
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !stateFilePermissionsOK(info) || info.Size()+int64(len(line)) > s.limit/3 {
		return fmt.Errorf("invalid or full admission journal")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(line); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// replayAdmissions tolerates a checkpoint committed before journal compaction,
// but not truncated/unverifiable records. Other baseline IDs are stale after a
// generation change and never grant matching to the new baseline.
func (s *Store) replayAdmissions(state *State) error {
	body, err := s.read("admissions.jsonl", s.limit/3)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("exact learning admission journal missing")
	}
	if err != nil {
		return err
	}
	if len(body) > 0 && body[len(body)-1] != '\n' {
		return fmt.Errorf("incomplete admission journal")
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		var envelope struct {
			Data json.RawMessage `json:"data"`
			MAC  string          `json:"hmac_sha256"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &envelope); err != nil {
			return err
		}
		mac := hmac.New(sha256.New, s.Key)
		mac.Write(envelope.Data)
		provided, err := hex.DecodeString(envelope.MAC)
		if err != nil || !hmac.Equal(provided, mac.Sum(nil)) {
			return fmt.Errorf("admission journal integrity failure")
		}
		var record admission
		if err := json.Unmarshal(envelope.Data, &record); err != nil {
			return err
		}
		if record.Baseline != state.BaselineID {
			continue
		}
		if record.Entry == nil || len(record.Entry.Fingerprint) != 64 || record.Entry.Count != simpleExecOccurrences {
			return fmt.Errorf("invalid admission journal entry")
		}
		key := record.Entry.Fingerprint
		state.Entries[key] = record.Entry
		if record.At.After(state.LastSeen[key]) {
			state.LastSeen[key] = record.At
		}
		delete(state.Candidates, key)
	}
	return scanner.Err()
}
