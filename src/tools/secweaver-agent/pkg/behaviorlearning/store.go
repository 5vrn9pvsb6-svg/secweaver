package behaviorlearning

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Store holds an exclusive OS lock for its lifetime. The existence marker makes
// partial initialization distinguishable from a never-started installation.
type Store struct {
	dir   string
	limit int64
	lock  *os.File
	Key   []byte
	fresh bool // Only this lock holder's first initialization may lack a checkpoint.
}

// OpenStore refuses symlinked state roots and partial/corrupt initialization.
// Administrators must explicitly recover such state, never silently relearn it.
func OpenStore(dir string, budgetMB int) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("state directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("invalid learning directory")
	}
	if err = protectStateDirectory(dir); err != nil {
		return nil, err
	}
	lock, err := lockState(filepath.Join(dir, "lock"))
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, limit: int64(budgetMB) << 20, lock: lock}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	marker := filepath.Join(dir, "initialized")
	_, err = os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		// Fail closed on leftover files from partial setup before creating a key.
		entries, e := os.ReadDir(dir)
		if e != nil {
			return nil, e
		}
		for _, entry := range entries {
			if entry.Name() != "lock" {
				return nil, fmt.Errorf("unmarked learning state")
			}
		}
		f, e := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		if e = f.Sync(); e != nil {
			f.Close()
			return nil, e
		}
		f.Close()
		s.Key = make([]byte, 32)
		if _, e = rand.Read(s.Key); e != nil {
			return nil, e
		}
		if e = s.atomic("key", s.Key); e != nil {
			return nil, e
		}
		s.fresh = true
	} else if err != nil {
		return nil, err
	} else {
		s.Key, err = s.read("key", 32)
		if err != nil || len(s.Key) != 32 {
			return nil, fmt.Errorf("invalid learning HMAC key")
		}
		if _, err = os.Lstat(filepath.Join(dir, "state.json")); err != nil {
			return nil, fmt.Errorf("initialized learning state missing: %w", err)
		}
	}
	ok = true
	return s, nil
}

// Load returns nil only for the first initialization within this locked session.
func (s *Store) Load() (*State, error) {
	body, err := s.read("state.json", s.limit/3)
	if errors.Is(err, os.ErrNotExist) && s.fresh {
		s.fresh = false
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var envelope struct {
		State json.RawMessage `json:"state"`
		MAC   string          `json:"hmac_sha256"`
	}
	if err = json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.Key)
	mac.Write(envelope.State)
	provided, err := hex.DecodeString(envelope.MAC)
	if err != nil || !hmac.Equal(provided, mac.Sum(nil)) {
		return nil, fmt.Errorf("learning checkpoint integrity failure")
	}
	var state State
	if err = json.Unmarshal(envelope.State, &state); err != nil {
		return nil, err
	}
	if state.Version != 1 || state.Entries == nil || state.Candidates == nil || state.LastSeen == nil {
		return nil, fmt.Errorf("incompatible learning checkpoint")
	}
	return &state, nil
}

// Commit reserves room for both old and replacement checkpoints. A state is
// enforceable only after this durable write succeeds.
func (s *Store) Commit(state State) error {
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if int64(len(body)) > s.limit/3 {
		return fmt.Errorf("learning state budget exceeded")
	}
	mac := hmac.New(sha256.New, s.Key)
	mac.Write(body)
	envelope, err := json.Marshal(struct {
		State json.RawMessage `json:"state"`
		MAC   string          `json:"hmac_sha256"`
	}{body, hex.EncodeToString(mac.Sum(nil))})
	if err != nil {
		return err
	}
	if int64(len(envelope)) > s.limit/3 {
		return fmt.Errorf("learning state budget exceeded")
	}
	if err = s.atomic("state.json", envelope); err != nil {
		return err
	}
	s.fresh = false
	return nil
}

// read bounds deserialization and rejects symlinks/nonregular files.
func (s *Store) read(name string, max int64) ([]byte, error) {
	path := filepath.Join(s.dir, name)
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, fmt.Errorf("invalid state file %s", name)
	}
	if !stateFilePermissionsOK(st) {
		return nil, fmt.Errorf("insecure learning state permissions: %s", name)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max+1))
}

// atomic retains the previous valid checkpoint until rename, and fsyncs its
// parent before reporting success. Temporary files are removed on all failures.
func (s *Store) atomic(name string, body []byte) error {
	f, err := os.CreateTemp(s.dir, ".checkpoint-")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return replaceStateFile(temp, filepath.Join(s.dir, name))
}

// Close releases the lock without deleting its inode, avoiding split ownership.
func (s *Store) Close() {
	if s != nil && s.lock != nil {
		_ = s.lock.Close()
		s.lock = nil
	}
}

// randomID propagates entropy failure so feature initialization can fall back
// to full output instead of crashing the collector.
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
