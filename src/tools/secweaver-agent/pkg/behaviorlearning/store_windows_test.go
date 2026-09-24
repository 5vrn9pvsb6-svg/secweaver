//go:build windows

package behaviorlearning

import (
	"path/filepath"
	"testing"
	"time"
)

// Run elevated on native Windows: verifies replacement and lock release rather
// than assuming cross-compilation proves Windows file-system semantics.
func TestWindowsStateLockReplacementAndReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStore(dir, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	state := State{Version: 1, Device: "windows-test", Entries: map[string]*Entry{}, Candidates: map[string]*Entry{}, LastSeen: map[string]time.Time{}}
	if err := s.Commit(state); err != nil {
		t.Fatal(err)
	}
	other, err := OpenStore(dir, 64)
	if err == nil {
		other.Close()
		t.Fatal("second state owner acquired exclusive handle")
	}
	state.Generation = 7
	if err := s.Commit(state); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = OpenStore(dir, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	loaded, err := s.Load()
	if err != nil || loaded.Generation != 7 {
		t.Fatalf("replacement/reopen: %+v %v", loaded, err)
	}
}
