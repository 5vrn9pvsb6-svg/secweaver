package behaviorlearning

import (
	"os"
	"path/filepath"
	"testing"
)

// A checkpoint disappearing after lock acquisition is corruption, not another
// installation. Only the first read by a fresh store may return an empty state.
func TestMissingCheckpointDoesNotRestartLearning(t *testing.T) {
	s, err := OpenStore(t.TempDir(), 64)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if state, err := s.Load(); err != nil || state != nil {
		t.Fatalf("initial load: %v %v", state, err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("second missing checkpoint accepted as initialization")
	}
	if err := s.Commit(State{Version: 1}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("deleted checkpoint accepted as initialization")
	}
}
