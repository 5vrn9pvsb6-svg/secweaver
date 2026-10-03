package auditportexecmon

import (
	"os"
	"path/filepath"
	"testing"
)

// Diagnostic reads must not create a baseline or acquire audit rule ownership.
func TestReadLearningStatusIsReadOnlyAndFailOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.json")
	if err := os.WriteFile(path, []byte(`{"behavior_learning":{"enabled":false}}`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := ReadLearningStatus(path, "")
	if err != nil || s.Enabled || s.Mode != "disabled" {
		t.Fatalf("disabled=%+v err=%v", s, err)
	}
	if err := os.WriteFile(path, []byte(`{"behavior_learning":{"enabled":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err = ReadLearningStatus(path, filepath.Join(dir, "logs", "exec.log"))
	if err == nil || !s.Enabled || s.Mode != "unknown" || s.FilteringActive {
		t.Fatalf("missing state=%+v err=%v", s, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "data")); !os.IsNotExist(err) {
		t.Fatalf("diagnostic created data dir: %v", err)
	}
}
