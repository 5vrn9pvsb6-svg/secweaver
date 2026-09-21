package windowseventlog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCursorStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cursors", "windows.cursor.json")
	cursors := map[string]uint64{
		"Security":                             42,
		"Microsoft-Windows-Sysmon/Operational": 101,
		"empty":                                0,
	}

	if err := SaveCursorState(path, "test-module", cursors); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCursorState(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded["Security"] != 42 || loaded["Microsoft-Windows-Sysmon/Operational"] != 101 {
		t.Fatalf("loaded cursors = %#v", loaded)
	}
	if _, ok := loaded["empty"]; ok {
		t.Fatalf("zero cursor should not be persisted: %#v", loaded)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestLoadMissingCursorStateReturnsEmpty(t *testing.T) {
	loaded, err := LoadCursorState(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 0 {
		t.Fatalf("loaded = %#v, want empty", loaded)
	}
}

func TestLoadCorruptCursorStateQuarantinesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cursor.json")
	if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCursorState(path)
	if err != nil || len(loaded) != 0 {
		t.Fatalf("loaded=%v err=%v", loaded, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("corrupt cursor should be moved, stat err=%v", err)
	}
	matches, err := filepath.Glob(path + ".corrupt-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("quarantined cursors=%v err=%v", matches, err)
	}
}
