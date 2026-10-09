package behaviorlearning

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Simulate the durable checkpoint/journal interleavings directly against Store.
// Engine restart still degrades an unclean generation; replay must preserve its
// evidence without granting automatic recovery from a source gap.
func TestAdmissionReplayAndCheckpointCompaction(t *testing.T) {
	f := simpleFixture(t)
	feedSimple(t, f, 0, 5)
	stale, err := f.e.store.Load()
	if err != nil || len(stale.Entries) != 0 {
		t.Fatalf("unexpected checkpoint before compaction: %v", err)
	}
	if err := f.e.store.replayAdmissions(stale); err != nil || len(stale.Entries) != 1 {
		t.Fatalf("journal replay lost promotion: %v", err)
	}
	if err := f.e.store.replayAdmissions(stale); err != nil || len(stale.Entries) != 1 {
		t.Fatal("replay was not idempotent")
	}
	if err := f.e.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(f.e.cfg.StateDir, "admissions.jsonl"))
	if err != nil || info.Size() != 0 {
		t.Fatalf("journal not compacted: %v", err)
	}
	state, err := Inspect(f.e.cfg.StateDir, f.e.cfg.StateMB)
	if err != nil || len(state.Entries) != 1 {
		t.Fatal("compaction removed durable entry")
	}
	// A crash before shutdown must not revive active matching on recovery.
	f.e.store.Close()
	f.e.closed = true
	restored, err := New(f.e.cfg, "device-test", f.e.original, f.e.summary)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	restored.Health(true, false)
	if restored.state.Mode != "degraded" || restored.summaryBase(time.Now()).FilteringActive {
		t.Fatal("unclean generation silently resumed suppression")
	}
}

func TestAdmissionJournalTamperAndPartialWriteFailOpen(t *testing.T) {
	for _, body := range [][]byte{[]byte(`{"unfinished"`), []byte("{\"data\":{},\"hmac_sha256\":\"00\"}\n")} {
		f := simpleFixture(t)
		if err := os.WriteFile(filepath.Join(f.e.cfg.StateDir, "admissions.jsonl"), body, 0600); err != nil {
			t.Fatal(err)
		}
		state := f.e.state
		if err := f.e.store.replayAdmissions(&state); err == nil {
			t.Fatal("unverified journal accepted")
		}
	}
}
