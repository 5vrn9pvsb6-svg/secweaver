package behaviorlearning

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"secweaver-agent/pkg/learningoperation"
)

// A real authenticated store/engine is used; only the clock is accelerated.
func relearningFixture(t *testing.T) (*fixture, learningoperation.Grant, string) {
	t.Helper()
	f := simpleFixture(t)
	feedSimple(t, f, 0, 5)
	f.e.state.HealthySeconds = 86400
	f.e.state.OnlineSeconds = 1000000
	f.e.freeze(f.now)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, reason := f.e.RelearningEligibility()
	if reason != "" {
		t.Fatal(reason)
	}
	g, err := learningoperation.Sign(learningoperation.Grant{OperationID: "op-1", Sequence: "1", EnterpriseID: "enterprise", DeviceID: "device-test", InstallationID: "install",
		IssuedAt: f.now, StartBefore: f.now.Add(30 * time.Second), RunNotAfter: f.now.Add(8 * 24 * time.Hour), DurationSeconds: 86400,
		Targets: []learningoperation.Target{{Stream: "exec", BaselineToken: token}}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return f, g, base64.StdEncoding.EncodeToString(pub)
}

func TestRelearningOfflineRecoveryNeverOverwritesSource(t *testing.T) {
	f, g, pub := relearningFixture(t)
	if _, err := f.e.ApplyRelearning(g, "exec", pub, "enterprise", "install"); err != nil {
		t.Fatal(err)
	}
	source := f.e.cfg.StateDir
	destination := filepath.Join(t.TempDir(), "restored")
	if err := RestoreRelearningBackup(source, destination, 64); err == nil {
		t.Fatal("live writer lock bypassed")
	}
	if err := f.e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RestoreRelearningBackup(source, destination, 64); err != nil {
		t.Fatal(err)
	}
	s, err := Inspect(destination, 64)
	if err != nil || s.Version != 1 || s.Relearning != nil || s.Mode != "enforcing" || len(s.Entries) != 1 {
		t.Fatal("invalid recovery", s, err)
	}
	if err = RestoreRelearningBackup(source, destination, 64); err == nil {
		t.Fatal("existing destination overwritten")
	}
	original, err := Inspect(source, 64)
	if err != nil || original.Version != 2 || original.Relearning.OperationID != g.OperationID {
		t.Fatal("source changed", err)
	}
	path := filepath.Join(source, "relearning-backup.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]json.RawMessage
	if err = json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle["hmac_sha256"] = json.RawMessage(`"00"`)
	raw, _ = json.Marshal(bundle)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = RestoreRelearningBackup(source, filepath.Join(t.TempDir(), "tampered"), 64); err == nil {
		t.Fatal("tampered backup accepted")
	}
}

func TestRelearningInboxRefusalIsTerminalAcrossRestart(t *testing.T) {
	f, g, pub := relearningFixture(t)
	data := t.TempDir()
	t.Setenv(RelearningDataEnv, data)
	t.Setenv(RelearningInstallationEnv, "install")
	t.Setenv("SECWEAVER_ENTERPRISE_ID", "enterprise")
	t.Setenv("SECWEAVER_COLLECTION_PUBLIC_KEY", pub)
	raw, _ := json.Marshal(g)
	if err := WriteOperationFile(data, "current.json", raw); err != nil {
		t.Fatal(err)
	}
	f.e.cfg.Shadow = true
	if err := f.e.PollRelearningInbox(); err == nil {
		t.Fatal("shadow start accepted")
	}
	f.e.cfg.Shadow = false
	f.e.inboxDigest = [32]byte{}
	f.e.inboxPollAfter = time.Time{}
	if err := f.e.PollRelearningInbox(); err != nil {
		t.Fatal(err)
	}
	if f.e.state.Relearning != nil {
		t.Fatal("durable refusal silently restarted")
	}
	if err := WriteOperationFile(data, "../state.json", nil); err == nil {
		t.Fatal("wire-selected path accepted")
	}
}

func TestRelearningRetainsIdentityEntriesKeyDedupAndReplays(t *testing.T) {
	f, g, pub := relearningFixture(t)
	before := f.e.state
	key := append([]byte(nil), f.e.store.Key...)
	f.e.state.Candidates["unqualified"] = &Entry{Count: 4}
	result, err := f.e.ApplyRelearning(g, "exec", pub, "enterprise", "install")
	if err != nil || result.State != "learning" || result.RetainedEntries != 1 {
		t.Fatalf("start: %+v %v", result, err)
	}
	if f.e.state.BaselineID != before.BaselineID || f.e.state.Policy != before.Policy || f.e.state.Generation != before.Generation ||
		!bytes.Equal(key, f.e.store.Key) || len(f.e.state.Candidates) != 0 || len(f.e.state.Entries) != 1 || len(f.e.state.Seen) == 0 {
		t.Fatal("trusted identity or dedup reset")
	}
	w := *f.e.state.Relearning
	f.now = f.now.Add(time.Minute)
	if _, err := f.e.ApplyRelearning(g, "exec", pub, "enterprise", "install"); err != nil {
		t.Fatal(err)
	}
	if *f.e.state.Relearning != w {
		t.Fatal("replay restarted learning")
	}
	state, err := Inspect(f.e.cfg.StateDir, f.e.cfg.StateMB)
	if err != nil || state.Version != 2 || state.Relearning.OperationID != g.OperationID {
		t.Fatalf("missing durable start: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.e.cfg.StateDir, "relearning-backup.json")); err != nil {
		t.Fatal(err)
	}
}

func TestRelearningAdditionalHealthyTimeAndCleanRestart(t *testing.T) {
	f, g, pub := relearningFixture(t)
	if _, err := f.e.ApplyRelearning(g, "exec", pub, "enterprise", "install"); err != nil {
		t.Fatal(err)
	}
	f.e.state.HealthySeconds += 86398
	f.now = f.now.Add(time.Second)
	f.e.Health(true, false)
	if err := f.e.Tick(); err != nil {
		t.Fatal(err)
	}
	if f.e.state.Mode != "learning" {
		t.Fatal("lifetime counter ended additional window")
	}
	cfg := f.e.cfg
	if err := f.e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err := New(cfg, "device-test", f.e.original, f.e.summary)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.now = func() time.Time { return f.now }
	e.lastTick = f.now
	f.now = f.now.Add(time.Second)
	e.Health(true, false)
	if err := e.Tick(); err != nil {
		t.Fatal(err)
	}
	w, result, err := ReadRelearningResult(cfg)
	if err != nil || w.State != "completed" || result.HealthySeconds != 86400 || e.state.Mode != "enforcing" {
		t.Fatalf("completion: %+v %v", result, err)
	}
}

func TestRelearningRejectsExpiredMismatchedUnsafeAndWriteFailure(t *testing.T) {
	for _, kind := range []string{"expired", "stream", "shadow", "degraded", "budget", "baseline"} {
		t.Run(kind, func(t *testing.T) {
			f, g, pub := relearningFixture(t)
			stream := "exec"
			switch kind {
			case "expired":
				f.now = g.StartBefore
			case "stream":
				stream = "file"
			case "shadow":
				f.e.cfg.Shadow = true
			case "degraded":
				f.e.Fault("source_event_loss")
			case "budget":
				f.e.store.limit = 1
			case "baseline":
				f.e.state.BaselineID = "different"
			}
			if _, err := f.e.ApplyRelearning(g, stream, pub, "enterprise", "install"); err == nil {
				t.Fatal("unsafe start accepted")
			}
			if f.e.state.Relearning != nil {
				t.Fatal("failed start published in memory")
			}
		})
	}
}

func TestRelearningHardDeadlineBlocksEventBeforeNextTick(t *testing.T) {
	f, g, pub := relearningFixture(t)
	if _, err := f.e.ApplyRelearning(g, "exec", pub, "enterprise", "install"); err != nil {
		t.Fatal(err)
	}
	f.now = f.e.state.Relearning.Deadline
	f.e.Health(true, false)
	for i := 0; i < 6; i++ {
		o := simpleObservation(100 + i)
		o.Context.Exec.CommandLine = "new tuple"
		if err := f.e.Process(o); err != nil {
			t.Fatal(err)
		}
	}
	if f.e.state.Relearning.State != "expired" || len(f.e.state.Entries) != 1 || f.e.state.Mode != "enforcing" {
		t.Fatal("admission continued after hard deadline")
	}
}
