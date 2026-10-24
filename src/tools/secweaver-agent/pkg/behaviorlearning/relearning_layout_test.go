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

// relearningLayoutGrant signs one operation for real, independently locked
// stores. Only the healthy clock is accelerated; no backup/budget I/O is mocked.
func relearningLayoutGrant(t *testing.T, streams map[string]*fixture) (learningoperation.Grant, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var targets []learningoperation.Target
	var now time.Time
	for _, stream := range []string{"exec", "file", "network", "risk"} {
		f := streams[stream]
		if f == nil {
			continue
		}
		f.e.state.HealthySeconds = 86400
		f.e.freeze(f.now)
		token, reason := f.e.RelearningEligibility()
		if reason != "" {
			t.Fatalf("%s eligibility: %s", stream, reason)
		}
		targets = append(targets, learningoperation.Target{Stream: stream, BaselineToken: token})
		if now.IsZero() || f.now.Before(now) {
			now = f.now
		}
	}
	g, err := learningoperation.Sign(learningoperation.Grant{OperationID: "layout-op", Sequence: "1", EnterpriseID: "enterprise", DeviceID: "device-test", InstallationID: "install",
		IssuedAt: now, StartBefore: now.Add(30 * time.Second), RunNotAfter: now.Add(8 * 24 * time.Hour), DurationSeconds: 86400, Targets: targets}, key)
	if err != nil {
		t.Fatal(err)
	}
	return g, base64.StdEncoding.EncodeToString(pub)
}

func TestRelearningExecWithIndependentChildStores(t *testing.T) {
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			windows := platform == "windows"
			cfg := Config{Enabled: true, simpleExec: true, StateDir: t.TempDir(), EventTypes: []string{"exec", "file_op", "active_connect"}}
			if windows {
				cfg = WindowsExecPolicy(cfg)
			}
			exec := fixtureWithConfig(t, cfg)
			for n := 0; n < 5; n++ {
				o := simpleObservation(n)
				if windows {
					o.Context.Exec.ListenerProcess = ""
				}
				if err := exec.e.Process(o); err != nil {
					t.Fatal(err)
				}
			}
			file := fixtureWithConfig(t, FilePolicy(exec.e.cfg, windows))
			feedFile(t, file, 0, 5, windows)
			if windows {
				// Windows also nests a separately owned connection baseline here.
				fixtureWithConfig(t, NetworkPolicy(exec.e.cfg))
			}
			g, pub := relearningLayoutGrant(t, map[string]*fixture{"exec": exec, "file": file})
			if result, err := file.e.ApplyRelearning(g, "file", pub, "enterprise", "install"); err != nil || result.RetainedEntries != 1 {
				t.Fatalf("file start: %+v %v", result, err)
			}
			childFiles := map[string][]byte{}
			for _, name := range []string{"key", "state.json", "admissions.jsonl", "relearning-backup.json"} {
				raw, err := os.ReadFile(filepath.Join(file.e.cfg.StateDir, name))
				if err != nil {
					t.Fatal(err)
				}
				childFiles[name] = raw
			}
			before, key := exec.e.state, append([]byte(nil), exec.e.store.Key...)
			if result, err := exec.e.ApplyRelearning(g, "exec", pub, "enterprise", "install"); err != nil || result.State != "learning" || result.RetainedEntries != 1 {
				t.Fatalf("exec start with live child stores: %+v %v", result, err)
			}
			if exec.e.state.BaselineID != before.BaselineID || exec.e.state.Policy != before.Policy || exec.e.state.Generation != before.Generation ||
				!bytes.Equal(key, exec.e.store.Key) || len(exec.e.state.Seen) != len(before.Seen) {
				t.Fatal("exec identity or source dedup changed")
			}
			for name, want := range childFiles {
				got, err := os.ReadFile(filepath.Join(file.e.cfg.StateDir, name))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("exec rewrote file store %s: %v", name, err)
				}
			}
			for n := 100; n < 105; n++ {
				o := simpleObservation(n)
				o.Context.Exec.CommandLine = "new exec tuple"
				if windows {
					o.Context.Exec.ListenerProcess = ""
				}
				if err := exec.e.Process(o); err != nil {
					t.Fatal(err)
				}
			}
			if len(exec.raw) != 8 || len(exec.e.state.Entries) != 2 {
				t.Fatal("new tuple did not learn and filter during the additional window")
			}
			if err := file.e.store.Commit(file.e.state); err != nil {
				t.Fatalf("child checkpoint after parent start: %v", err)
			}
			if err := exec.e.Close(); err != nil {
				t.Fatalf("parent checkpoint with live child: %v", err)
			}
			restarted := fixtureWithConfig(t, exec.e.cfg)
			if restarted.e.state.Mode != "learning" || restarted.e.state.Relearning.OperationID != g.OperationID || len(restarted.e.state.Entries) != 2 ||
				!bytes.Equal(key, restarted.e.store.Key) || file.e.state.Relearning.State != "learning" {
				t.Fatal("clean restart lost parent or child learning state")
			}
		})
	}
}

func TestRelearningBudgetSeparatesChildStorage(t *testing.T) {
	f, g, pub := relearningFixture(t)
	child := fixtureWithConfig(t, FilePolicy(f.e.cfg, false))
	path := filepath.Join(child.e.cfg.StateDir, "prior-backup")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	// A sparse file exercises accounting without allocating the parent's budget
	// in RAM. The parent must not charge or clean another stream's files.
	if err = file.Truncate(f.e.store.limit); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = f.e.ApplyRelearning(g, "exec", pub, "enterprise", "install"); err != nil {
		t.Fatalf("child bytes consumed parent budget: %v", err)
	}
	if err = child.e.store.relearningBudget(1); err == nil {
		t.Fatal("child storage escaped its own budget")
	}
	if err = os.Rename(path, filepath.Join(f.e.cfg.StateDir, "prior-backup")); err != nil {
		t.Fatal(err)
	}
	if err = f.e.store.Commit(f.e.state); err == nil {
		t.Fatal("parent-owned backup escaped the parent budget")
	}
}

func TestRelearningParentAndChildCheckpointConcurrently(t *testing.T) {
	f, g, pub := relearningFixture(t)
	child := fixtureWithConfig(t, FilePolicy(f.e.cfg, false))
	if _, err := f.e.ApplyRelearning(g, "exec", pub, "enterprise", "install"); err != nil {
		t.Fatal(err)
	}
	// Each stream has exactly one writer, as in production. Parent budgeting
	// must neither take the child's lock nor inspect its transient write files.
	results := make(chan error, 2)
	for _, engine := range []*Engine{f.e, child.e} {
		go func(e *Engine) {
			for n := 0; n < 10; n++ {
				if err := e.store.Commit(e.state); err != nil {
					results <- err
					return
				}
			}
			results <- nil
		}(engine)
	}
	for n := 0; n < 2; n++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
}

func TestRelearningRejectsUnownedOrLinkedDirectories(t *testing.T) {
	for _, kind := range []string{"unknown-directory", "linux-network-directory", "linked-file-directory", "file-store-child", "coordination-child"} {
		t.Run(kind, func(t *testing.T) {
			f, g, pub := relearningFixture(t)
			root, name := f.e.cfg.StateDir, "unknown"
			switch kind {
			case "linux-network-directory":
				name = "network-operations"
			case "linked-file-directory":
				name = "file-operations"
			case "file-store-child":
				child := fixtureWithConfig(t, FilePolicy(f.e.cfg, false))
				g, pub = relearningLayoutGrant(t, map[string]*fixture{"file": child})
				f, root, name = child, child.e.cfg.StateDir, "file-operations"
			case "coordination-child":
				root, name = t.TempDir(), "file-operations"
				if err := WriteOperationFile(root, "current.json", []byte("{}")); err != nil {
					t.Fatal(err)
				}
				root = filepath.Join(root, "learning-operations")
			}
			path := filepath.Join(root, name)
			if kind == "linked-file-directory" {
				if err := os.Symlink(t.TempDir(), path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			} else if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "coordination-child" {
				if err := WriteOperationFile(filepath.Dir(root), "exec.json", []byte("{}")); err == nil {
					t.Fatal("coordination store accepted a child directory")
				}
				return
			}
			before, err := os.ReadFile(filepath.Join(root, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			stream := relearningStream(f.e.state.Strategy)
			if _, err = f.e.ApplyRelearning(g, stream, pub, "enterprise", "install"); err == nil {
				t.Fatal("unsafe layout accepted")
			}
			after, err := os.ReadFile(filepath.Join(root, "state.json"))
			if err != nil || !bytes.Equal(before, after) || f.e.state.Relearning != nil {
				t.Fatal("failed layout check changed trusted state")
			}
			if _, err = os.Lstat(filepath.Join(root, "relearning-backup.json")); !os.IsNotExist(err) {
				t.Fatalf("failed layout check wrote a backup: %v", err)
			}
		})
	}
}

func TestRelearningInboxReportsStorageFailure(t *testing.T) {
	for _, kind := range []string{"layout", "budget"} {
		t.Run(kind, func(t *testing.T) {
			f, g, pub := relearningFixture(t)
			data := t.TempDir()
			t.Setenv(RelearningDataEnv, data)
			t.Setenv(RelearningInstallationEnv, "install")
			t.Setenv("SECWEAVER_ENTERPRISE_ID", "enterprise")
			t.Setenv("SECWEAVER_COLLECTION_PUBLIC_KEY", pub)
			body, _ := json.Marshal(g)
			if err := WriteOperationFile(data, "current.json", body); err != nil {
				t.Fatal(err)
			}
			want := "state_budget_exceeded"
			if kind == "layout" {
				want = "state_layout_invalid"
				if err := os.Mkdir(filepath.Join(f.e.cfg.StateDir, "unknown"), 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				f.e.store.limit = 1
			}
			if err := f.e.PollRelearningInbox(); err == nil {
				t.Fatal("invalid storage accepted")
			}
			body, err := ReadOperationFile(data, "exec.json")
			if err != nil {
				t.Fatal(err)
			}
			var refusal RelearningRefusal
			if err = json.Unmarshal(body, &refusal); err != nil || refusal.Result.State != "rejected" || refusal.Result.Reason != want {
				t.Fatalf("storage refusal: %+v %v", refusal.Result, err)
			}
			if bytes.Contains(body, []byte(f.e.cfg.StateDir)) || bytes.Contains(body, f.e.store.Key) {
				t.Fatal("local path or key leaked into the receipt")
			}
		})
	}
}
