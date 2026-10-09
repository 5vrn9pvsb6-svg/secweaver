package behaviorlearning

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fileFixture(t *testing.T, windows bool) *fixture {
	t.Helper()
	return fixtureWithConfig(t, FilePolicy(Config{Enabled: true, StateDir: t.TempDir(), EventTypes: []string{"exec", "file_op"}}, windows))
}

func fileObservation(n int, windows bool) Observation {
	o := simpleObservation(n)
	fields := *o.Context.Exec
	if windows {
		fields.ListenerProcess, fields.PIDName, fields.Exe, fields.CommandLine = "", "powershell.exe", `C:\Windows\powershell.exe`, "powershell -File script.ps1"
	}
	o.Context = Context{File: &FileFields{ExecFields: fields, FilePaths: []string{"/etc/shadow", "/etc"}}}
	o.Raw = json.RawMessage(fmt.Sprintf(`{"event_type":"file_op","action":"action-%d"}`, n))
	return o
}

func feedFile(t *testing.T, f *fixture, start, count int, windows bool) {
	t.Helper()
	for n := start; n < start+count; n++ {
		if err := f.e.Process(fileObservation(n, windows)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFileFiveFieldsImmediateAdmissionAndFreeze(t *testing.T) {
	for _, windows := range []bool{false, true} {
		t.Run(fmt.Sprint(windows), func(t *testing.T) {
			f := fileFixture(t, windows)
			feedFile(t, f, 0, 5, windows)
			if len(f.raw) != 4 || len(f.e.state.Entries) != 1 || !f.e.summaryBase(f.now).FilteringActive {
				t.Fatal("fifth file did not filter during learning")
			}
			changes := []func(*FileFields){
				func(v *FileFields) { v.FilePaths[0] += " " },
				func(v *FileFields) { v.FilePaths[0], v.FilePaths[1] = v.FilePaths[1], v.FilePaths[0] },
				func(v *FileFields) { v.ListenerProcess += "other" },
				func(v *FileFields) { v.PIDName += " " },
				func(v *FileFields) { v.Exe += "X" },
				func(v *FileFields) { v.CommandLine += " " },
				func(v *FileFields) { v.FilePaths = nil },
				func(v *FileFields) { v.CommandLine = "" },
				func(v *FileFields) { v.FilePaths[0] = "\xff" },
			}
			for n, mutate := range changes {
				o := fileObservation(100+n, windows)
				mutate(o.Context.File)
				if err := f.e.Process(o); err != nil {
					t.Fatal(err)
				}
			}
			if len(f.raw) != 4+len(changes) {
				t.Fatal("changed/incomplete file tuple suppressed")
			}
			f.e.freeze(f.now)
			for n := 200; n < 206; n++ {
				o := fileObservation(n, windows)
				o.Context.File.CommandLine = "new after freeze"
				if err := f.e.Process(o); err != nil {
					t.Fatal(err)
				}
			}
			feedFile(t, f, 300, 10, windows)
			if len(f.raw) != 10+len(changes) || len(f.e.state.Entries) != 1 {
				t.Fatal("freeze learned unknown files or stopped exact matches")
			}
			if status := f.e.summaryBase(f.now); status.SourceEventType != "file_op" {
				t.Fatal("file status cannot be distinguished from exec")
			}
		})
	}
}

func TestFileRollingWindowReplayRestartAndFaults(t *testing.T) {
	for _, elapsed := range []time.Duration{time.Hour, time.Hour + time.Nanosecond} {
		t.Run(elapsed.String(), func(t *testing.T) {
			f := fileFixture(t, false)
			feedFile(t, f, 0, 4, false)
			feedFile(t, f, 0, 4, false)
			f.now = f.now.Add(elapsed)
			f.e.Health(true, false)
			feedFile(t, f, 4, 1, false)
			want := 4
			if elapsed > time.Hour {
				want = 5
			}
			if len(f.raw) != want {
				t.Fatalf("originals=%d want=%d", len(f.raw), want)
			}
		})
	}
	t.Run("restart journal checkpoint", func(t *testing.T) {
		f := fileFixture(t, true)
		f.now = time.Now().Add(-time.Minute)
		feedFile(t, f, 0, 5, true)
		if err := f.e.Close(); err != nil {
			t.Fatal(err)
		}
		e, err := New(f.e.cfg, "device-test", f.e.original, f.e.summary)
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		e.Health(true, false)
		if err := e.Process(fileObservation(10, true)); err != nil || len(f.raw) != 4 {
			t.Fatalf("file baseline not restored: %v", err)
		}
		journal, err := os.ReadFile(filepath.Join(e.cfg.StateDir, "admissions.jsonl"))
		if err != nil || len(journal) != 0 {
			t.Fatal("file admissions not compacted after checkpoint")
		}
	})
	for _, reason := range []string{"shadow", "unhealthy", "journal", "summary"} {
		t.Run(reason, func(t *testing.T) {
			f := fileFixture(t, false)
			feedFile(t, f, 0, 4, false)
			switch reason {
			case "shadow":
				f.e.cfg.Shadow = true
			case "unhealthy":
				f.e.Health(false, false)
			case "journal":
				f.e.store.limit = 3
			case "summary":
				feedFile(t, f, 4, 1, false)
				f.failSummary = true
				if err := f.e.Checkpoint(); err == nil {
					t.Fatal("summary failure hidden")
				}
			}
			feedFile(t, f, 5, 1, false)
			if len(f.raw) != 5 {
				t.Fatal("uncertainty suppressed file evidence")
			}
		})
	}
}

func TestFilePolicyScopeDoesNotChangeParentHash(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		enabled bool
	}{
		{`{"enabled":true}`, true},
		{`{"enabled":true,"event_types":["exec"]}`, false},
		{`{"enabled":true,"event_types":["file_op"]}`, true},
		{`{"enabled":false}`, false},
	} {
		cfg, err := DecodeExec([]byte(tc.raw))
		if err != nil {
			t.Fatal(err)
		}
		cfg.StateDir = t.TempDir()
		before := policyHash(cfg)
		file := FilePolicy(cfg, false)
		if file.Enabled != tc.enabled || before != policyHash(cfg) || file.StateDir == cfg.StateDir {
			t.Fatal("file policy changed parent or ignored explicit scope")
		}
		if policyHash(file) == policyHash(FilePolicy(cfg, true)) {
			t.Fatal("Linux and Windows file strategies share an identity")
		}
	}
}

func TestReadSummarySelectsBaselineInSharedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summaries.log")
	var content []byte
	for i, id := range []string{"exec-baseline", "file-baseline"} {
		b, _ := json.Marshal(Summary{Time: time.Now().Add(time.Duration(i) * time.Second), EventType: "behavior_learning_status", BaselineID: id})
		content = append(append(content, b...), '\n')
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	summary, err := ReadBaselineSummary(path, "exec-baseline")
	if err != nil || summary.BaselineID != "exec-baseline" {
		t.Fatal("file summary replaced exec status")
	}
}
