package windowsevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/windowseventlog"
)

// A real Sysmon-shaped record supplies execution-time identity, independently
// of the current host OS and any live process still using its numeric PID.
func eligibleWindowsEvent(now time.Time) Event {
	return Event{EvidenceID: "event-1", EventType: "exec", WindowsEventID: "1", WindowsRecordID: "10",
		Provider: "Microsoft-Windows-Sysmon", Channel: "Microsoft-Windows-Sysmon/Operational", HostName: "win-test", Time: now.Format(time.RFC3339Nano),
		Exe: `C:\Program Files\Example\worker.exe`, ParentProcess: `C:\Program Files\Example\service.exe`,
		Fields: map[string]string{"ProcessGuid": "{aaaa0000-0000-0000-0000-000000000001}", "ParentProcessGuid": "{aaaa0000-0000-0000-0000-000000000002}",
			"Hashes": "SHA256=" + strings.Repeat("a", 64), "CommandLine": `"C:\Program Files\Example\worker.exe" --check`,
			"ParentCommandLine": `"C:\Program Files\Example\service.exe"`, "CurrentDirectory": `C:\Program Files\Example\`,
			"User": `NT AUTHORITY\SYSTEM`, "ParentUser": `NT AUTHORITY\SYSTEM`, "TerminalSessionId": "0", "LogonId": "0x3e7", "IntegrityLevel": "System"}}
}

func TestWindowsEligibilityAndBypasses(t *testing.T) {
	now := time.Now()
	if o := learningObservation(eligibleWindowsEvent(now), now.Add(-time.Minute), now); !o.Complete {
		t.Fatalf("eligible record rejected: %+v", o)
	}
	for name, mutate := range map[string]func(*Event){
		"security4688":       func(e *Event) { e.WindowsEventID = "4688"; e.Provider = "Microsoft-Windows-Security-Auditing" },
		"missing-hash":       func(e *Event) { delete(e.Fields, "Hashes") },
		"md5-only":           func(e *Event) { e.Fields["Hashes"] = "MD5=" + strings.Repeat("a", 32) },
		"missing-command":    func(e *Event) { delete(e.Fields, "CommandLine") },
		"bad-guid":           func(e *Event) { e.Fields["ProcessGuid"] = "42" },
		"interactive":        func(e *Event) { e.Fields["TerminalSessionId"] = "1" },
		"changed-user":       func(e *Event) { e.Fields["ParentUser"] = "alice" },
		"domain-token":       func(e *Event) { e.Fields["LogonId"] = "0x1234" },
		"elevation":          func(e *Event) { e.Fields["IntegrityLevel"] = "High" },
		"powershell":         func(e *Event) { e.Exe = `C:\Windows\System32\powershell.exe` },
		"renamed-powershell": func(e *Event) { e.Fields["OriginalFileName"] = "PowerShell.EXE" },
		"shell-parent":       func(e *Event) { e.ParentProcess = `C:\Windows\System32\cmd.exe` },
		"download":           func(e *Event) { e.Fields["CommandLine"] += " https://example.org/a" },
		"temp-image":         func(e *Event) { e.Exe = `C:\Users\Public\worker.exe` },
		"old-record":         func(e *Event) { e.Time = now.Add(-time.Hour).Format(time.RFC3339Nano) },
		"fake-provider":      func(e *Event) { e.Provider = "NotSysmon" },
	} {
		t.Run(name, func(t *testing.T) {
			e := eligibleWindowsEvent(now)
			mutate(&e)
			if o := learningObservation(e, now.Add(-time.Minute), now); o.Complete {
				t.Fatal("unsafe record qualified")
			}
		})
	}
}

func TestWindowsPIDReuseAndExactCommandContext(t *testing.T) {
	now := time.Now()
	e := eligibleWindowsEvent(now)
	a := learningObservation(e, now.Add(-time.Minute), now)
	e.Fields["ProcessGuid"] = "{bbbb0000-0000-0000-0000-000000000001}"
	b := learningObservation(e, now.Add(-time.Minute), now)
	if a.Instance == b.Instance {
		t.Fatal("reused PID merged distinct processes")
	}
	ax, _ := json.Marshal(a.Context)
	bx, _ := json.Marshal(b.Context)
	if !bytes.Equal(ax, bx) {
		t.Fatal("instance IDs leaked into reusable fingerprint")
	}
	e.Fields["CommandLine"] += " --different"
	cx, _ := json.Marshal(learningObservation(e, now.Add(-time.Minute), now).Context)
	if bytes.Equal(ax, cx) {
		t.Fatal("different command matched")
	}
}

type failedSync struct{ bytes.Buffer }

func (*failedSync) Sync() error { return errors.New("sync failed") }

func TestLearningCheckpointFailureAndQueryFault(t *testing.T) {
	t.Setenv("SECWEAVER_DEVICE_ID", "test-device")
	t.Setenv("SECWEAVER_ENTERPRISE_ID", "TESTENTERPRISE01")
	dir := t.TempDir()
	out := &failedSync{}
	w, err := newLearning(out, LearningOptions{StateDir: filepath.Join(dir, "state"), Output: filepath.Join(dir, "summary.log")}, "", filepath.Join(dir, "exec.log"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	SourcePoll(w, false)
	if err := w.Sync(); err == nil {
		t.Fatal("cursor checkpoint ignored failed output sync")
	}
	s, err := behaviorlearning.Inspect(filepath.Join(dir, "state"), 64)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	if !bytes.Contains(b, []byte("windows_source_query_failed")) {
		t.Fatalf("source failure did not persist: %s", b)
	}
}

func TestUnavailableLearningPreservesSource(t *testing.T) {
	t.Setenv("SECWEAVER_DEVICE_ID", "")
	var out bytes.Buffer
	w, closeFn := WrapLearning(&out, LearningOptions{Enabled: true}, filepath.Join(t.TempDir(), "cursor"), filepath.Join(t.TempDir(), "exec.log"), time.Second)
	defer closeFn()
	if w != &out {
		t.Fatal("missing identity must preserve original sink")
	}
	e := windowseventlog.Event{System: windowseventlog.SystemData{EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security"}, EventData: []windowseventlog.DataField{{Name: "NewProcessName", Value: `C:\Windows\System32\cmd.exe`}}}
	if n, err := WriteSource(w, e, false); err != nil || n != 1 || out.Len() == 0 {
		t.Fatalf("original lost: n=%d err=%v", n, err)
	}
}
