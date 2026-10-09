package windowsevidence

import (
	"bytes"
	"fmt"
	"path/filepath"
	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/windowseventlog"
	"strings"
	"testing"
	"time"
)

func activityFixture(now time.Time) (*Learning, Event) {
	w := &Learning{started: now.Add(-time.Minute), fileContexts: map[string]fileContext{}, networkEngine: &behaviorlearning.Engine{}}
	exec := eligibleWindowsEvent(now.Add(-time.Second))
	exec.Fields["Image"] = exec.Exe
	w.rememberFileExecution(exec, now)
	e := Event{EvidenceID: "connect-1", EventType: "active_connect", WindowsEventID: "3", WindowsRecordID: "11", Provider: exec.Provider, Channel: exec.Channel,
		HostName: exec.HostName, Time: now.Format(time.RFC3339Nano), Exe: exec.Exe, User: exec.Fields["User"], SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: "443", Protocol: "tcp",
		Fields: map[string]string{"ProcessGuid": exec.Fields["ProcessGuid"], "Initiated": "true"}}
	return w, e
}

func TestObservedProcessTamperingDisablesAllMatching(t *testing.T) {
	t.Setenv("SECWEAVER_DEVICE_ID", "test-device")
	t.Setenv("SECWEAVER_ENTERPRISE_ID", "TESTENTERPRISE01")
	dir := t.TempDir()
	var original bytes.Buffer
	w, err := newLearning(&original, LearningOptions{StateDir: filepath.Join(dir, "state"), Output: filepath.Join(dir, "summary.log")}, "", filepath.Join(dir, "exec.log"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	_, err = WriteSource(w, windowseventlog.Event{System: windowseventlog.SystemData{Provider: "Microsoft-Windows-Sysmon", EventID: "25"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	state, err := behaviorlearning.Inspect(filepath.Join(dir, "state"), 64)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != "degraded" || state.Reason != "windows_process_integrity_changed" {
		t.Fatalf("tampered process still eligible: %+v", state)
	}
}

func TestActivityRequiresSameObservedGUIDAndImage(t *testing.T) {
	now := time.Now()
	w, e := activityFixture(now)
	o := w.activityObservation(e, now)
	if !o.Complete || o.Context.Network == nil || o.Context.Network.Port != 443 {
		t.Fatalf("valid activity rejected: %+v", o)
	}
	for name, mutate := range map[string]func(*Event){
		"reused-pid-new-guid": func(e *Event) { e.Fields["ProcessGuid"] = "{bbbb0000-0000-0000-0000-000000000001}" },
		"changed-image":       func(e *Event) { e.Exe = `C:\Program Files\Example\different.exe` },
		"inbound":             func(e *Event) { e.Fields["Initiated"] = "false" },
		"missing-direction":   func(e *Event) { delete(e.Fields, "Initiated") },
		"stale":               func(e *Event) { e.Time = now.Add(-time.Hour).Format(time.RFC3339Nano) },
		"before-exec":         func(e *Event) { e.Time = now.Add(-2 * time.Second).Format(time.RFC3339Nano) },
	} {
		t.Run(name, func(t *testing.T) {
			w, e := activityFixture(now)
			mutate(&e)
			if w.activityObservation(e, now).Complete {
				t.Fatal("unverified activity qualified")
			}
		})
	}
}

func TestNetworkAdapterDoesNotHandleFileEvents(t *testing.T) {
	now := time.Now()
	w, e := activityFixture(now)
	e.EventType, e.WindowsEventID, e.Action, e.Path = "file_op", "11", "create", `C:\ProgramData\Example\worker.log`
	if w.activityObservation(e, now).Complete {
		t.Fatal("file event reached the network activity policy")
	}
}

func TestActivityCacheBoundedAndExpires(t *testing.T) {
	now := time.Now()
	w, _ := activityFixture(now)
	for i := 0; i < 1500; i++ {
		e := eligibleWindowsEvent(now)
		e.Fields["ProcessGuid"] = fmt.Sprintf("{abcd0000-0000-0000-0000-%012x}", i)
		e.Fields["CommandLine"] += strings.Repeat("x", 5000)
		e.Fields["Image"] = e.Exe
		w.rememberFileExecution(e, now)
	}
	if len(w.fileContexts) > 1024 || w.fileContextBytes > activityContextBytes {
		t.Fatal("unbounded process context cache")
	}
	w.pruneContexts(now.Add(61 * time.Minute))
	if len(w.fileContexts) != 0 || w.fileContextBytes != 0 {
		t.Fatal("expired context retained")
	}
}
