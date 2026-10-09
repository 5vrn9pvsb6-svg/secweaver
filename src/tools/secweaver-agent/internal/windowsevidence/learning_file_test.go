package windowsevidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/windowseventlog"
)

// Real Classify/WriteSource and the durable engine run on every CI platform;
// only the native Event Log transport is replaced by complete Sysmon records.
func fileLearningFixture(t *testing.T, out io.Writer) (*Learning, string) {
	t.Helper()
	t.Setenv("SECWEAVER_DEVICE_ID", "test-device")
	t.Setenv("SECWEAVER_ENTERPRISE_ID", "TESTENTERPRISE01")
	dir := t.TempDir()
	w, err := newLearning(out, LearningOptions{Enabled: true, EventTypes: "exec,active_connect,file_op", StateDir: filepath.Join(dir, "state"), Output: filepath.Join(dir, "summary.log")}, "", filepath.Join(dir, "exec.log"), time.Second)
	if err != nil || w == nil || w.fileEngine == nil {
		t.Fatalf("create file adapter: %v", err)
	}
	t.Cleanup(func() { w.Close() })
	w.fileEngine.Health(true, false)
	SourcePoll(w, true)
	return w, dir
}

func fileSysmonEvent(id, record int, guid, command string) windowseventlog.Event {
	e := windowseventlog.Event{System: windowseventlog.SystemData{
		EventID: fmt.Sprint(id), EventRecordID: fmt.Sprint(record), Computer: "win-test",
		Provider: "Microsoft-Windows-Sysmon", Channel: "Microsoft-Windows-Sysmon/Operational", TimeCreated: time.Now().Format(time.RFC3339Nano),
	}}
	for key, value := range map[string]string{
		"ProcessGuid": guid, "ProcessId": "42", "Image": `C:\Users\Alice\powershell.exe`,
		"CommandLine": command, "TargetFilename": `C:\Windows\System32\tasks\job.xml`, "User": "Alice",
	} {
		e.EventData = append(e.EventData, windowseventlog.DataField{Name: key, Value: value})
	}
	return e
}

const fileTestGUID = "{aaaa0000-0000-0000-0000-000000000001}"

func TestWindowsFileLearningUsesFiveExactFieldsAndBothActions(t *testing.T) {
	var out bytes.Buffer
	w, dir := fileLearningFixture(t, &out)
	command := "  powershell -File task.ps1  "
	if n, err := WriteSource(w, fileSysmonEvent(1, 1, fileTestGUID, command), false); err != nil || n != 1 {
		t.Fatalf("exec original: %d %v", n, err)
	}
	// The source intentionally lacks SHA256/service identity and writes a
	// sensitive non-log path. None of those are gates in the new file policy.
	for i := 0; i < 6; i++ {
		id := 11
		if i%2 == 1 {
			id = 23
		}
		n, err := WriteSource(w, fileSysmonEvent(id, i+2, fileTestGUID, ""), false)
		want := 1
		if i >= 4 {
			want = 0
		}
		if err != nil || n != want {
			t.Fatalf("file %d emitted=%d want=%d err=%v", i, n, want, err)
		}
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	state, err := behaviorlearning.Inspect(filepath.Join(dir, "state", "file-operations"), 64)
	if err != nil || len(state.Entries) != 1 {
		t.Fatalf("file state not committed before cursor: %v", err)
	}
	var file map[string]any
	line := bytes.Split(bytes.TrimSpace(out.Bytes()), []byte{'\n'})[1]
	if err := json.Unmarshal(line, &file); err != nil {
		t.Fatal(err)
	}
	if file["listener_process"] != "" || file["pid_name"] != "powershell.exe" || file["command_line"] != command || file["path"] == nil || file["file_paths"] == nil {
		t.Fatalf("file contract lost exact fields: %s", line)
	}
	if _, err := WriteSource(w, fileSysmonEvent(5, 99, fileTestGUID, ""), false); err != nil {
		t.Fatal(err)
	}
	if n, err := WriteSource(w, fileSysmonEvent(11, 100, fileTestGUID, ""), false); err != nil || n != 1 {
		t.Fatal("exit retained stale command context")
	}
}

func TestWindowsFileMissingContextAndPIDReuseRetainOriginals(t *testing.T) {
	for _, mode := range []string{"no-create", "no-command", "new-guid", "other-host", "conflicting-image", "fault"} {
		t.Run(mode, func(t *testing.T) {
			var out bytes.Buffer
			w, _ := fileLearningFixture(t, &out)
			command := "powershell -File same.ps1"
			if mode == "no-command" {
				command = ""
			}
			if mode != "no-create" {
				if _, err := WriteSource(w, fileSysmonEvent(1, 1, fileTestGUID, command), false); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "fault" {
				SourceFault(w, "source-gap")
			}
			for i := 0; i < 6; i++ {
				e := fileSysmonEvent(11, 10+i, fileTestGUID, "")
				if mode == "other-host" {
					e.System.Computer = "other-host"
				}
				for j := range e.EventData {
					if mode == "new-guid" && e.EventData[j].Name == "ProcessGuid" {
						e.EventData[j].Value = "{bbbb0000-0000-0000-0000-000000000001}"
					}
					if mode == "conflicting-image" && e.EventData[j].Name == "Image" {
						e.EventData[j].Value += ".changed"
					}
				}
				if n, err := WriteSource(w, e, false); err != nil || n != 1 {
					t.Fatalf("incomplete file suppressed: n=%d err=%v", n, err)
				}
			}
		})
	}
}

func TestWindowsFileCacheBoundAndExpiry(t *testing.T) {
	w, _ := fileLearningFixture(t, io.Discard)
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	for i := 0; i < 1500; i++ {
		items := Classify(fileSysmonEvent(1, i+1, fmt.Sprintf("{abcd0000-0000-0000-0000-%012x}", i), strings.Repeat("x", 5000)), false)
		w.rememberFileExecution(items[0], now)
	}
	if len(w.fileContexts) == 0 || len(w.fileContexts) > 1024 || w.fileContextBytes > activityContextBytes {
		t.Fatal("file context was not bounded or never admitted")
	}
	w.pruneContexts(now.Add(61 * time.Minute))
	if len(w.fileContexts) != 0 || w.fileContextBytes != 0 {
		t.Fatal("expired file context retained")
	}
}

func TestWindowsFileSinkFailureStopsFilteringBeforeCursor(t *testing.T) {
	w, dir := fileLearningFixture(t, &failedSync{})
	if err := w.Sync(); err == nil {
		t.Fatal("failed sink allowed cursor checkpoint")
	}
	if err := w.fileEngine.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	state, err := behaviorlearning.Inspect(filepath.Join(dir, "state", "file-operations"), 64)
	if err != nil || state.Mode != "degraded" {
		t.Fatalf("file engine ignored sink failure: %v", err)
	}
}
