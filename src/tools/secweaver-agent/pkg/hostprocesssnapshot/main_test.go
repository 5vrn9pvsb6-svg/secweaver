package hostprocesssnapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"secweaver-agent/internal/agentactivity"
)

func TestCollectLinuxProcessFixture(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte("btime 1700000000\n"), 0644); err != nil {
		t.Fatal(err)
	}
	status := "Name:\tnginx\nState:\tS (sleeping)\nPid:\t123\nPPid:\t1\nUid:\t0 0 0 0\nThreads:\t3\nVmRSS:\t2048 kB\nVmSize:\t8192 kB\n"
	stat := "123 (nginx worker) S 1 0 0 0 0 0 0 0 0 0 200 100 0 0 0 0 3 0 500 8388608 512"
	if err := linuxProcessFixture(root, 123, status, stat, []string{"nginx", "-g", "daemon off;"}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000010, 0).UTC()
	processes, err := collectLinuxProcesses(context.Background(), root, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 1 {
		t.Fatalf("process count=%d", len(processes))
	}
	p := processes[0]
	if p.PID != 123 || p.PPID != 1 || p.Process != "nginx" || p.RSSBytes != 2048*1024 || p.ThreadCount != 3 {
		t.Fatalf("unexpected process: %+v", p)
	}
	if p.CommandLine != `nginx -g "daemon off;"` {
		t.Fatalf("command_line=%q", p.CommandLine)
	}
}

func linuxProcessFixture(procRoot string, pid int, status, stat string, cmdline []string) error {
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(base, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(base, "status"), []byte(status), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(base, "stat"), []byte(stat), 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(base, "cmdline"), []byte(strings.Join(cmdline, "\x00")+"\x00"), 0644)
}

func TestRedactProcessSecrets(t *testing.T) {
	p := processInfo{Command: []string{"sshpass", "-p", "secret-value", "ssh", "root@example"}, CommandLine: "sshpass -p secret-value ssh root@example"}
	redactProcess(&p)
	if !p.CommandRedacted || p.Command[2] != "[REDACTED]" || bytes.Contains([]byte(p.CommandLine), []byte("secret-value")) {
		t.Fatalf("secret was not redacted: %+v", p)
	}
}

func TestRowsToProcessInfoMapsWindowsFields(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rows := []windowsProcess{{
		PID: 42, PPID: 4, Name: "worker.exe", ExecutablePath: `C:\Apps\worker.exe`,
		CommandLine: `worker.exe --token secret`, CreationDate: "2026-07-16T11:00:00Z",
		WorkingSetSize: 4096, VirtualSize: 8192, ThreadCount: 6, SessionID: 1,
		CPUTimeMS: 1250, User: `DOMAIN\svc`,
	}}
	processes := rowsToProcessInfo(rows, now)
	if len(processes) != 1 {
		t.Fatalf("process count=%d", len(processes))
	}
	p := processes[0]
	if p.PID != 42 || p.PPID != 4 || p.Process != "worker.exe" || p.User != `DOMAIN\svc` || p.ElapsedSeconds != 3600 || p.RSSBytes != 4096 {
		t.Fatalf("unexpected process: %+v", p)
	}
}

func TestRunWritesOneEventPerProcessWithSharedSnapshot(t *testing.T) {
	var out bytes.Buffer
	st := &stats{}
	err := run(context.Background(), runConfig{
		Once: true, Interval: time.Minute, HostIP: "10.0.0.1", RedactSensitive: true,
		Collector: func(context.Context, time.Time) ([]processInfo, error) {
			return []processInfo{{PID: 2, Process: "b"}, {PID: 1, Process: "a"}}, nil
		},
	}, &out, st)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n"))
	if len(lines) != 2 || st.Snapshots != 1 || st.EventsWritten != 2 {
		t.Fatalf("lines=%d stats=%+v", len(lines), st)
	}
	var first, second processEvent
	if json.Unmarshal(lines[0], &first) != nil || json.Unmarshal(lines[1], &second) != nil {
		t.Fatal("invalid JSON events")
	}
	if first.PID != "1" || second.PID != "2" || first.SnapshotID == "" || first.SnapshotID != second.SnapshotID {
		t.Fatalf("unexpected events: %+v %+v", first, second)
	}
}

func TestProcessEventsEmitDeltaAndCompressBaselineCommands(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	initial := []processInfo{
		{PID: 10, PPID: 1, UID: "1000", User: "app", Process: "worker", Exe: "/opt/worker", CommandLine: "/opt/worker --serve", StartTime: now.Add(-time.Hour).Format(time.RFC3339Nano), Cgroup: "/app"},
	}
	initial[0].CommandHash = processCommandHash(initial[0])
	events, state, delta, err := processEvents(initial, persistedProcessState{}, 24*time.Hour, "host-a", "10.0.0.1", "snapshot-1", now, 4)
	if err != nil {
		t.Fatal(err)
	}
	if delta || len(events) != 1 || events[0].EventType != "process_snapshot" {
		t.Fatalf("unexpected baseline: delta=%v events=%+v", delta, events)
	}
	if events[0].CommandLine != "" || len(events[0].Command) != 0 || events[0].CommandHash == "" {
		t.Fatalf("baseline command was not compressed: %+v", events[0])
	}

	changed := initial[0]
	changed.UID = "0"
	changed.User = "root"
	changed.CommandLine = "/opt/worker --admin"
	changed.CommandHash = processCommandHash(changed)
	started := processInfo{PID: 11, PPID: 10, Process: "helper", Exe: "/opt/helper", CommandLine: "/opt/helper", StartTime: now.Add(time.Minute).Format(time.RFC3339Nano)}
	started.CommandHash = processCommandHash(started)
	events, _, delta, err = processEvents([]processInfo{changed, started}, state, 24*time.Hour, "host-a", "10.0.0.1", "snapshot-2", now.Add(10*time.Minute), 3)
	if err != nil {
		t.Fatal(err)
	}
	if !delta || len(events) != 2 {
		t.Fatalf("unexpected delta: delta=%v events=%+v", delta, events)
	}
	if events[0].EventType != "process_change" || events[0].CommandLine == "" || !containsString(events[0].ChangeFields, "uid") || !containsString(events[0].ChangeFields, "command_hash") {
		t.Fatalf("missing process change detail: %+v", events[0])
	}
	if events[1].EventType != "process_start" || events[1].CommandLine == "" {
		t.Fatalf("missing process start detail: %+v", events[1])
	}
}

func TestProcessEventsTreatPIDReuseAsExitAndStart(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	old := processInfo{PID: 42, Process: "old", CommandLine: "old", StartTime: now.Add(-time.Hour).Format(time.RFC3339Nano)}
	old.CommandHash = processCommandHash(old)
	_, state, _, err := processEvents([]processInfo{old}, persistedProcessState{}, 24*time.Hour, "host-a", "", "snapshot-1", now, 1)
	if err != nil {
		t.Fatal(err)
	}
	reused := processInfo{PID: 42, Process: "new", CommandLine: "new", StartTime: now.Add(time.Minute).Format(time.RFC3339Nano)}
	reused.CommandHash = processCommandHash(reused)
	events, _, _, err := processEvents([]processInfo{reused}, state, 24*time.Hour, "host-a", "", "snapshot-2", now.Add(10*time.Minute), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].EventType != "process_start" || events[1].EventType != "process_exit" {
		t.Fatalf("PID reuse must be start+exit, got %+v", events)
	}
}

func TestProcessEventsDoNotDeltaTrackMissingStartTime(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	process := processInfo{PID: 7, Process: "restricted", CommandLine: "restricted"}
	process.CommandHash = processCommandHash(process)
	_, state, _, err := processEvents([]processInfo{process}, persistedProcessState{}, 24*time.Hour, "host-a", "", "snapshot-1", now, 1)
	if err != nil {
		t.Fatal(err)
	}
	events, next, delta, err := processEvents([]processInfo{process}, state, 24*time.Hour, "host-a", "", "snapshot-2", now.Add(10*time.Minute), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !delta || len(events) != 0 || len(next.Processes) != 0 {
		t.Fatalf("process without start_time entered delta state: events=%+v state=%+v", events, next)
	}
}

func TestProcessEventsRejectEmptyIdentifiableCollection(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	process := processInfo{PID: 7, Process: "worker", StartTime: now.Add(-time.Hour).Format(time.RFC3339Nano)}
	process.CommandHash = processCommandHash(process)
	_, state, _, err := processEvents([]processInfo{process}, persistedProcessState{}, 24*time.Hour, "host-a", "", "snapshot-1", now, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, next, _, err := processEvents(nil, state, 24*time.Hour, "host-a", "", "snapshot-2", now.Add(10*time.Minute), 1)
	if err == nil || len(next.Processes) != 1 {
		t.Fatalf("incomplete scan advanced state: state=%+v err=%v", next, err)
	}
}

func TestLoadProcessStateQuarantinesCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := loadProcessState(path, "host-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.Initialized || len(state.Processes) != 0 {
		t.Fatalf("corrupt state did not reset safely: %+v", state)
	}
	matches, err := filepath.Glob(path + ".corrupt-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("corrupt state was not quarantined: matches=%v err=%v", matches, err)
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func TestRecognizesOnlyExactInternalWindowsScript(t *testing.T) {
	known := agentactivity.MarkPowerShellScript(windowsProcessScript)
	if !agentactivity.IsInternalPowerShellScript(known) {
		t.Fatal("fixed process inventory script should be recognized")
	}
	if agentactivity.IsInternalPowerShellScript(known + "; Invoke-Expression 'malicious'") {
		t.Fatal("modified script must not be recognized as an internal collector")
	}
}
