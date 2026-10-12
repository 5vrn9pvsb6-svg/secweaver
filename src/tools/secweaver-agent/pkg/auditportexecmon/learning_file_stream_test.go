package auditportexecmon

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fileStreamMonitor() *processTreeMonitor {
	listener := listenerInfo{PID: 1234, Process: "nginx", Port: 443, MonitorExe: "/usr/sbin/nginx", ExeOnly: true}
	return &processTreeMonitor{listeners: []listenerInfo{listener}, pidListener: map[int]listenerInfo{}, monitored: map[int]bool{}, exeMonitored: map[string]bool{}, selfBranch: map[int]bool{}, execKey: "exec", fileKey: "file", connectKey: "connect", sensitiveFileKey: "sensitive", cloneKey: "clone", trackDescendants: true, monitorSensitiveFileReads: true, sensitiveFilePaths: defaultSensitiveFilePaths}
}

func fileStreamLines(key string) []string {
	return []string{
		fmt.Sprintf(`type=SYSCALL msg=audit(1791388800.001:42): syscall=2 items=2 pid=2345 ppid=1234 exe="/usr/sbin/nginx" comm="nginx" key="%s"`, key),
		`type=CWD msg=audit(1791388800.001:42): cwd="/"`,
		`type=PATH msg=audit(1791388800.001:42): item=0 name="/etc"`,
		`type=PATH msg=audit(1791388800.001:42): item=1 name="/etc/shadow"`,
		`type=PROCTITLE msg=audit(1791388800.001:42): proctitle="nginx  -g daemon off;"`,
	}
}

// Drive the real per-line boundary; batching all records before emission hid
// the first-PATH bug. Sensitive targets deliberately occur after a directory.
func TestFileStreamWaitsForPathsAndCommand(t *testing.T) {
	for _, key := range []string{"file", "sensitive"} {
		t.Run(key, func(t *testing.T) {
			accs, monitor := map[string]*auditAccumulator{}, fileStreamMonitor()
			var out fileEvidenceCapture
			lines := fileStreamLines(key)
			for i, line := range lines {
				id, _ := consumeAuditLine(accs, line)
				emitOneReady(accs, id, "exec", "connect", "file", monitor, hostIdentity{}, false, &out)
				if i < len(lines)-1 && out.observation.Context.File != nil {
					t.Fatal("emitted before final evidence")
				}
			}
			o := out.observation
			expected := 2
			if key == "sensitive" {
				expected = 1
			}
			if !o.Complete || o.Context.File == nil || len(o.Context.File.FilePaths) != expected || o.Context.File.CommandLine != "nginx  -g daemon off;" || len(accs) != 0 {
				t.Fatalf("lost native evidence: %+v", o)
			}
		})
	}
}

// Timeout is measured from the primary record, not the latest auxiliary
// record; a missing tail must neither hang nor become eligible for suppression.
func TestFileStreamTimeoutRetainsPartialEvidence(t *testing.T) {
	for _, key := range []string{"file", "sensitive"} {
		accs, monitor := map[string]*auditAccumulator{}, fileStreamMonitor()
		var out fileEvidenceCapture
		for _, line := range fileStreamLines(key)[:3] {
			consumeAuditLine(accs, line)
		}
		acc := accs["42"]
		now := acc.firstSeen.Add(fileRecordSettleDelay)
		acc.lastRecordAt = now
		emitOne(accs, "42", "exec", "connect", "file", monitor, hostIdentity{}, false, &out, 0, now)
		if out.observation.Context.File == nil || out.observation.Complete || out.observation.Reason != "incomplete_file_paths" || len(accs) != 0 {
			t.Fatalf("partial evidence lost/qualified: %+v", out.observation)
		}
	}
}

// Exercise both production transports so their periodic flush does not bypass
// assembly. Cancellation occurs after enough time for the bounded fallback.
func TestFileEvidenceThroughAuditTransports(t *testing.T) {
	for _, source := range []string{"stream", "file"} {
		t.Run(source, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
			defer cancel()
			body := strings.Join(fileStreamLines("sensitive"), "\n") + "\n"
			var out bytes.Buffer
			m := fileStreamMonitor()
			if source == "stream" {
				_ = followAuditStream(ctx, strings.NewReader(body), "exec", "connect", "file", m, hostIdentity{}, false, &out, time.Hour)
			} else {
				path := filepath.Join(t.TempDir(), "audit.log")
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				_ = followAuditLog(ctx, path, "exec", "connect", "file", m, hostIdentity{}, true, 0, false, &out, time.Hour)
			}
			if !strings.Contains(out.String(), "/etc/shadow") || !strings.Contains(out.String(), "nginx  -g daemon off;") {
				t.Fatalf("transport lost evidence: %s", &out)
			}
		})
	}
}

// Delay/reordering within the bounded window is valid; missing or capped
// command evidence is emitted after the deadline with an actionable reason.
func TestFileCommandArrivalAndTimeout(t *testing.T) {
	for _, scenario := range []string{"delayed", "missing", "capped", "out_of_order"} {
		t.Run(scenario, func(t *testing.T) {
			accs, m := map[string]*auditAccumulator{}, fileStreamMonitor()
			var out fileEvidenceCapture
			lines := fileStreamLines("file")
			if scenario == "out_of_order" {
				lines[3], lines[4] = lines[4], lines[3]
			}
			for _, line := range lines[:4] {
				id, _ := consumeAuditLine(accs, line)
				emitOneReady(accs, id, "exec", "connect", "file", m, hostIdentity{}, false, &out)
			}
			acc := accs["42"]
			if acc == nil {
				t.Fatal("flushed before delayed tail")
			}
			if scenario == "delayed" || scenario == "out_of_order" {
				if !fileRecordPending(acc, acc.firstSeen.Add(100*time.Millisecond), 0) {
					t.Fatal("did not wait for tail")
				}
				id, _ := consumeAuditLine(accs, lines[4])
				emitOneReady(accs, id, "exec", "connect", "file", m, hostIdentity{}, false, &out)
				if !out.observation.Complete {
					t.Fatalf("delayed evidence incomplete: %+v", out.observation)
				}
			} else {
				reason := "missing_file_command"
				if scenario == "capped" {
					consumeAuditLine(accs, `type=PROCTITLE msg=audit(1791388800.001:42): proctitle="`+strings.Repeat("x", 128)+`"`)
					reason = "capped_file_command"
				}
				emitOne(accs, "42", "exec", "connect", "file", m, hostIdentity{}, false, &out, 0, acc.firstSeen.Add(fileRecordSettleDelay))
				if out.observation.Complete || out.observation.Reason != reason || out.observation.Context.File == nil {
					t.Fatalf("bad timeout evidence: %+v", out.observation)
				}
			}
		})
	}
}

func TestFileStreamEOFRetainsMissingTail(t *testing.T) {
	for _, key := range []string{"file", "sensitive"} {
		body := strings.Join(fileStreamLines(key)[:3], "\n") + "\n"
		var out fileEvidenceCapture
		_ = followAuditStream(context.Background(), strings.NewReader(body), "exec", "connect", "file", fileStreamMonitor(), hostIdentity{}, false, &out, time.Hour)
		if out.observation.Context.File == nil || out.observation.Complete || out.observation.Reason != "incomplete_file_paths" {
			t.Fatalf("EOF discarded partial evidence: %+v", out.observation)
		}
	}
}
