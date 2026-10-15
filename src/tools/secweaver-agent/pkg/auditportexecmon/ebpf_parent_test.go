package auditportexecmon

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"secweaver-agent/pkg/processtracker"
)

// Using the current test PID as PPID simulates a PID reused by an unrelated
// process. Its readable /proc name must not replace the old event's snapshot.
func TestEBPFExecUsesHistoricalParentSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		parent       *processtracker.ParentIdentity
	}{
		{"exited-or-reused", "complete", &processtracker.ParentIdentity{Comm: "original-parent", Exe: "/opt/original-parent", StartBootNS: 123456, ExeStatus: "captured"}},
		{"missing-snapshot", "unavailable", nil},
		{"bounded-path", "partial", &processtracker.ParentIdentity{Comm: "original-parent", StartBootNS: 123456, ExeStatus: "truncated"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := processtracker.Event{Type: processtracker.EventExec, PID: 42, PPID: uint32(os.Getpid()), Comm: "echo", Filename: "/bin/echo", Args: []string{"echo", "proof"}, Parent: tc.parent}
			var output bytes.Buffer
			if err := emitEBPFExecEventWithContext(source, listenerInfo{PID: 10, Process: "sshd", Port: 22}, "exec", hostIdentity{}, &output, processExecutionContext{}); err != nil {
				t.Fatal(err)
			}
			var got auditEvent
			if err := json.Unmarshal(output.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.ParentIdentityStatus != tc.status || got.ListenerProcess != "sshd" {
				t.Fatalf("parent/service evidence mixed: %+v", got)
			}
			if tc.parent == nil {
				if got.PPIDName != "" || got.PPIDExe != "" || got.PPIDStartBootNS != 0 {
					t.Fatalf("current PID repaired historical evidence: %+v", got)
				}
			} else if got.PPIDName != tc.parent.Comm || got.PPIDExe != tc.parent.Exe || got.PPIDStartBootNS != tc.parent.StartBootNS || got.PPIDExeStatus != tc.parent.ExeStatus {
				t.Fatalf("parent snapshot not preserved: %+v", got)
			}
		})
	}
}
