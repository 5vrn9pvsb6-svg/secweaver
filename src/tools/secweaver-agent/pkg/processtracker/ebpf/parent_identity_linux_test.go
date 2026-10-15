//go:build linux && (amd64 || arm64)

package ebpf

import (
	"testing"

	"secweaver-agent/pkg/processtracker"
)

func TestDecodeParentSnapshotSurvivesMissingProcess(t *testing.T) {
	raw := processLifecycleProcessEvent{Type: processtracker.EventExec, Ppid: 123, ParentFlags: parentPIDValid | parentCommValid | parentStartValid | parentExeValid, ParentStartBoottimeNs: 987654321, ParentExeOffset: 239}
	for i, c := range []byte("original-parent") {
		raw.ParentComm[i] = int8(c)
	}
	for i, c := range []byte("/usr/bin/parent ") {
		raw.ParentExe[239+i] = int8(c)
	}
	parent := decodeParentIdentity(raw)
	if parent == nil || parent.Comm != "original-parent" || parent.StartBootNS != 987654321 || parent.Exe != "/usr/bin/parent " || parent.ExeStatus != "captured" {
		t.Fatalf("historical parent changed: %+v", parent)
	}
}

func TestParentNamePreservesWhitespace(t *testing.T) {
	raw := processLifecycleProcessEvent{Type: processtracker.EventExec, Ppid: 12, ParentFlags: parentPIDValid | parentCommValid}
	for i, c := range []byte(" parent name ") {
		raw.ParentComm[i] = int8(c)
	}
	if got := decodeParentIdentity(raw); got == nil || got.Comm != " parent name " {
		t.Fatalf("kernel parent name was normalized: %+v", got)
	}
}

// Per-field validity prevents bytes left in the per-CPU scratch map by a
// previous exec from being attributed to a later fork, unreadable or reused PID.
func TestDecodeParentSnapshotRejectsStaleAndIncompleteBytes(t *testing.T) {
	base := processLifecycleProcessEvent{Type: processtracker.EventExec, Ppid: 123, ParentStartBoottimeNs: 999}
	base.ParentComm[0] = 'x'
	base.ParentExe[0] = '/'
	base.ParentExe[1] = 'x'
	for _, tc := range []struct {
		name   string
		flags  uint32
		offset uint32
		want   string
	}{
		{"unavailable", parentPIDValid, 0, "unavailable"},
		{"truncated", parentPIDValid | parentExeValid | parentExeTruncated, 0, "truncated"},
		{"invalid-offset", parentPIDValid | parentExeValid, 256, "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := base
			raw.ParentFlags, raw.ParentExeOffset = tc.flags, tc.offset
			parent := decodeParentIdentity(raw)
			if parent == nil || parent.Comm != "" || parent.StartBootNS != 0 || parent.Exe != "" || parent.ExeStatus != tc.want {
				t.Fatalf("unproven evidence accepted: %+v", parent)
			}
		})
	}
	base.ParentFlags = parentCommValid | parentStartValid
	if decodeParentIdentity(base) != nil {
		t.Fatal("parent without relationship accepted")
	}
	base.ParentFlags, base.Type = parentPIDValid, processtracker.EventFork
	if decodeParentIdentity(base) != nil {
		t.Fatal("fork scratch bytes interpreted as exec parent")
	}
}
