//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The generated event layout and decoder must agree after adding kernel
// identity fields. Empty argv elements are meaningful and cannot be dropped.
func TestDecodeLearningIdentity(t *testing.T) {
	raw := processLifecycleProcessEvent{Type: 2, Pid: 42, Uid: 1001, Gid: 1002, Euid: 1001, Egid: 1002, Auid: 4294967295, IdentityValid: 1, StartBoottimeNs: 123000000, ExecutableInode: 1234, ExecutableDev: 0x801, Argc: 3}
	raw.Args[0][0] = 'x'
	raw.Args[2][0] = 'z'
	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, raw); err != nil {
		t.Fatal(err)
	}
	var decoded processLifecycleProcessEvent
	if err := binary.Read(&buffer, binary.LittleEndian, &decoded); err != nil {
		t.Fatal(err)
	}
	event := decodeEvent(decoded)
	if !event.IdentityValid || event.EUID != 1001 || event.EGID != 1002 || event.AUID != 4294967295 || event.StartBootNS != 123000000 || event.ExecutableInode != 1234 {
		t.Fatalf("identity: %+v", event)
	}
	if len(event.Args) != 3 || event.Args[1] != "" {
		t.Fatalf("argv boundaries: %#v", event.Args)
	}
	raw.IdentityValid = 0
	if decodeEvent(raw).IdentityValid {
		t.Fatal("missing kernel evidence became trusted")
	}
}

func TestLearningIdentityObjectLoads(t *testing.T) {
	spec, err := loadProcessLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	if spec.Programs["handle_process_exec"] == nil {
		t.Fatal("missing exec program")
	}
	if got := spec.Maps["pending_execs"].ValueSize; got != uint32(binary.Size(processLifecycleProcessEvent{})) {
		t.Fatalf("kernel event size %d != Go %d", got, binary.Size(processLifecycleProcessEvent{}))
	}
}
