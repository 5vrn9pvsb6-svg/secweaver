package ebpf

import (
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// Parse the shipped object without loading it into a kernel. This check runs
// on developer platforms too; Linux tests additionally compare generated Go
// layouts and decode real wire bytes. Kernel verifier checks remain separate.
func TestEmbeddedObjectCarriesRootLifetime(t *testing.T) {
	spec, err := cebpf.LoadCollectionSpec("processlifecycle_bpfel.o")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		structure, mapping string
		offset             btf.Bits
	}{
		{"process_owner", "tracked_processes", 0},
		{"process_event", "pending_execs", 40 * 8},
	} {
		var layout *btf.Struct
		if err := spec.Types.TypeByName(tc.structure, &layout); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, member := range layout.Members {
			if member.Name != "root_start_time" {
				continue
			}
			size, err := btf.Sizeof(member.Type)
			if err != nil || size != 8 || member.Offset != tc.offset {
				t.Fatalf("%s root token layout: size=%d offset=%d err=%v", tc.structure, size, member.Offset, err)
			}
			found = true
		}
		if !found || spec.Maps[tc.mapping].ValueSize != layout.Size {
			t.Fatalf("missing/inconsistent root token in %s", tc.structure)
		}
	}
}
