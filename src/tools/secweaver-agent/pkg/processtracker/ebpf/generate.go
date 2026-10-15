package ebpf

// Regeneration is a release-time operation. The resulting CO-RE object is
// embedded in generated Go, so production hosts never invoke this command.
// Keep the v1 instruction baseline for vendor 4.19 verifiers; newer LLVM
// defaults can emit ALU32 operations with different range-analysis behavior.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target bpfel -type process_event -type process_owner processLifecycle process_lifecycle.c -- -O2 -g -Wall -mcpu=v1
