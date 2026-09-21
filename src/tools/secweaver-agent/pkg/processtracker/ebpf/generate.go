package ebpf

// Regeneration is a release-time operation. The resulting CO-RE object is
// embedded in generated Go, so production hosts never invoke this command.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target bpfel -type process_event -type process_owner processLifecycle process_lifecycle.c -- -O2 -g -Wall
