// Package processtracker defines the process-lifecycle boundary used by host
// collectors. Kernel-specific implementations live below this package so the
// audit fallback and eBPF backend cannot accidentally share lifecycle state.
package processtracker

import (
	"context"
	"errors"
)

const (
	EventFork uint32 = iota + 1
	EventExec
	EventExit
)

var ErrUnsupported = errors.New("process tracker is unsupported on this platform")

// Event is the compact, backend-neutral process lifecycle record consumed by
// audit-port-execmon. RootPID identifies the listener tree that owns the event.
type Event struct {
	Type          uint32
	TimestampNS   uint64
	RootPID       uint32
	PID           uint32
	PPID          uint32
	UID           uint32
	GID           uint32
	Comm          string
	Filename      string
	Args          []string
	ArgsTruncated bool
	// IdentityValid gates learning; zero-valued fields without it are unknown.
	IdentityValid                bool
	EUID, EGID                   uint32
	AUID                         uint32
	StartBootNS, ExecutableInode uint64
	ExecutableDev                uint32
}

// Tracker owns one kernel process-lifecycle data source. Track seeds an
// existing process; future forks inherit RootPID inside the kernel backend.
type Tracker interface {
	Track(pid, ppid, rootPID uint32, descendants bool) error
	Untrack(pid uint32) error
	Events() <-chan Event
	Errors() <-chan error
	LostSamples() uint64
	Close() error
}

// Factory allows capability probing and construction to be replaced in tests
// without importing a concrete kernel implementation into the audit fallback.
type Factory interface {
	Probe() error
	New(context.Context, Options) (Tracker, error)
}

type Options struct {
	MaxTrackedProcesses   uint32
	PerfBufferBytesPerCPU int
}
