//go:build linux && (amd64 || arm64)

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"secweaver-agent/pkg/processtracker"
)

const (
	defaultMaxTrackedProcesses = 131072
	defaultPerfBufferBytes     = 256 << 10
)

// Factory performs cheap deterministic checks in Probe; New remains the
// authoritative verifier because kernel policy and helper availability can
// only be proven by loading and attaching the programs.
type Factory struct{}

func (Factory) Probe() error {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("%w: eBPF process tracking is release-tested only on linux/amd64 and linux/arm64", processtracker.ErrUnsupported)
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return fmt.Errorf("%w: kernel BTF is unavailable at /sys/kernel/btf/vmlinux", processtracker.ErrUnsupported)
	}
	if !tracepointExists("syscalls", "sys_enter_execve") {
		return fmt.Errorf("%w: syscalls/sys_enter_execve tracepoint is unavailable", processtracker.ErrUnsupported)
	}
	if !tracepointExists("syscalls", "sys_exit_execve") {
		return fmt.Errorf("%w: syscalls/sys_exit_execve tracepoint is unavailable", processtracker.ErrUnsupported)
	}
	if !tracepointExists("sched", "sched_process_exec") {
		return fmt.Errorf("%w: sched/sched_process_exec tracepoint is unavailable", processtracker.ErrUnsupported)
	}
	return nil
}

func (factory Factory) New(ctx context.Context, options processtracker.Options) (processtracker.Tracker, error) {
	if err := factory.Probe(); err != nil {
		return nil, err
	}
	// Kernels before 5.11 account BPF maps against RLIMIT_MEMLOCK. The call is
	// harmless on newer kernels and avoids requiring an operator-side ulimit.
	memlockErr := rlimit.RemoveMemlock()

	spec, err := loadProcessLifecycle()
	if err != nil {
		return nil, fmt.Errorf("load embedded eBPF collection: %w", err)
	}
	maxTracked := options.MaxTrackedProcesses
	if maxTracked == 0 {
		maxTracked = defaultMaxTrackedProcesses
	}
	if tracked := spec.Maps["tracked_processes"]; tracked != nil {
		tracked.MaxEntries = maxTracked
	}

	objects := processLifecycleObjects{}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		if memlockErr != nil {
			return nil, fmt.Errorf("load eBPF programs: %w (remove memlock limit: %v)", err, memlockErr)
		}
		return nil, fmt.Errorf("load eBPF programs: %w", err)
	}
	tracker := &processTracker{
		objects: objects,
		events:  make(chan processtracker.Event, 8192),
		errors:  make(chan error, 1),
	}
	if err := tracker.attach(options.PerfBufferBytesPerCPU); err != nil {
		_ = tracker.Close()
		return nil, err
	}
	go tracker.readEvents(ctx)
	go func() {
		<-ctx.Done()
		_ = tracker.Close()
	}()
	return tracker, nil
}

type processTracker struct {
	objects processLifecycleObjects
	links   []link.Link
	reader  *perf.Reader
	events  chan processtracker.Event
	errors  chan error

	lost      atomic.Uint64
	closeOnce sync.Once
}

func (tracker *processTracker) attach(perCPUBufferBytes int) error {
	if perCPUBufferBytes <= 0 {
		perCPUBufferBytes = defaultPerfBufferBytes
	}
	attachRaw := func(name string, program *cebpf.Program) error {
		attached, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: name, Program: program})
		if err != nil {
			return err
		}
		tracker.links = append(tracker.links, attached)
		return nil
	}
	if err := attachRaw("sched_process_fork", tracker.objects.HandleProcessFork); err != nil {
		return fmt.Errorf("attach sched_process_fork eBPF program: %w", err)
	}
	if err := attachRaw("sched_process_exec", tracker.objects.HandleProcessExec); err != nil {
		return fmt.Errorf("attach sched_process_exec eBPF program: %w", err)
	}
	if err := attachRaw("sched_process_exit", tracker.objects.HandleProcessExit); err != nil {
		return fmt.Errorf("attach sched_process_exit eBPF program: %w", err)
	}
	execve, err := link.Tracepoint("syscalls", "sys_enter_execve", tracker.objects.HandleExecve, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter_execve eBPF program: %w", err)
	}
	tracker.links = append(tracker.links, execve)
	execveExit, err := link.Tracepoint("syscalls", "sys_exit_execve", tracker.objects.HandleExecveExit, nil)
	if err != nil {
		return fmt.Errorf("attach sys_exit_execve eBPF program: %w", err)
	}
	tracker.links = append(tracker.links, execveExit)
	// Some older distribution kernels omit execveat. Its absence reduces only
	// that syscall's visibility and must not disable ordinary execve tracking.
	if tracepointExists("syscalls", "sys_enter_execveat") && tracepointExists("syscalls", "sys_exit_execveat") {
		if execveat, attachErr := link.Tracepoint("syscalls", "sys_enter_execveat", tracker.objects.HandleExecveat, nil); attachErr == nil {
			if execveatExit, exitErr := link.Tracepoint("syscalls", "sys_exit_execveat", tracker.objects.HandleExecveatExit, nil); exitErr == nil {
				tracker.links = append(tracker.links, execveat)
				tracker.links = append(tracker.links, execveatExit)
			} else {
				// Keep optional execveat capture transactional: without the exit
				// hook, failed syscalls could leave stale staged arguments.
				_ = execveat.Close()
			}
		}
	}
	reader, err := perf.NewReader(tracker.objects.ProcessEvents, perCPUBufferBytes)
	if err != nil {
		return fmt.Errorf("open eBPF process event buffer: %w", err)
	}
	tracker.reader = reader
	return nil
}

func (tracker *processTracker) Track(pid, ppid, rootPID uint32, descendants bool) error {
	if pid <= 1 || rootPID <= 1 {
		return fmt.Errorf("invalid tracked process: pid=%d root_pid=%d", pid, rootPID)
	}
	var flags uint32
	if descendants {
		flags = 1
	}
	owner := processLifecycleProcessOwner{RootPid: rootPID, ParentPid: ppid, Flags: flags}
	if err := tracker.objects.TrackedProcesses.Update(pid, owner, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("seed eBPF tracked process pid=%d root_pid=%d: %w", pid, rootPID, err)
	}
	return nil
}

func (tracker *processTracker) Untrack(pid uint32) error {
	if pid <= 1 {
		return nil
	}
	if err := tracker.objects.TrackedProcesses.Delete(pid); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove eBPF tracked process pid=%d: %w", pid, err)
	}
	return nil
}

func (tracker *processTracker) Events() <-chan processtracker.Event { return tracker.events }
func (tracker *processTracker) Errors() <-chan error                { return tracker.errors }
func (tracker *processTracker) LostSamples() uint64                 { return tracker.lost.Load() }

func (tracker *processTracker) readEvents(ctx context.Context) {
	defer close(tracker.events)
	defer close(tracker.errors)
	for {
		record, err := tracker.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) || ctx.Err() != nil {
				return
			}
			select {
			case tracker.errors <- fmt.Errorf("read eBPF process event: %w", err):
			default:
			}
			return
		}
		if record.LostSamples > 0 {
			tracker.lost.Add(record.LostSamples)
			continue
		}
		var raw processLifecycleProcessEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			select {
			case tracker.errors <- fmt.Errorf("decode eBPF process event: %w", err):
			default:
			}
			continue
		}
		event := decodeEvent(raw)
		select {
		case tracker.events <- event:
		case <-ctx.Done():
			return
		}
	}
}

func decodeEvent(raw processLifecycleProcessEvent) processtracker.Event {
	argc := int(raw.Argc)
	if argc > len(raw.Args) {
		argc = len(raw.Args)
	}
	args := make([]string, 0, argc)
	for index := 0; index < argc; index++ {
		if value := int8String(raw.Args[index][:]); value != "" {
			args = append(args, value)
		}
	}
	return processtracker.Event{
		Type:          raw.Type,
		TimestampNS:   raw.TimestampNs,
		RootPID:       raw.RootPid,
		PID:           raw.Pid,
		PPID:          raw.Ppid,
		UID:           raw.Uid,
		GID:           raw.Gid,
		Comm:          int8String(raw.Comm[:]),
		Filename:      int8String(raw.Filename[:]),
		Args:          args,
		ArgsTruncated: raw.Flags&1 != 0,
	}
}

func int8String(value []int8) string {
	buffer := make([]byte, 0, len(value))
	for _, character := range value {
		if character == 0 {
			break
		}
		buffer = append(buffer, byte(character))
	}
	return strings.TrimSpace(string(buffer))
}

func (tracker *processTracker) Close() error {
	var closeErr error
	tracker.closeOnce.Do(func() {
		if tracker.reader != nil {
			closeErr = tracker.reader.Close()
		}
		for index := len(tracker.links) - 1; index >= 0; index-- {
			if err := tracker.links[index].Close(); closeErr == nil && err != nil {
				closeErr = err
			}
		}
		if err := tracker.objects.Close(); closeErr == nil && err != nil {
			closeErr = err
		}
	})
	return closeErr
}

func tracepointExists(group, name string) bool {
	for _, root := range []string{"/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"} {
		if _, err := os.Stat(root + "/" + group + "/" + name + "/format"); err == nil {
			return true
		}
	}
	return false
}
