//go:build linux && (amd64 || arm64)

package ebpf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"secweaver-agent/pkg/processtracker"
)

type parentKernelProof struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Comm string `json:"comm"`
	Exe  string `json:"exe"`
}

// This opt-in test attaches real programs and runs disposable processes. It
// needs root/BTF and must never silently skip a verifier error after opt-in.
// Subreaper ownership is restored after testing; no host service is modified.
func TestParentSnapshotKernel(t *testing.T) {
	if os.Getenv("SECWEAVER_EBPF_PARENT_INTEGRATION") != "1" {
		t.Skip("set SECWEAVER_EBPF_PARENT_INTEGRATION=1 on a disposable Linux test host")
	}
	var previous int32
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&previous)), 0, 0, 0, 0); errno != 0 {
		t.Fatal(errno)
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(previous), 0, 0, 0) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tracker, err := (Factory{}).New(ctx, processtracker.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tracker.Close()
	if err := tracker.Track(uint32(os.Getpid()), uint32(os.Getppid()), uint32(os.Getpid()), 123456, true); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"exited", "reparent", "long-path"} {
		t.Run(mode, func(t *testing.T) {
			proofFile := filepath.Join(t.TempDir(), "parent-proof.json")
			marker := "secweaver-parent-" + mode + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
			program, helperMode := executable, mode
			if mode == "long-path" {
				// A real executable beyond the path budget must yield explicit
				// truncation without losing the parent name/start token or exec.
				program = filepath.Join(t.TempDir(), strings.Repeat("x", 120), strings.Repeat("y", 120), "parent-helper")
				if err := os.MkdirAll(filepath.Dir(program), 0700); err != nil {
					t.Fatal(err)
				}
				input, err := os.Open(executable)
				if err != nil {
					t.Fatal(err)
				}
				output, err := os.OpenFile(program, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
				if err != nil {
					input.Close()
					t.Fatal(err)
				}
				_, copyErr := io.Copy(output, input)
				input.Close()
				closeErr := output.Close()
				if copyErr != nil || closeErr != nil {
					t.Fatalf("copy long-path executable: copy=%v close=%v", copyErr, closeErr)
				}
				helperMode = "exited"
			}
			command := exec.CommandContext(ctx, program, "-test.run=^TestParentSnapshotHelper$", "--", helperMode, proofFile, marker)
			command.Env = append(os.Environ(), "SECWEAVER_EBPF_PARENT_HELPER=1")
			if body, err := command.CombinedOutput(); err != nil {
				t.Fatalf("parent helper: %v: %s", err, body)
			}
			// Waiting for the helper first forces userspace validation after the
			// original parent has exited. Consume only the uniquely marked exec.
			for {
				select {
				case err := <-tracker.Errors():
					if err != nil {
						t.Fatal(err)
					}
				case event, ok := <-tracker.Events():
					if !ok {
						t.Fatal("tracker closed before proof")
					}
					if event.Type != processtracker.EventExec || event.Filename != "/bin/echo" || len(event.Args) != 2 || event.Args[1] != marker {
						if event.Type == processtracker.EventExec && event.Filename == "/bin/echo" {
							t.Logf("echo without expected staged argv: %+v", event)
						}
						continue
					}
					body, err := os.ReadFile(proofFile)
					if err != nil {
						t.Fatal(err)
					}
					var proof parentKernelProof
					if err := json.Unmarshal(body, &proof); err != nil {
						t.Fatal(err)
					}
					if mode == "reparent" && proof.PPID != os.Getpid() {
						t.Fatalf("child not adopted by test subreaper: %+v", proof)
					}
					parent := event.Parent
					if int(event.PID) != proof.PID || int(event.PPID) != proof.PPID || parent == nil || parent.Comm != proof.Comm || parent.StartBootNS == 0 {
						t.Fatalf("kernel evidence differs from exec-time proof: event=%+v parent=%+v proof=%+v", event, parent, proof)
					}
					if mode == "long-path" {
						if parent.Exe != "" || parent.ExeStatus != "truncated" {
							t.Fatalf("long path misrepresented as complete: %+v", parent)
						}
					} else if parent.Exe != proof.Exe || parent.ExeStatus != "captured" {
						t.Fatalf("complete parent path mismatch: parent=%+v proof=%+v", parent, proof)
					}
					t.Logf("pid=%d ppid=%d parent=%s exe=%s start_boot_ns=%d root=%d", event.PID, event.PPID, parent.Comm, parent.Exe, parent.StartBootNS, event.RootPID)
					if mode == "reparent" {
						// The test adopts this helper; reap it without touching any
						// unrelated children of the test process.
						_, _ = unix.Wait4(proof.PID, nil, 0, nil)
					}
					return
				case <-ctx.Done():
					t.Fatal("timed out waiting for marked exec")
				}
			}
		})
	}
}

// Helpers run only in separately spawned test processes. The orphan case
// waits for a genuine parent change before exec, exposing stale fork-time PPID.
func TestParentSnapshotHelper(t *testing.T) {
	if os.Getenv("SECWEAVER_EBPF_PARENT_HELPER") != "1" {
		return
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) != 3 {
		t.Fatalf("invalid helper arguments: %v", args)
	}
	mode, proofFile, marker := args[0], args[1], args[2]
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if mode == "exited" || mode == "reparent" {
		childMode := "exec"
		if mode == "reparent" {
			childMode = "orphan"
		}
		command := exec.Command(executable, "-test.run=^TestParentSnapshotHelper$", "--", childMode, proofFile, marker)
		command.Env = os.Environ()
		if mode == "exited" {
			if err := command.Run(); err != nil {
				t.Fatal(err)
			}
			return
		}
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		defer command.Process.Release()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(proofFile + ".ready"); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		_ = command.Process.Kill()
		t.Fatal("orphan did not become ready")
	}
	if mode == "orphan" {
		original := os.Getppid()
		if err := os.WriteFile(proofFile+".ready", []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for os.Getppid() == original && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if os.Getppid() == original {
			t.Fatal("original parent still alive")
		}
	}
	ppid := os.Getppid()
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", ppid))
	if err != nil {
		t.Fatal(err)
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", ppid))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(parentKernelProof{PID: os.Getpid(), PPID: ppid, Comm: strings.TrimSpace(string(comm)), Exe: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proofFile, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := execFromNonLeader([]string{"echo", marker}); err != nil {
		t.Fatal(err)
	}
}

// Force de_thread instead of relying on Go's scheduler to occasionally choose
// a nonleader. The old group leader exits during this exec but the process
// remains alive; a per-thread exit must not delete its owner or staged argv.
func execFromNonLeader(args []string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if unix.Gettid() != os.Getpid() {
		return unix.Exec("/bin/echo", args, os.Environ())
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		result <- unix.Exec("/bin/echo", args, os.Environ())
	}()
	return <-result
}
