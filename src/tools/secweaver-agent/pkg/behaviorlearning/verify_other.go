//go:build !linux

package behaviorlearning

import "fmt"

type Execution struct {
	PID, PPID, RootPID              int
	Exe                             string
	Args                            []string
	UID, GID, EUID, EGID, AUID, CWD string
	Address                         string
	Port                            int
	Success, Truncated              bool
	HasTTY                          *bool
	Backend                         string
	Inode, Device, SourceTime       string
	StartBootNS                     uint64
}

// Verifier is the unavailable Linux verifier on other platforms. Windows uses
// its separate execution-time Sysmon adapter in internal/windowsevidence.
type Verifier struct{}

// ParentInstance never fabricates ancestry on unsupported platforms.
func (*Verifier) ParentInstance(int) string { return "" }

func NewVerifier() (*Verifier, error) { return nil, fmt.Errorf("Linux verification unavailable") }
func (*Verifier) Verify(Execution) (Context, string, string, string) {
	return Context{}, "", "", "unsupported_platform"
}
