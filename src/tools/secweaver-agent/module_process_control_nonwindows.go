//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// prepareModuleProcessControl keeps Unix lifecycle semantics signal-based.
func prepareModuleProcessControl(cmd *exec.Cmd) (moduleProcessControl, error) {
	cmd.Stdin = os.Stdin
	return moduleProcessControl{
		requestStop: func() error {
			if cmd.Process == nil {
				return os.ErrProcessDone
			}
			return cmd.Process.Signal(syscall.SIGTERM)
		},
		afterStart: func(*os.Process) error { return nil },
		close:      func() {},
	}, nil
}
