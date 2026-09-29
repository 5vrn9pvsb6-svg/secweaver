//go:build windows

package agentupdate

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const (
	createNewProcessGroup  = 0x00000200
	createBreakawayFromJob = 0x01000000
	createNoWindow         = 0x08000000
)

// launchWindowsReplaceHelper starts the post-exit transaction without a
// console and outside the parent's Job Object. A service or CI supervisor may
// kill all processes left in its job when the Agent exits, so process-group
// detachment alone is insufficient. If the host forbids breakaway, fail closed
// while the current service is still running instead of launching a helper
// that may be killed immediately after the Agent exits.
func launchWindowsReplaceHelper(scriptPath, stderrPath string) (*os.Process, error) {
	return startWindowsReplaceHelper(
		scriptPath,
		stderrPath,
		createNewProcessGroup|createNoWindow|createBreakawayFromJob,
	)
}

// startWindowsReplaceHelper owns only process creation. stderr uses a unique,
// ACL-protected path for each transaction so a still-exiting activation helper
// cannot lock a rollback helper's diagnostic. The updater bounds old files; this
// is startup evidence, not an append-only Windows service log.
func startWindowsReplaceHelper(scriptPath, stderrPath string, creationFlags uint32) (*os.Process, error) {
	stderr, err := os.OpenFile(stderrPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open Windows replacement helper diagnostic: %w", err)
	}
	defer stderr.Close()

	cmd := exec.Command(
		"powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-File", scriptPath,
	)
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: creationFlags,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd.Process, nil
}
