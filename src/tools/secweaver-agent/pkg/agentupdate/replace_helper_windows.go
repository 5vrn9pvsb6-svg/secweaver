//go:build windows

package agentupdate

import (
	"os/exec"
	"syscall"
)

const (
	createNewProcessGroup = 0x00000200
	detachedProcess       = 0x00000008
)

// launchWindowsReplaceHelper starts the post-exit transaction outside the
// Agent's service process group. The service deliberately reports a successful
// stop for an update, so this helper is the sole owner of replacing the locked
// executable and starting SCM again. Releasing the process handle avoids a leak
// in a service expected to run for months before its next update.
func launchWindowsReplaceHelper(scriptPath string) error {
	cmd := exec.Command(
		"powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-File", scriptPath,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createNewProcessGroup | detachedProcess,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
