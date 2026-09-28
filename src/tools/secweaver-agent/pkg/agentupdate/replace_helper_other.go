//go:build !windows

package agentupdate

import "errors"

// launchWindowsReplaceHelper is a defensive non-Windows stub. Install and
// rollback reach this path only when runtime.GOOS is windows, but keeping the
// platform boundary explicit prevents generic updater code from importing
// Windows-only process attributes.
func launchWindowsReplaceHelper(string) error {
	return errors.New("Windows replacement helper is unavailable on this platform")
}
