//go:build !windows

package agentupdate

import (
	"errors"
	"os"
)

// launchWindowsReplaceHelper is a defensive non-Windows stub. Install and
// rollback reach this path only when runtime.GOOS is windows, but keeping the
// platform boundary explicit prevents generic updater code from importing
// Windows-only process attributes.
func launchWindowsReplaceHelper(string, string) (*os.Process, error) {
	return nil, errors.New("Windows replacement helper is unavailable on this platform")
}
