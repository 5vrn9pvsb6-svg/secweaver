//go:build !windows

package hostprocesssnapshot

import "os"

// POSIX rename atomically replaces an existing state file on the same mount.
func replaceProcessStateFile(source, destination string) error {
	return os.Rename(source, destination)
}
