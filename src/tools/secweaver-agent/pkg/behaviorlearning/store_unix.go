//go:build !windows

package behaviorlearning

import (
	"os"
	"path/filepath"
)

func protectStateDirectory(path string) error    { return os.Chmod(path, 0700) }
func stateFilePermissionsOK(st os.FileInfo) bool { return st.Mode().Perm() == 0600 }

// replaceStateFile retains Unix rename and parent-directory durability.
func replaceStateFile(source, destination string) error {
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
