//go:build !windows

package agentupdate

import "os"

func replaceFileAtomic(source, destination string) error {
	return os.Rename(source, destination)
}
