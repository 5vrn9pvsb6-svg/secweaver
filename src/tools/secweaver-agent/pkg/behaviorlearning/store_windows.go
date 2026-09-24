//go:build windows

package behaviorlearning

import (
	"golang.org/x/sys/windows"
	"os"
)

// protectStateDirectory restricts inheritable access to SYSTEM/Administrators.
// Unix mode bits cannot express Windows confidentiality. Unsupported ACL storage
// fails initialization and the adapter continues emitting original evidence.
func protectStateDirectory(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// Windows exposes synthetic mode bits; the protected directory ACL owns access.
func stateFilePermissionsOK(os.FileInfo) bool { return true }

// replaceStateFile uses write-through replacement; Windows directories do not
// support the Unix fsync contract used by the other platform implementation.
func replaceStateFile(source, destination string) error {
	src, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
