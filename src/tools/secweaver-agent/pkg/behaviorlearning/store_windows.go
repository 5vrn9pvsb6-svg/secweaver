//go:build windows

package behaviorlearning

import (
	"os"

	"golang.org/x/sys/windows"
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

// openSummaryFile lets a status reader keep its old complete snapshot while the
// writer atomically replaces the path. os.Open omits FILE_SHARE_DELETE on
// Windows, which would turn a concurrent doctor probe into a writer failure.
// Sharing replacement does not grant access or weaken the directory's ACL.
func openSummaryFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

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
