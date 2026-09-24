//go:build windows

package behaviorlearning

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

// lockState uses a non-shared handle; process death releases ownership. Opening
// the reparse point itself lets us reject redirects instead of locking elsewhere.
func lockState(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("invalid learning lock: %v", err)
	}
	return os.NewFile(uintptr(h), path), nil
}
