//go:build windows

package output

import (
	"syscall"
	"unsafe"
)

var getDiskFreeSpaceEx = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

func diskFreeBytes(path string) (uint64, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var available uint64
	r1, _, callErr := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&available)),
		0,
		0,
	)
	if r1 == 0 {
		if callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, syscall.GetLastError()
	}
	return available, nil
}
