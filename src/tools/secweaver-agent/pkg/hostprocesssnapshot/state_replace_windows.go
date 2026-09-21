//go:build windows

package hostprocesssnapshot

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var processStateMoveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

// MoveFileExW is required because os.Rename does not consistently replace an
// existing destination on Windows. WRITE_THROUGH keeps cursor durability aligned
// with the output checkpoint that precedes this state commit.
func replaceProcessStateFile(source, destination string) error {
	sourcePtr, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPtr, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	result, _, callErr := processStateMoveFileEx.Call(
		uintptr(unsafe.Pointer(sourcePtr)),
		uintptr(unsafe.Pointer(destinationPtr)),
		moveFileReplaceExisting|moveFileWriteThrough,
	)
	if result == 0 {
		return fmt.Errorf("MoveFileExW process state replace failed: %w", callErr)
	}
	return nil
}
