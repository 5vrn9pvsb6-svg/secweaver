//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"secweaver-agent/internal/modulecontrol"
)

// prepareModuleProcessControl creates a cooperative stdin channel before Start.
// CommandContext retains the 15-second WaitDelay kill fallback configured by
// runModuleProcess when a collector cannot finish its checkpoint in time.
func prepareModuleProcessControl(cmd *exec.Cmd) (moduleProcessControl, error) {
	controlWriter, err := cmd.StdinPipe()
	if err != nil {
		return moduleProcessControl{}, fmt.Errorf("create module stop pipe: %w", err)
	}
	cmd.Env = withEnvValue(cmd.Env, modulecontrol.Environment, modulecontrol.StdinV1)
	var once sync.Once
	requestStop := func() error {
		once.Do(func() {
			_, _ = io.WriteString(controlWriter, modulecontrol.StopCommand+"\n")
			_ = controlWriter.Close()
		})
		return nil
	}
	var job windows.Handle
	afterStart := func(process *os.Process) error {
		if process == nil {
			return os.ErrProcessDone
		}
		created, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			return fmt.Errorf("create module job object: %w", err)
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, err := windows.SetInformationJobObject(
			created,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)),
		); err != nil {
			windows.CloseHandle(created)
			return fmt.Errorf("configure module job object: %w", err)
		}
		processHandle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(process.Pid))
		if err != nil {
			windows.CloseHandle(created)
			return fmt.Errorf("open module process for job assignment: %w", err)
		}
		defer windows.CloseHandle(processHandle)
		if err := windows.AssignProcessToJobObject(created, processHandle); err != nil {
			windows.CloseHandle(created)
			return fmt.Errorf("assign module process to job object: %w", err)
		}
		job = created
		return nil
	}
	closeControl := func() {
		_ = requestStop()
		if job != 0 {
			_ = windows.CloseHandle(job)
			job = 0
		}
	}
	return moduleProcessControl{requestStop: requestStop, afterStart: afterStart, close: closeControl}, nil
}
