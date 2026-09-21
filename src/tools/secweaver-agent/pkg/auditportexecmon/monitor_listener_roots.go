package auditportexecmon

import (
	"fmt"
	"os"

	"strings"
)

// This file owns process-family-specific root selection for gateways, Java services, and SSH sessions.

func (m *processTreeMonitor) fallbackExeOnlyToPIDTree(index int, listener listenerInfo, cause error) error {
	// Some kernels reject -F exe for particular binaries/filesystems. Falling
	// back to the live PID tree preserves coverage at a higher rule cost rather
	// than disabling the listener completely.
	if listener.PID <= 1 {
		return cause
	}
	fallback := listener
	fallback.ExeOnly = false
	fallback.MonitorExe = ""
	m.listeners[index] = fallback
	fmt.Fprintf(os.Stderr, "exe-only audit rules failed, fallback to pid-tree: exe=%s process=%s pid=%d address=%s port=%d err=%v\n", listener.MonitorExe, listener.Process, listener.PID, listener.Address, listener.Port, cause)
	return m.expandPID(fallback.PID, fallback)
}

func (m *processTreeMonitor) bootstrapWebGateway(listener listenerInfo) error {
	if err := m.addExeRules(listener); err != nil {
		return err
	}
	trackListener := listener
	trackListener.ExeOnly = false
	fmt.Fprintf(os.Stderr, "web gateway monitor mode hybrid: exe=%s process=%s pid=%d address=%s port=%d\n", listener.MonitorExe, listener.Process, listener.PID, listener.Address, listener.Port)
	if !m.trackDescendants {
		return nil
	}
	for _, pid := range findMonitorSeedPIDs(listener) {
		if err := m.expandPID(pid, trackListener); err != nil {
			return err
		}
	}
	return nil
}

func (m *processTreeMonitor) bootstrapJava(listener listenerInfo) error {
	switch m.javaMonitorMode {
	case javaMonitorModePIDTree:
		pidTree := listener
		pidTree.ExeOnly = false
		pidTree.MonitorExe = ""
		fmt.Fprintf(os.Stderr, "java monitor mode pid_tree: process=%s pid=%d address=%s port=%d\n", listener.Process, listener.PID, listener.Address, listener.Port)
		return m.expandPID(pidTree.PID, pidTree)
	case javaMonitorModeHybrid:
		if err := m.addExeRules(listener); err != nil {
			return err
		}
		trackListener := listener
		trackListener.ExeOnly = false
		fmt.Fprintf(os.Stderr, "java monitor mode hybrid: exe=%s process=%s pid=%d address=%s port=%d\n", listener.MonitorExe, listener.Process, listener.PID, listener.Address, listener.Port)
		if !m.trackDescendants {
			return nil
		}
		for _, pid := range findMonitorSeedPIDs(listener) {
			if err := m.expandPID(pid, trackListener); err != nil {
				return err
			}
		}
		return nil
	default:
		return m.addExeRules(listener)
	}
}

func isSSHDListener(l listenerInfo) bool {
	if l.ExeOnly || l.PID <= 1 {
		return false
	}
	comm := strings.ToLower(l.Process)
	if comm == "sshd" {
		return true
	}
	return strings.HasSuffix(readProcExe(l.PID), "/sshd")
}

func sshdMonitorExe(listener listenerInfo) string {
	if exe := readProcExe(listener.PID); exe != "" {
		return exe
	}
	return "/usr/sbin/sshd"
}

func (m *processTreeMonitor) bootstrapSSHD(listener listenerInfo) error {
	aux := listener
	aux.MonitorExe = sshdMonitorExe(listener)
	if err := m.addExeRules(aux); err != nil {
		return err
	}
	if err := m.expandPID(listener.PID, listener); err != nil {
		return err
	}
	return m.expandSSHDSessionPIDs(listener)
}

func (m *processTreeMonitor) expandSSHDSessionPIDs(listener listenerInfo) error {
	exe := sshdMonitorExe(listener)
	skipSelf := func(pid int) bool { return m.isSelfProcessTree(pid) }
	for _, pid := range findPIDsByExe(exe) {
		if skipSelf(pid) {
			continue
		}
		if pid == listener.PID || readProcPPID(pid) == listener.PID || isDescendantOf(listener.PID, pid) {
			if err := m.expandPID(pid, listener); err != nil {
				return err
			}
		}
	}
	for _, pid := range collectDescendantPIDs(listener.PID, skipSelf) {
		if err := m.expandPID(pid, listener); err != nil {
			return err
		}
	}
	return nil
}
