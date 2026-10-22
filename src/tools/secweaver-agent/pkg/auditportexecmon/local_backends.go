package auditportexecmon

import (
	"fmt"
	"net"
	"path"
	"strings"
)

const maxLocalBackendListeners = 64

// localBackendListener is a local collection scope, not a proxy mapping. All
// three fields must match; port/name alone must not authorize an unrelated PID.
type localBackendListener struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Exe     string `json:"exe"`
}

type localBackendProcess struct {
	PID, PPID int
	StartTime uint64
	Exe, Comm string
}

// validateLocalBackendListeners rejects broad selectors before any tracker or
// audit mutation. Literal loopback IPs avoid DNS and wildcard scope expansion.
func validateLocalBackendListeners(listeners []localBackendListener) error {
	if len(listeners) > maxLocalBackendListeners {
		return fmt.Errorf("exec.local_backend_listeners supports at most %d entries", maxLocalBackendListeners)
	}
	seen := map[string]bool{}
	for _, l := range listeners {
		ip := net.ParseIP(l.Address)
		if ip == nil || !ip.IsLoopback() || l.Port < 1 || l.Port > 65535 ||
			!path.IsAbs(l.Exe) || path.Clean(l.Exe) != l.Exe || len(l.Exe) > 4096 || strings.ContainsRune(l.Exe, 0) {
			return fmt.Errorf("exec.local_backend_listeners requires a literal loopback address, port 1-65535 and a clean absolute exe path")
		}
		key := fmt.Sprintf("%s/%d/%s", ip.String(), l.Port, l.Exe)
		if seen[key] {
			return fmt.Errorf("exec.local_backend_listeners contains a duplicate selector")
		}
		seen[key] = true
	}
	return nil
}

func localBackendEndpointSelected(l listenerInfo, selectors []localBackendListener) bool {
	for _, selector := range selectors {
		if l.Port == selector.Port && listenAddressMatches(selector.Address, l.Address) {
			return true
		}
	}
	return false
}

// readLocalBackendProcess brackets uncached procfs reads with lifetime tokens.
// A disappearing/reused PID is unknown, not a reason to use a same-name daemon.
func readLocalBackendProcess(pid int) localBackendProcess {
	start := readProcessStartTime(pid)
	if pid <= 1 || start == 0 {
		return localBackendProcess{}
	}
	p := localBackendProcess{PID: pid, PPID: readProcessParentPID(pid), StartTime: start,
		Exe: cleanDeletedSuffix(readProcExe(pid)), Comm: readProcComm(pid)}
	if readProcessStartTime(pid) != start {
		return localBackendProcess{}
	}
	return p
}

// resolveLocalBackendRoot admits an exact socket owner and walks only its real
// same-executable parent chain. This seeds a PHP-FPM master plus its workers
// when netstat reports one inherited-FD worker, without merging independent
// same-executable services. The bounded walk never crosses a proxy/runtime.
func resolveLocalBackendRoot(l listenerInfo, selectors []localBackendListener, inspect func(int) localBackendProcess) (listenerInfo, bool) {
	if !isLoopback(l.Address) || !localBackendEndpointSelected(l, selectors) {
		return listenerInfo{}, false
	}
	owner := inspect(l.PID)
	if owner.PID != l.PID || owner.StartTime == 0 {
		return listenerInfo{}, false
	}
	matched := false
	for _, selector := range selectors {
		if selector.Exe == owner.Exe && localBackendEndpointSelected(l, []localBackendListener{selector}) {
			matched = true
			break
		}
	}
	if !matched {
		return listenerInfo{}, false
	}
	root := owner
	seen := map[int]bool{root.PID: true}
	for depth := 0; depth < 64 && root.PPID > 1; depth++ {
		parent := inspect(root.PPID)
		if parent.PID != root.PPID || parent.StartTime == 0 || parent.Exe != owner.Exe || seen[parent.PID] {
			break
		}
		current := inspect(root.PID)
		if current.StartTime != root.StartTime || current.PPID != parent.PID || current.Exe != owner.Exe {
			return listenerInfo{}, false
		}
		seen[parent.PID] = true
		root = parent
	}
	// Recheck both ends after the walk; bootstrap additionally revalidates root
	// lifetime before and after tracking. Unknown identities fail closed here.
	if current := inspect(owner.PID); current.StartTime != owner.StartTime || current.Exe != owner.Exe || current.PPID != owner.PPID {
		return listenerInfo{}, false
	}
	if current := inspect(root.PID); current.StartTime != root.StartTime || current.Exe != root.Exe {
		return listenerInfo{}, false
	}
	l.PID, l.RootStartTime, l.Process = root.PID, root.StartTime, root.Comm
	l.MonitorExe, l.ExeOnly = "", false
	l.LocalBackendExe = root.Exe
	return l, true
}
