package auditportexecmon

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const listenerCommandTimeout = 5 * time.Second

func findExternalListeners(portFilter int, whitelistPorts map[int]bool) ([]listenerInfo, error) {
	return findExternalListenersWithSources(portFilter, whitelistPorts, listenerDiscoverySources{
		netstatCandidates: readNetstatListenerCandidates,
		socketOwners:      buildSocketInodeMapWithStats,
		procListeners:     findListenersFromProc,
	})
}

type listenerDiscoverySources struct {
	netstatCandidates func() (netstatListenerScan, error)
	socketOwners      func() (map[string]int, socketInodeScanStats)
	procListeners     func(map[string]int) []listenerInfo
}

// netstatListenerScan preserves completeness information that a plain slice
// loses. RejectedListenLines makes partial vendor-format parsing fail safe.
type netstatListenerScan struct {
	Candidates          []listenerInfo
	TCPListenLines      int
	RejectedListenLines int
}

// findExternalListenersWithSources keeps the common case cheap: root netstat
// output already contains PID/program ownership, so walking every process FD is
// only justified when netstat fails, finds nothing, omits a relevant PID, or
// contains a TCP LISTEN row the compatibility parser cannot understand.
func findExternalListenersWithSources(portFilter int, whitelistPorts map[int]bool, sources listenerDiscoverySources) ([]listenerInfo, error) {
	netstatScan, netstatErr := sources.netstatCandidates()
	needsProcFallback := netstatErr != nil || netstatScan.TCPListenLines == 0 || netstatScan.RejectedListenLines > 0
	if netstatScan.RejectedListenLines > 0 {
		// A successful command can still contain an unfamiliar row shape. Treat
		// partial parsing as incomplete discovery instead of silently dropping it.
		fmt.Fprintf(os.Stderr, "netstat listener parse incomplete: listen_lines=%d parsed=%d rejected=%d fallback=procfs\n",
			netstatScan.TCPListenLines, len(netstatScan.Candidates), netstatScan.RejectedListenLines)
	}

	seen := map[string]bool{}
	var listeners []listenerInfo
	appendListeners := func(candidates []listenerInfo) {
		for _, listener := range candidates {
			if !listenerMatchesFilter(listener, portFilter, whitelistPorts) {
				continue
			}
			if listener.Process == "" {
				listener.Process = readProcComm(listener.PID)
			}
			if listener.Process == "" && listener.MonitorExe != "" {
				listener.Process = filepath.Base(listener.MonitorExe)
			}
			if listener.Process == "" {
				listener.Process = "unknown"
			}
			identity := listenerIdentity(listener)
			if seen[identity] {
				continue
			}
			seen[identity] = true
			listeners = append(listeners, listener)
		}
	}

	for _, candidate := range netstatScan.Candidates {
		if !listenerMatchesFilter(candidate, portFilter, whitelistPorts) {
			continue
		}
		if candidate.PID <= 1 && candidate.MonitorExe == "" {
			needsProcFallback = true
			continue
		}
		if listener, ok := resolveNetstatListener(candidate, nil); ok {
			appendListeners([]listenerInfo{listener})
		}
	}

	if needsProcFallback {
		inodeToPID, stats := sources.socketOwners()
		if stats.BudgetExhausted {
			// A bounded scan protects the host from a very large FD table. Missing
			// owners remain eligible for repair on the next reconciliation round.
			fmt.Fprintf(os.Stderr, "listener /proc fd scan reached budget: scanned=%d budget=%d\n", stats.FDsScanned, stats.FDBudget)
		}
		for _, candidate := range netstatScan.Candidates {
			if !listenerMatchesFilter(candidate, portFilter, whitelistPorts) || candidate.PID > 1 || candidate.MonitorExe != "" {
				continue
			}
			if listener, ok := resolveNetstatListener(candidate, inodeToPID); ok {
				appendListeners([]listenerInfo{listener})
			}
		}
		appendListeners(sources.procListeners(inodeToPID))
	}

	if len(listeners) == 0 {
		if portFilter > 0 {
			return nil, fmt.Errorf("没有找到监听在对外地址上的 TCP 端口 %d；请确认 netstat -tlnp 可见该端口且非 127.0.0.1", portFilter)
		}
		return nil, fmt.Errorf("没有找到任何对外监听 TCP 端口；请确认 netstat -tlnp 有 LISTEN 且非 127.0.0.1")
	}
	for i := range listeners {
		enrichListenerMonitorMode(&listeners[i])
	}
	return listeners, nil
}

func listenerMatchesFilter(listener listenerInfo, portFilter int, whitelistPorts map[int]bool) bool {
	return !isLoopback(listener.Address) && (portFilter <= 0 || listener.Port == portFilter) && !whitelistPorts[listener.Port]
}

func listenerIdentity(listener listenerInfo) string {
	if listener.ExeOnly && listener.MonitorExe != "" {
		return fmt.Sprintf("exe-only:%s/%s/%d", listener.MonitorExe, listener.Address, listener.Port)
	}
	if listener.MonitorExe != "" {
		return fmt.Sprintf("exe:%s/%s/%d", listener.MonitorExe, listener.Address, listener.Port)
	}
	return fmt.Sprintf("%d/%s/%d", listener.PID, listener.Address, listener.Port)
}

func enrichListenerMonitorMode(l *listenerInfo) {
	// Long-lived multiprocess runtimes are cheaper and more stable with -F exe
	// coverage than one rule group per worker PID. PID-tree fallback remains
	// available when the executable path or kernel support is insufficient.
	if l.PID <= 1 {
		return
	}
	comm := strings.ToLower(l.Process)
	if comm == "" || comm == "unknown" {
		comm = strings.ToLower(readProcComm(l.PID))
	}
	exe := readProcExe(l.PID)
	if isNginxListener(comm, exe) {
		if resolved := resolveProcessExe(l.PID, exe, "nginx", nil, []string{"/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx", "/usr/local/openresty/nginx/sbin/nginx"}); resolved != "" {
			exe = resolved
		}
		l.MonitorExe = exe
		l.ExeOnly = true
		return
	}
	if isJavaListener(comm, exe) {
		if resolved := resolveJavaExe(l.PID, exe); resolved != "" {
			exe = resolved
		}
		l.MonitorExe = exe
		l.ExeOnly = true
	}
}

func isNginxListener(comm, exe string) bool {
	return comm == "nginx" || comm == "openresty" || strings.HasSuffix(exe, "/nginx")
}

func isApacheListener(comm, exe string) bool {
	return comm == "httpd" || comm == "apache2" || strings.HasSuffix(exe, "/httpd") || strings.HasSuffix(exe, "/apache2")
}

func isWebGatewayListener(l listenerInfo) bool {
	comm := strings.ToLower(strings.TrimSpace(l.Process))
	exe := l.MonitorExe
	if exe == "" && l.PID > 1 {
		exe = readProcExe(l.PID)
	}
	return isNginxListener(comm, exe) || isApacheListener(comm, exe)
}

// companionBackend 与 Web 网关（nginx/apache）通过 FastCGI/反向代理协作、但独立进程树的应用运行时。

func findListenersFromProc(inodeToPID map[string]int) []listenerInfo {
	var listeners []listenerInfo
	for _, procFile := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		candidates, err := parseProcNetListeners(procFile, inodeToPID)
		if err != nil {
			continue
		}
		listeners = append(listeners, candidates...)
	}
	return listeners
}

func readNetstatListenerCandidates() (netstatListenerScan, error) {
	// netstat is optional. Its timeout prevents a stuck compatibility helper from
	// blocking reconciliation; the caller decides whether /proc fallback is needed.
	// Force the C locale because the parser uses the stable LISTEN state token.
	ctx, cancel := context.WithTimeout(context.Background(), listenerCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "netstat", "-tlnp")
	cmd.Env = netstatCommandEnv(os.Environ())
	out, err := cmd.Output()
	if err != nil {
		return netstatListenerScan{}, err
	}
	return parseNetstatListenerOutput(out)
}

// parseNetstatListenerOutput records rejected TCP LISTEN rows separately from
// headers and unrelated protocols. This lets the caller distinguish an empty
// host from a successful command whose distribution-specific format was only
// partially understood.
func parseNetstatListenerOutput(out []byte) (netstatListenerScan, error) {
	var result netstatListenerScan
	scanner := bufio.NewScanner(bytes.NewReader(out))
	// netstat lines are normally short; the explicit bound avoids Scanner's 64KB
	// default becoming an undocumented compatibility limit for long process names.
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !isNetstatTCPListenLine(line) {
			continue
		}
		result.TCPListenLines++
		listener, ok := parseNetstatListenCandidate(line)
		if ok {
			result.Candidates = append(result.Candidates, listener)
		} else {
			result.RejectedListenLines++
		}
	}
	return result, scanner.Err()
}

// netstatCommandEnv preserves the service environment while replacing locale
// variables exactly once. Removing existing values avoids relying on duplicate
// environment-variable resolution in the child process.
func netstatCommandEnv(environment []string) []string {
	result := make([]string, 0, len(environment)+2)
	for _, entry := range environment {
		key, _, ok := strings.Cut(entry, "=")
		if ok && (key == "LC_ALL" || key == "LANG") {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "LC_ALL=C", "LANG=C")
}

func parseNetstatListenCandidate(line string) (listenerInfo, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return listenerInfo{}, false
	}
	if !strings.HasPrefix(strings.ToLower(fields[0]), "tcp") {
		return listenerInfo{}, false
	}
	listenIdx := -1
	for i, field := range fields {
		if strings.EqualFold(field, "LISTEN") {
			listenIdx = i
			break
		}
	}
	if listenIdx < 2 {
		return listenerInfo{}, false
	}

	// Linux net-tools normally places Local Address at LISTEN-2, but BusyBox
	// and vendor builds may insert columns. The first address-shaped token before
	// LISTEN is the local endpoint; the following one is the foreign endpoint.
	host, port, addressFound := "", 0, false
	for _, field := range fields[1:listenIdx] {
		if parsedHost, parsedPort, ok := splitHostPortLoose(field); ok {
			host, port, addressFound = parsedHost, parsedPort, true
			break
		}
	}
	if !addressFound {
		return listenerInfo{}, false
	}

	pid, name := 0, ""
	for _, field := range fields[listenIdx+1:] {
		if parsedPID, parsedName := parseNetstatPIDProgram(field); parsedPID > 0 {
			pid, name = parsedPID, parsedName
			break
		}
	}
	return listenerInfo{
		Address: host,
		Port:    port,
		PID:     pid,
		Process: name,
		Raw:     line,
	}, true
}

func isNetstatTCPListenLine(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(strings.ToLower(fields[0]), "tcp") {
		return false
	}
	for _, field := range fields[1:] {
		if strings.EqualFold(field, "LISTEN") {
			return true
		}
	}
	return false
}

func resolveNetstatListener(listener listenerInfo, inodeToPID map[string]int) (listenerInfo, bool) {
	if listener.PID <= 1 {
		if resolvedPID, resolvedName, monitorExe, ok := resolveMonitorTarget(listener.Address, listener.Port, listener.Process, inodeToPID); ok {
			listener.PID = resolvedPID
			if resolvedName != "" {
				listener.Process = resolvedName
			}
			listener.MonitorExe = monitorExe
		}
	}
	if listener.PID <= 1 && listener.MonitorExe == "" {
		return listenerInfo{}, false
	}
	if listener.Process == "" || listener.Process == "init" || listener.Process == "systemd" {
		if listener.PID > 1 {
			listener.Process = readProcComm(listener.PID)
		}
	}
	return listener, true
}

func parseNetstatPIDProgram(field string) (int, string) {
	slash := strings.Index(field, "/")
	if slash < 0 {
		return 0, ""
	}
	pid, err := strconv.Atoi(field[:slash])
	if err != nil {
		return 0, ""
	}
	name := field[slash+1:]
	if idx := strings.Index(name, ":"); idx >= 0 {
		name = name[:idx]
	}
	return pid, name
}

func resolveMonitorTarget(address string, port int, netstatName string, inodeToPID map[string]int) (pid int, name string, monitorExe string, ok bool) {
	// Socket activation can report systemd/init instead of the eventual daemon.
	// Resolve inode ownership first, then use a tightly scoped sshd fallback.
	if resolvedPID, resolvedName, found := findPIDByListenAddressPort(address, port, inodeToPID); found && resolvedPID > 1 {
		return resolvedPID, resolvedName, "", true
	}
	if pids := findSSHDMonitorPIDs(); len(pids) > 0 && (port == 22 || netstatName == "init" || netstatName == "systemd") {
		pid = pids[0]
		name = readProcComm(pid)
		if name == "" {
			name = "sshd"
		}
		return pid, name, "", true
	}
	if port == 22 {
		return 0, "sshd", "/usr/sbin/sshd", true
	}
	return 0, "", "", false
}

func findSSHDMonitorPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		if !isSSHDMonitorProcess(pid) {
			continue
		}
		pids = append(pids, pid)
	}
	for i := 0; i < len(pids); i++ {
		for j := i + 1; j < len(pids); j++ {
			if pids[j] < pids[i] {
				pids[i], pids[j] = pids[j], pids[i]
			}
		}
	}
	return pids
}

func isSSHDMonitorProcess(pid int) bool {
	comm := readProcComm(pid)
	if comm != "sshd" {
		return false
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return true
	}
	text := string(bytes.ReplaceAll(cmdline, []byte{0}, []byte(" ")))
	return !strings.Contains(text, "@")
}

func findPIDByListenAddressPort(address string, port int, inodeToPID map[string]int) (int, string, bool) {
	portHex := fmt.Sprintf("%04X", port)
	for _, procFile := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(procFile)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "sl") || line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 || !strings.EqualFold(fields[3], "0A") {
				continue
			}
			localParts := strings.Split(fields[1], ":")
			if len(localParts) != 2 || !strings.EqualFold(localParts[1], portHex) {
				continue
			}
			if isProcNetLoopback(localParts[0]) {
				continue
			}
			listenAddress := formatProcNetAddress(localParts[0])
			if !listenAddressMatches(address, listenAddress) {
				continue
			}
			inode := normalizeInode(fields[len(fields)-2])
			pid := lookupPIDByInode(inode, inodeToPID)
			if pid > 1 {
				return pid, readProcComm(pid), true
			}
		}
	}
	return 0, "", false
}

func listenAddressMatches(requested, actual string) bool {
	requested = strings.Trim(requested, "[]")
	actual = strings.Trim(actual, "[]")
	if requested == "" || requested == actual {
		return true
	}
	reqIP := net.ParseIP(requested)
	actualIP := net.ParseIP(actual)
	if reqIP != nil && actualIP != nil && reqIP.Equal(actualIP) {
		return true
	}
	return isWildcardAddress(requested) && isWildcardAddress(actual)
}

func isWildcardAddress(address string) bool {
	address = strings.Trim(address, "[]")
	return address == "" || address == "0.0.0.0" || address == "::" || address == "::0" || address == "0000:0000:0000:0000:0000:0000:0000:0000"
}

func parseProcNetListeners(path string, inodeToPID map[string]int) ([]listenerInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var listeners []listenerInfo
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "sl") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if !strings.EqualFold(fields[3], "0A") {
			continue
		}
		localParts := strings.Split(fields[1], ":")
		if len(localParts) != 2 {
			continue
		}
		if isProcNetLoopback(localParts[0]) {
			continue
		}
		port64, err := strconv.ParseUint(localParts[1], 16, 16)
		if err != nil {
			continue
		}
		port := int(port64)
		address := formatProcNetAddress(localParts[0])
		inode := normalizeInode(fields[len(fields)-2])
		pid := lookupPIDByInode(inode, inodeToPID)
		name := ""
		if pid <= 1 {
			if resolvedPID, resolvedName, monitorExe, ok := resolveMonitorTarget(address, port, "", inodeToPID); ok {
				pid = resolvedPID
				name = resolvedName
				if monitorExe != "" {
					listeners = append(listeners, listenerInfo{
						PID:        pid,
						Process:    name,
						Address:    address,
						Port:       port,
						MonitorExe: monitorExe,
						Raw:        line,
					})
					continue
				}
			}
		}
		if pid <= 1 {
			continue
		}
		if isLoopback(address) {
			continue
		}
		if name == "" {
			name = readProcComm(pid)
		}
		if name == "" {
			name = "unknown"
		}
		listeners = append(listeners, listenerInfo{
			PID:     pid,
			Process: name,
			Address: address,
			Port:    port,
			Raw:     line,
		})
	}
	return listeners, scanner.Err()
}

func formatProcNetAddress(addrHex string) string {
	switch len(addrHex) {
	case 8:
		ip := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			part := addrHex[(3-i)*2 : (3-i)*2+2]
			value, err := strconv.ParseUint(part, 16, 8)
			if err != nil {
				return addrHex
			}
			ip[i] = byte(value)
		}
		return ip.String()
	case 32:
		ip := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			part := addrHex[i*2 : i*2+2]
			value, err := strconv.ParseUint(part, 16, 8)
			if err != nil {
				return addrHex
			}
			ip[i] = byte(value)
		}
		return ip.String()
	default:
		return addrHex
	}
}
