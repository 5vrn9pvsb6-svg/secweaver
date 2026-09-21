package auditportexecmon

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type companionBackend struct {
	Label             string
	CommNames         []string
	CmdlineSubstrings []string
	ExeSuffixes       []string
	CommonPaths       []string
	PathMonitor       bool // 默认按 -F exe= 路径监控（当前用于 php-fpm）
}

var webGatewayCompanionBackends = []companionBackend{
	{
		Label:             "php-fpm",
		CommNames:         []string{"php-fpm"},
		CmdlineSubstrings: []string{"php-fpm"},
		ExeSuffixes:       []string{"/php-fpm"},
		CommonPaths:       []string{"/usr/sbin/php-fpm", "/usr/bin/php-fpm", "/usr/local/php/sbin/php-fpm", "/usr/local/sbin/php-fpm"},
		PathMonitor:       true,
	},
	{
		Label:             "uwsgi",
		CommNames:         []string{"uwsgi"},
		CmdlineSubstrings: []string{"uwsgi"},
		ExeSuffixes:       []string{"/uwsgi"},
		CommonPaths:       []string{"/usr/bin/uwsgi", "/usr/local/bin/uwsgi", "/usr/sbin/uwsgi"},
	},
	{
		Label:             "gunicorn",
		CommNames:         []string{"gunicorn"},
		CmdlineSubstrings: []string{"gunicorn"},
		ExeSuffixes:       []string{"/gunicorn"},
		CommonPaths:       []string{"/usr/bin/gunicorn", "/usr/local/bin/gunicorn"},
	},
	{
		Label:             "puma",
		CommNames:         []string{"puma"},
		CmdlineSubstrings: []string{"puma"},
		ExeSuffixes:       []string{"/puma"},
		CommonPaths:       []string{"/usr/bin/puma", "/usr/local/bin/puma"},
	},
	{
		Label:             "unicorn",
		CommNames:         []string{"unicorn"},
		CmdlineSubstrings: []string{"unicorn"},
		ExeSuffixes:       []string{"/unicorn", "/unicorn_rails"},
		CommonPaths:       []string{"/usr/bin/unicorn", "/usr/local/bin/unicorn"},
	},
}

func commMatchesAny(comm string, names []string) bool {
	comm = strings.ToLower(strings.TrimSpace(comm))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" && (comm == name || strings.HasPrefix(comm, name)) {
			return true
		}
	}
	return false
}

func exeMatchesCompanionBackend(exe string, backend companionBackend) bool {
	exe = cleanDeletedSuffix(exe)
	if exe == "" {
		return false
	}
	for _, suffix := range backend.ExeSuffixes {
		if strings.HasSuffix(exe, suffix) {
			return true
		}
	}
	return false
}

func matchesCompanionBackend(comm, exe string, backend companionBackend) bool {
	return commMatchesAny(comm, backend.CommNames) || exeMatchesCompanionBackend(exe, backend)
}

func cmdlineMatchesCompanionBackend(cmdline []string, backend companionBackend) bool {
	if len(cmdline) == 0 {
		return false
	}
	joined := strings.ToLower(strings.Join(cmdline, " "))
	for _, sub := range backend.CmdlineSubstrings {
		sub = strings.ToLower(strings.TrimSpace(sub))
		if sub != "" && strings.Contains(joined, sub) {
			return true
		}
	}
	return false
}

func matchesCompanionProcess(pid int, backend companionBackend) bool {
	if pid <= 1 {
		return false
	}
	comm := readProcComm(pid)
	exe := readProcExe(pid)
	if matchesCompanionBackend(comm, exe, backend) {
		return true
	}
	if cmdlineMatchesCompanionBackend(readProcCmdline(pid), backend) {
		return true
	}
	if backend.Label == "php-fpm" && strings.HasPrefix(strings.ToLower(strings.TrimSpace(comm)), "pool ") {
		return true
	}
	return false
}

func findCompanionBackendPIDs(backend companionBackend) []int {
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
		if matchesCompanionProcess(pid, backend) {
			pids = append(pids, pid)
		}
	}
	return pids
}

func findCompanionBackendRootPIDs(backend companionBackend) []int {
	all := findCompanionBackendPIDs(backend)
	return companionBackendRootPIDs(all)
}

func companionBackendRootPIDs(all []int) []int {
	if len(all) == 0 {
		return nil
	}
	inTree := map[int]bool{}
	for _, pid := range all {
		inTree[pid] = true
	}
	ppidMap := buildPPIDMap()
	var roots []int
	for _, pid := range all {
		ppid := ppidMap[pid]
		if !inTree[ppid] {
			roots = append(roots, pid)
		}
	}
	return roots
}

func resolveCompanionBackendExe(pid int, comm, exe string, backend companionBackend) string {
	if usableExecutable(exe) && exeMatchesCompanionBackend(exe, backend) {
		return cleanDeletedSuffix(exe)
	}
	binaryName := backend.CommNames[0]
	if resolved := resolveProcessExe(pid, exe, binaryName, nil, backend.CommonPaths); resolved != "" {
		return resolved
	}
	for _, candidate := range backend.CommonPaths {
		if usableExecutable(candidate) {
			return candidate
		}
	}
	if exeMatchesCompanionBackend(exe, backend) {
		return cleanDeletedSuffix(exe)
	}
	if commMatchesAny(comm, backend.CommNames) && exe != "" {
		return cleanDeletedSuffix(exe)
	}
	if cmdlineMatchesCompanionBackend(readProcCmdline(pid), backend) && exe != "" {
		return cleanDeletedSuffix(exe)
	}
	return ""
}

func discoverCompanionBackendExes(backend companionBackend) []string {
	pids := findCompanionBackendPIDs(backend)
	return discoverCompanionBackendExesForPIDs(backend, pids)
}

func discoverCompanionBackendExesForPIDs(backend companionBackend, pids []int) []string {
	if len(pids) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var exes []string
	for _, pid := range pids {
		resolved := resolveCompanionBackendExe(pid, readProcComm(pid), readProcExe(pid), backend)
		if resolved == "" || seen[resolved] {
			continue
		}
		seen[resolved] = true
		exes = append(exes, resolved)
	}
	return exes
}

func (m *processTreeMonitor) companionAlreadyPrimaryListener(backend companionBackend, exe string) bool {
	for _, listener := range m.listeners {
		if isWebGatewayListener(listener) {
			continue
		}
		if listener.MonitorExe != "" && listener.MonitorExe == exe {
			return true
		}
		if commMatchesAny(listener.Process, backend.CommNames) {
			return true
		}
	}
	return false
}

func (m *processTreeMonitor) bootstrapCompanionBackends(gateway listenerInfo) {
	// FastCGI/reverse-proxy backends are not descendants of nginx/apache, but an
	// exploited request can execute inside them. Associate their roots and
	// executables with the gateway so evidence retains listener context.
	for _, backend := range webGatewayCompanionBackends {
		pids := findCompanionBackendPIDs(backend)
		if len(pids) == 0 {
			continue
		}
		exes := discoverCompanionBackendExesForPIDs(backend, pids)
		if len(exes) > 0 && m.companionAlreadyPrimaryListener(backend, exes[0]) {
			continue
		}
		logKey := backend.Label
		m.mu.Lock()
		alreadyLogged := m.companionLogged[logKey]
		if !alreadyLogged {
			m.companionLogged[logKey] = true
		}
		m.mu.Unlock()
		if !alreadyLogged {
			exe := ""
			if len(exes) > 0 {
				exe = exes[0]
			} else if len(pids) > 0 {
				exe = cleanDeletedSuffix(readProcExe(pids[0]))
			}
			roots := companionBackendRootPIDs(pids)
			mode := "pid-tree"
			if backend.PathMonitor {
				mode = "exe-path"
			}
			fmt.Fprintf(os.Stderr, "companion backend (%s): %s exe=%s pids=%d roots=%v gateway=%s port=%d address=%s\n", mode, backend.Label, exe, len(pids), roots, gateway.Process, gateway.Port, gateway.Address)
		}
		if backend.PathMonitor {
			for _, exe := range exes {
				if err := m.addCompanionPathRules(exe, gateway, backend.Label); err != nil {
					fmt.Fprintf(os.Stderr, "companion exe-path rules failed: backend=%s exe=%s err=%v\n", backend.Label, exe, err)
				}
			}
			// PHP 命令（system/exec 等）在 pool worker 内 fork 出 /bin/sh，仅靠 -F exe=php-fpm 捕不到；
			// 需对每个 master/worker 下发 pid/ppid exec + clone 规则。
			trackTarget := companionTrackingTarget(gateway)
			for _, pid := range pids {
				m.registerCompanionPID(pid, trackTarget)
				if err := m.expandPID(pid, trackTarget.Gateway); err != nil {
					fmt.Fprintf(os.Stderr, "companion worker expand failed: backend=%s pid=%d gateway=%s port=%d err=%v\n", backend.Label, pid, gateway.Process, gateway.Port, err)
				}
			}
			continue
		}
		trackTarget := companionTrackingTarget(gateway)
		for _, pid := range pids {
			m.registerCompanionPID(pid, trackTarget)
			if err := m.expandPID(pid, trackTarget.Gateway); err != nil {
				fmt.Fprintf(os.Stderr, "companion expand failed: backend=%s pid=%d gateway=%s port=%d err=%v\n", backend.Label, pid, gateway.Process, gateway.Port, err)
			}
		}
		for _, exe := range exes {
			if err := m.addCompanionPathRules(exe, gateway, backend.Label); err != nil {
				fmt.Fprintf(os.Stderr, "companion exe rules failed: backend=%s exe=%s err=%v\n", backend.Label, exe, err)
			}
		}
	}
}

func companionTrackingTarget(gateway listenerInfo) trackingTarget {
	gw := gateway
	gw.ExeOnly = false
	return trackingTarget{Gateway: gw, ExpandDescendants: true, Source: "companion"}
}

func (m *processTreeMonitor) registerCompanionPID(pid int, target trackingTarget) {
	if pid <= 1 {
		return
	}
	m.mu.Lock()
	m.pidTargets[pid] = target
	m.pidListener[pid] = target.Gateway
	m.mu.Unlock()
}

func (m *processTreeMonitor) companionTargetForProcess(pid, ppid int) (trackingTarget, bool) {
	// Walk exact process ancestry so worker -> shell -> command chains inherit the
	// gateway without globally attributing every instance of a runtime binary.
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.processBackend == processTreeBackendAudit {
		if target, ok := m.pidTargets[pid]; ok {
			return target, true
		}
		if target, ok := m.pidTargets[ppid]; ok {
			return target, true
		}
		return trackingTarget{}, false
	}
	seen := map[int]bool{}
	for _, start := range []int{pid, ppid} {
		if start <= 1 || seen[start] {
			continue
		}
		for p := start; p > 1; p = readProcPPID(p) {
			if seen[p] {
				break
			}
			seen[p] = true
			if target, ok := m.pidTargets[p]; ok {
				return target, true
			}
		}
	}
	return trackingTarget{}, false
}

func (m *processTreeMonitor) preferredWebGatewayLocked() (listenerInfo, bool) {
	var fallback listenerInfo
	for _, listener := range m.listeners {
		if !isWebGatewayListener(listener) {
			continue
		}
		if listener.Address == "0.0.0.0" {
			return listener, true
		}
		if fallback.Process == "" {
			fallback = listener
		}
	}
	if fallback.Process != "" {
		return fallback, true
	}
	return listenerInfo{}, false
}

func (m *processTreeMonitor) preferredWebGateway() (listenerInfo, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.preferredWebGatewayLocked()
}

func (m *processTreeMonitor) gatewayForProcessChainLocked(pid, ppid int) (listenerInfo, bool) {
	if pid <= 1 && ppid <= 1 {
		return listenerInfo{}, false
	}
	if listener, ok := m.pidListener[pid]; ok {
		return listener, true
	}
	if listener, ok := m.pidListener[ppid]; ok {
		return listener, true
	}
	seen := map[int]bool{}
	for _, start := range []int{pid, ppid} {
		if start <= 1 || seen[start] {
			continue
		}
		for p := start; p > 1; p = readProcPPID(p) {
			if seen[p] {
				break
			}
			seen[p] = true
			if listener, ok := m.pidListener[p]; ok {
				return listener, true
			}
			for _, backend := range webGatewayCompanionBackends {
				if matchesCompanionProcess(p, backend) {
					if gw, ok := m.preferredWebGatewayLocked(); ok {
						return gw, true
					}
				}
			}
			for _, root := range m.listeners {
				if root.ExeOnly {
					continue
				}
				if root.PID > 1 && root.PID == p {
					return root, true
				}
			}
		}
	}
	return listenerInfo{}, false
}

func (m *processTreeMonitor) addCompanionPathRules(exe string, gateway listenerInfo, processName string) error {
	exe = cleanDeletedSuffix(exe)
	if exe == "" {
		return nil
	}
	m.mu.Lock()
	m.exeTargets[exe] = trackingTarget{Gateway: gateway, ExpandDescendants: false, Source: "companion-exe"}
	if m.exeMonitored[exe] {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	aux := gateway
	aux.MonitorExe = exe
	aux.Process = processName
	aux.ExeOnly = true
	return m.addExeRules(aux)
}
