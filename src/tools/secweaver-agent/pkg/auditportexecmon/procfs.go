package auditportexecmon

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const procCacheTTL = 500 * time.Millisecond

const (
	// Listener fallback is intentionally bounded and paced. netstat is the
	// primary source, so spending unbounded CPU on unusual FD-heavy hosts would
	// be a worse failure mode than repairing a missing listener next round.
	listenerProcScanFDBudget   = 32768
	listenerProcScanBatchSize  = 128
	listenerProcScanBatchPause = time.Millisecond
)

// P0 Optimization: Shorter TTL for startTime cache since it's read frequently
// and process identity verification requires freshness
const procStartTimeCacheTTL = 100 * time.Millisecond

type intMapCacheEntry struct {
	Value     map[int]int
	ExpiresAt time.Time
}

type pidListCacheEntry struct {
	Value     []int
	ExpiresAt time.Time
}

type uint64MapCacheEntry struct {
	Value     map[int]uint64
	ExpiresAt time.Time
}

var (
	// Clone bursts repeatedly ask the same /proc questions. A short TTL collapses
	// duplicate scans while staying far below the reconciliation interval.
	procCacheMu     sync.Mutex
	ppidMapCache    intMapCacheEntry
	pidsByExeCache  = map[string]pidListCacheEntry{}
	pidsByCommCache = map[string]pidListCacheEntry{}

	// P0 Optimization: Cache for readProcStartTime to reduce /proc reads
	// This cache significantly reduces syscall overhead in PID verification
	startTimeCache uint64MapCacheEntry
)

func findRootPIDsByComm(names []string) []int {
	all := findPIDsByComm(names)
	nameSet := map[int]bool{}
	for _, pid := range all {
		nameSet[pid] = true
	}
	var roots []int
	for _, pid := range all {
		ppid := readProcPPID(pid)
		if !nameSet[ppid] {
			roots = append(roots, pid)
		}
	}
	return roots
}

func findPIDsByComm(names []string) []int {
	key := commNamesCacheKey(names)
	now := time.Now()
	procCacheMu.Lock()
	if entry, ok := pidsByCommCache[key]; ok && now.Before(entry.ExpiresAt) {
		out := cloneIntSlice(entry.Value)
		procCacheMu.Unlock()
		return out
	}
	procCacheMu.Unlock()

	pids := findPIDsByCommUncached(names)
	procCacheMu.Lock()
	pidsByCommCache[key] = pidListCacheEntry{Value: cloneIntSlice(pids), ExpiresAt: time.Now().Add(procCacheTTL)}
	procCacheMu.Unlock()
	return pids
}

func findPIDsByCommUncached(names []string) []int {
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
		if commMatchesAny(readProcComm(pid), names) {
			pids = append(pids, pid)
		}
	}
	return pids
}

func isJavaListener(comm, exe string) bool {
	base := filepath.Base(cleanDeletedSuffix(exe))
	return comm == "java" || base == "java"
}

func resolveJavaExe(pid int, procExe string) string {
	return resolveProcessExe(pid, procExe, "java", []string{"JAVA_HOME", "JRE_HOME"}, []string{"/usr/bin/java", "/usr/local/bin/java", "/bin/java"})
}

func resolveProcessExe(pid int, procExe, binaryName string, homeEnvKeys []string, commonPaths []string) string {
	if usableExecutable(procExe) {
		return cleanDeletedSuffix(procExe)
	}
	candidates := processExeCandidates(pid, procExe, binaryName, homeEnvKeys, commonPaths)
	seen := map[string]bool{}
	for _, candidate := range candidates {
		candidate = cleanDeletedSuffix(candidate)
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		if usableExecutable(candidate) {
			return candidate
		}
	}
	return ""
}

func processExeCandidates(pid int, procExe, binaryName string, homeEnvKeys []string, commonPaths []string) []string {
	return buildProcessExeCandidates(procExe, binaryName, readProcCmdline(pid), readProcEnviron(pid), homeEnvKeys, commonPaths)
}

func buildProcessExeCandidates(procExe, binaryName string, cmdline []string, env map[string]string, homeEnvKeys []string, commonPaths []string) []string {
	var out []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path != "" {
			out = append(out, path)
		}
	}
	add(procExe)
	for _, arg := range cmdline {
		if strings.Contains(arg, "/") && filepath.Base(cleanDeletedSuffix(arg)) == binaryName {
			add(arg)
		}
	}
	for _, key := range homeEnvKeys {
		if value := env[key]; value != "" {
			add(filepath.Join(value, "bin", binaryName))
		}
	}
	if pathValue := env["PATH"]; pathValue != "" {
		for _, dir := range strings.Split(pathValue, ":") {
			add(filepath.Join(dir, binaryName))
		}
	}
	if procExe != "" {
		base := filepath.Dir(cleanDeletedSuffix(procExe))
		add(filepath.Join(base, binaryName))
		add(filepath.Join(filepath.Dir(base), "bin", binaryName))
	}
	for _, path := range commonPaths {
		add(path)
	}
	return out
}

func cleanDeletedSuffix(path string) string {
	return strings.TrimSpace(strings.TrimSuffix(path, " (deleted)"))
}

func usableExecutable(path string) bool {
	path = cleanDeletedSuffix(path)
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0111 != 0
}

func readProcCmdline(pid int) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return nil
	}
	parts := bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) > 0 {
			out = append(out, string(part))
		}
	}
	return out
}

func readProcEnviron(pid int) map[string]string {
	result := map[string]string{}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil || len(data) == 0 {
		return result
	}
	for _, part := range bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0}) {
		if len(part) == 0 {
			continue
		}
		key, value, ok := strings.Cut(string(part), "=")
		if ok && key != "" {
			result[key] = value
		}
	}
	return result
}

func isDescendantOf(ancestor, pid int) bool {
	if ancestor <= 1 || pid <= 1 {
		return false
	}
	if pid == ancestor {
		return true
	}
	for p := readProcPPID(pid); p > 1; p = readProcPPID(p) {
		if p == ancestor {
			return true
		}
	}
	return false
}

func splitHostPortLoose(s string) (string, int, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		idx := strings.LastIndex(s, "]:")
		if idx < 0 {
			return "", 0, false
		}
		host := strings.TrimPrefix(s[:idx+1], "[")
		host = strings.TrimSuffix(host, "]")
		port, err := strconv.Atoi(s[idx+2:])
		return host, port, err == nil
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", 0, false
	}
	host := s[:idx]
	p, err := strconv.Atoi(s[idx+1:])
	if err != nil {
		return "", 0, false
	}
	return host, p, true
}

func isLoopback(host string) bool {
	host = strings.Trim(host, "[]")
	if host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type socketInodeScanStats struct {
	FDsScanned      int
	FDBudget        int
	BudgetExhausted bool
}

func buildSocketInodeMapWithStats() (map[string]int, socketInodeScanStats) {
	return scanSocketInodeMap("/proc", listenerProcScanFDBudget)
}

// scanSocketInodeMap joins /proc/net socket inodes to process owners while
// bounding both work per reconciliation and scheduler occupancy. Opening FD
// directories in batches avoids materializing a large directory in memory.
func scanSocketInodeMap(procRoot string, fdBudget int) (map[string]int, socketInodeScanStats) {
	result := map[string]int{}
	if fdBudget <= 0 {
		fdBudget = listenerProcScanFDBudget
	}
	stats := socketInodeScanStats{FDBudget: fdBudget}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return result, stats
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		fdDir := filepath.Join(procRoot, entry.Name(), "fd")
		dir, err := os.Open(fdDir)
		if err != nil {
			continue
		}
		for {
			remaining := fdBudget - stats.FDsScanned
			if remaining <= 0 {
				stats.BudgetExhausted = true
				_ = dir.Close()
				return result, stats
			}
			batchSize := listenerProcScanBatchSize
			if remaining < batchSize {
				batchSize = remaining
			}
			names, readErr := dir.Readdirnames(batchSize)
			for _, name := range names {
				stats.FDsScanned++
				target, linkErr := os.Readlink(filepath.Join(fdDir, name))
				if linkErr != nil || !strings.HasPrefix(target, "socket:[") {
					continue
				}
				inode := normalizeInode(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"))
				if _, exists := result[inode]; !exists {
					result[inode] = pid
				}
			}
			if readErr != nil {
				// EOF and process-exit races both finish this best-effort FD directory.
				break
			}
			if len(names) == batchSize {
				// A short pause bounds burst CPU without materially delaying the rare
				// fallback path. The normal netstat path never pays this cost.
				time.Sleep(listenerProcScanBatchPause)
			}
		}
		_ = dir.Close()
	}
	return result, stats
}

func lookupPIDByInode(inode string, cache map[string]int) int {
	inode = normalizeInode(inode)
	if pid, ok := cache[inode]; ok && pid > 1 {
		return pid
	}
	// The caller already performed one bounded owner scan. Re-scanning all FDs
	// for every cache miss turns N unresolved sockets into N full /proc walks.
	return 0
}

func normalizeInode(inode string) string {
	inode = strings.TrimSpace(inode)
	if inode == "" {
		return inode
	}
	value, err := strconv.ParseUint(inode, 10, 64)
	if err != nil {
		return inode
	}
	return strconv.FormatUint(value, 10)
}

func isProcNetLoopback(addrHex string) bool {
	switch len(addrHex) {
	case 8:
		return strings.EqualFold(addrHex, "0100007F")
	case 32:
		if strings.EqualFold(addrHex, "00000000000000000000000000000001") || strings.EqualFold(addrHex, "00000000000000000000000001000000") {
			return true
		}
		ip := parseProcNetIPv6(addrHex)
		return ip != nil && ip.IsLoopback()
	default:
		return false
	}
}

func parseProcNetIPv6(addrHex string) net.IP {
	if len(addrHex) != 32 {
		return nil
	}
	ip := make(net.IP, 16)
	for word := 0; word < 4; word++ {
		base := word * 8
		for b := 0; b < 4; b++ {
			part := addrHex[base+(3-b)*2 : base+(3-b)*2+2]
			value, err := strconv.ParseUint(part, 16, 8)
			if err != nil {
				return nil
			}
			ip[word*4+b] = byte(value)
		}
	}
	return ip
}

func collectDescendantPIDs(root int, skip func(int) bool) []int {
	// Build one PPID snapshot and traverse in memory. Re-reading every ancestor
	// would turn a full tree scan into O(processes * tree depth) /proc IO.
	if root <= 1 {
		return nil
	}
	if skip != nil && skip(root) {
		return nil
	}
	ppidMap := buildPPIDMap()
	seen := map[int]bool{root: true}
	queue := []int{root}
	var descendants []int
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for pid, ppid := range ppidMap {
			if ppid != parent || seen[pid] {
				continue
			}
			if skip != nil && skip(pid) {
				continue
			}
			seen[pid] = true
			descendants = append(descendants, pid)
			queue = append(queue, pid)
		}
	}
	return descendants
}

func buildPPIDMap() map[int]int {
	now := time.Now()
	procCacheMu.Lock()
	if ppidMapCache.Value != nil && now.Before(ppidMapCache.ExpiresAt) {
		out := cloneIntMap(ppidMapCache.Value)
		procCacheMu.Unlock()
		return out
	}
	procCacheMu.Unlock()

	result := buildPPIDMapUncached()
	procCacheMu.Lock()
	ppidMapCache = intMapCacheEntry{Value: cloneIntMap(result), ExpiresAt: time.Now().Add(procCacheTTL)}
	procCacheMu.Unlock()
	return result
}

func buildPPIDMapUncached() map[int]int {
	result := map[int]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		result[pid] = readProcPPID(pid)
	}
	return result
}

func findPIDsByExe(exe string) []int {
	exe = cleanDeletedSuffix(exe)
	if exe == "" {
		return nil
	}
	now := time.Now()
	procCacheMu.Lock()
	if entry, ok := pidsByExeCache[exe]; ok && now.Before(entry.ExpiresAt) {
		out := cloneIntSlice(entry.Value)
		procCacheMu.Unlock()
		return out
	}
	procCacheMu.Unlock()

	pids := findPIDsByExeUncached(exe)
	procCacheMu.Lock()
	pidsByExeCache[exe] = pidListCacheEntry{Value: cloneIntSlice(pids), ExpiresAt: time.Now().Add(procCacheTTL)}
	procCacheMu.Unlock()
	return pids
}

func findPIDsByExeUncached(exe string) []int {
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
		target, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil || cleanDeletedSuffix(target) != exe {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}

func commNamesCacheKey(names []string) string {
	parts := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, "\x00")
}

func cloneIntSlice(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	out := make([]int, len(values))
	copy(out, values)
	return out
}

func cloneIntMap(values map[int]int) map[int]int {
	if len(values) == 0 {
		return map[int]int{}
	}
	out := make(map[int]int, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func readProcPPID(pid int) int {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	return parseProcStatPPID(string(stat))
}

func readProcStartTime(pid int) uint64 {
	// P0 Optimization: Check cache first to avoid repeated /proc reads
	// stat field 22 is monotonic since boot and identifies a process lifetime;
	// unlike PID it cannot be reused until reboot. Zero means unverified.
	//
	// This function is called multiple times during PID verification:
	// - Initial read before lock
	// - Verification after lock acquisition
	// - Final verification after pressure check
	// Without caching, this causes 3x /proc reads per PID expansion.

	now := time.Now()
	procCacheMu.Lock()
	if startTimeCache.Value != nil && now.Before(startTimeCache.ExpiresAt) {
		if cached, ok := startTimeCache.Value[pid]; ok {
			procCacheMu.Unlock()
			return cached
		}
	}
	procCacheMu.Unlock()

	// Cache miss - read from /proc
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	startTime := parseProcStatStartTime(string(stat))

	// Update cache
	procCacheMu.Lock()
	if startTimeCache.Value == nil || now.After(startTimeCache.ExpiresAt) {
		// Initialize or refresh cache
		startTimeCache.Value = make(map[int]uint64, 256)
		startTimeCache.ExpiresAt = now.Add(procStartTimeCacheTTL)
	}
	startTimeCache.Value[pid] = startTime
	procCacheMu.Unlock()

	return startTime
}

func parseProcStatStartTime(stat string) uint64 {
	// comm is parenthesized and may itself contain spaces or ')'. Locate the last
	// closing parenthesis before indexing fields.
	end := strings.LastIndex(stat, ")")
	if end < 0 || end+2 >= len(stat) {
		return 0
	}
	fields := strings.Fields(strings.TrimSpace(stat[end+1:]))
	// The first field after comm is field 3 (state); starttime is field 22.
	if len(fields) <= 19 {
		return 0
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0
	}
	return startTime
}

func parseProcStatPPID(stat string) int {
	end := strings.LastIndex(stat, ")")
	if end < 0 || end+2 >= len(stat) {
		return 0
	}
	rest := strings.TrimSpace(stat[end+1:])
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return ppid
}

func readProcComm(pid int) string {
	if pid <= 0 {
		return ""
	}
	if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		name := strings.TrimSpace(string(comm))
		if name != "" && !invalidComm(name) {
			return name
		}
	}
	if target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		return filepath.Base(target)
	}
	return ""
}

func readProcExe(pid int) string {
	if pid <= 1 {
		return ""
	}
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return target
}
