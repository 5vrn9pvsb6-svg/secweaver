package output

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const DefaultBufferSize = 64 * 1024
const DefaultFlushInterval = 5 * time.Second
const DefaultMaxSizeBytes int64 = 100 * 1024 * 1024
const DefaultMaxBackups = 5

// DefaultFilePerm restricts Agent-owned logs to their service account. The
// output layer rejects broader caller-supplied modes so new modules cannot
// accidentally expose security telemetry through group or world permissions.
const DefaultFilePerm os.FileMode = 0600
const EnterpriseIDEnv = "SECWEAVER_ENTERPRISE_ID"
const HostNameEnv = "SECWEAVER_HOST_NAME"
const HostIPEnv = "SECWEAVER_HOST_IP"

var enterpriseIDPattern = regexp.MustCompile(`^[A-Z0-9]{16}$`)

type AppendOptions struct {
	Path          string
	Fallback      io.Writer
	Perm          os.FileMode
	BufferSize    int
	FlushInterval time.Duration
	MaxSizeBytes  int64
	MaxBackups    int
}

type PeriodicFlushWriter struct {
	mu   sync.Mutex
	buf  *bufio.Writer
	dest io.Writer
	stop chan struct{}
	done chan struct{}
	once sync.Once
	err  error
}

type EnterpriseJSONLinesWriter struct {
	mu           sync.Mutex
	destination  io.Writer
	enterpriseID string
	hostName     string
	hostIP       string
	pending      []byte
}

type HostIdentity struct {
	HostName string
	HostIP   string
}

type RotatingFile struct {
	mu           sync.Mutex
	path         string
	perm         os.FileMode
	maxSizeBytes int64
	maxBackups   int
	file         *os.File
	size         int64
	budget       diskBudgetPolicy
	nextCheck    time.Time
	budgetErr    error
}

var availableDiskBytes = diskFreeBytes

func NormalizeEnterpriseID(value string) (string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if !enterpriseIDPattern.MatchString(normalized) {
		return "", fmt.Errorf("must contain exactly 16 ASCII letters or digits")
	}
	return normalized, nil
}

func EnterpriseIDFromEnv() (string, error) {
	value, err := NormalizeEnterpriseID(os.Getenv(EnterpriseIDEnv))
	if err != nil {
		return "", fmt.Errorf("%s is required and invalid: %w", EnterpriseIDEnv, err)
	}
	return value, nil
}

func HostIdentityFromEnv() (HostIdentity, error) {
	hostName := strings.TrimSpace(os.Getenv(HostNameEnv))
	if hostName == "" {
		value, err := os.Hostname()
		if err != nil {
			return HostIdentity{}, fmt.Errorf("detect host_name: %w", err)
		}
		hostName = strings.TrimSpace(value)
	}
	if hostName == "" || strings.ContainsAny(hostName, "\x00\r\n") {
		return HostIdentity{}, fmt.Errorf("host_name is required and must not contain control characters")
	}

	hostIP := strings.TrimSpace(os.Getenv(HostIPEnv))
	if hostIP == "" {
		var err error
		hostIP, err = DetectPrimaryHostIP()
		if err != nil {
			return HostIdentity{}, err
		}
	}
	normalizedIP, err := normalizeHostIP(hostIP)
	if err != nil {
		return HostIdentity{}, fmt.Errorf("%s is invalid: %w", HostIPEnv, err)
	}
	return HostIdentity{HostName: hostName, HostIP: normalizedIP}, nil
}

func DetectPrimaryHostIP() (string, error) {
	if ip := preferredRouteHostIP(); ip != "" {
		return ip, nil
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("detect host_ip interfaces: %w", err)
	}
	bestIP, bestName, bestScore := "", "", -1
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || !usableHostIP(ip) {
				continue
			}
			score := hostIPScore(iface.Name, ip)
			value := normalizedIPString(ip)
			if score > bestScore || (score == bestScore && (bestName == "" || iface.Name < bestName)) {
				bestIP, bestName, bestScore = value, iface.Name, score
			}
		}
	}
	if bestIP == "" {
		return "", fmt.Errorf("host_ip auto-detection found no active non-loopback address; set %s explicitly", HostIPEnv)
	}
	return bestIP, nil
}

func preferredRouteHostIP() string {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9})
	if err != nil {
		return ""
	}
	defer conn.Close()
	address, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || !usableHostIP(address.IP) {
		return ""
	}
	return normalizedIPString(address.IP)
}

func hostIPScore(interfaceName string, ip net.IP) int {
	score := 0
	if ip.To4() != nil {
		score += 100
	}
	if ip.IsPrivate() {
		score += 20
	}
	name := strings.ToLower(interfaceName)
	for _, prefix := range []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "tun", "tap", "wg", "tailscale"} {
		if strings.HasPrefix(name, prefix) {
			return score - 50
		}
	}
	return score + 10
}

func normalizeHostIP(value string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if !usableHostIP(ip) {
		return "", fmt.Errorf("must be a non-loopback unicast IP address")
	}
	return normalizedIPString(ip), nil
}

func usableHostIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func normalizedIPString(ip net.IP) string {
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.String()
	}
	return ip.String()
}

func NewEnterpriseJSONLinesWriter(destination io.Writer, enterpriseID string) (*EnterpriseJSONLinesWriter, error) {
	if destination == nil {
		return nil, fmt.Errorf("event output destination is required")
	}
	normalized, err := NormalizeEnterpriseID(enterpriseID)
	if err != nil {
		return nil, fmt.Errorf("enterprise_id: %w", err)
	}
	identity, err := HostIdentityFromEnv()
	if err != nil {
		return nil, err
	}
	return &EnterpriseJSONLinesWriter{
		destination: destination, enterpriseID: normalized,
		hostName: identity.HostName, hostIP: identity.HostIP,
	}, nil
}

func (w *EnterpriseJSONLinesWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = append(w.pending, p...)
	for {
		lineEnd := bytes.IndexByte(w.pending, '\n')
		if lineEnd < 0 {
			break
		}
		line := append([]byte(nil), w.pending[:lineEnd]...)
		w.pending = w.pending[lineEnd+1:]
		if err := w.writeRecord(line); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (w *EnterpriseJSONLinesWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(bytes.TrimSpace(w.pending)) > 0 {
		line := append([]byte(nil), w.pending...)
		w.pending = nil
		if err := w.writeRecord(line); err != nil {
			return err
		}
	}
	if flusher, ok := w.destination.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

func (w *EnterpriseJSONLinesWriter) writeRecord(line []byte) error {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(line, &record); err != nil {
		return fmt.Errorf("event output must be a JSON object: %w", err)
	}
	if record == nil {
		return fmt.Errorf("event output must be a JSON object")
	}
	enterpriseID, _ := json.Marshal(w.enterpriseID)
	record["enterprise_id"] = enterpriseID
	setRequiredString(record, "host_name", w.hostName)
	setRequiredString(record, "host_ip", w.hostIP)
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode event output: %w", err)
	}
	encoded = append(encoded, '\n')
	for len(encoded) > 0 {
		n, writeErr := w.destination.Write(encoded)
		if writeErr != nil {
			return writeErr
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		encoded = encoded[n:]
	}
	return nil
}

func setRequiredString(record map[string]json.RawMessage, key, fallback string) {
	if raw, ok := record[key]; ok {
		var value string
		if json.Unmarshal(raw, &value) == nil && strings.TrimSpace(value) != "" {
			return
		}
	}
	encoded, _ := json.Marshal(fallback)
	record[key] = encoded
}

func NewPeriodicFlushWriter(w io.Writer, bufferSize int, interval time.Duration) *PeriodicFlushWriter {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	p := &PeriodicFlushWriter{buf: bufio.NewWriterSize(w, bufferSize), dest: w}
	if interval > 0 {
		p.stop = make(chan struct{})
		p.done = make(chan struct{})
		go p.flushLoop(interval)
	}
	return p
}

func (w *PeriodicFlushWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	if err := w.buf.Flush(); err != nil {
		w.err = err
		return err
	}
	if syncer, ok := w.dest.(interface{ Sync() error }); ok {
		if err := syncer.Sync(); err != nil {
			w.err = err
			return err
		}
	}
	return nil
}

func (w *PeriodicFlushWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	return w.buf.Write(p)
}

func (w *PeriodicFlushWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	if err := w.buf.Flush(); err != nil {
		w.err = err
		return err
	}
	return nil
}

func (w *PeriodicFlushWriter) Close() error {
	if w.stop != nil {
		w.once.Do(func() {
			close(w.stop)
			<-w.done
		})
	}
	return w.Flush()
}

func (w *PeriodicFlushWriter) flushLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer func() {
		ticker.Stop()
		close(w.done)
	}()
	for {
		select {
		case <-ticker.C:
			_ = w.Flush()
		case <-w.stop:
			return
		}
	}
}

// OpenRotatingFile opens an Agent-owned log and enforces its requested mode on
// both the active file and retained backups. Applying the mode to existing
// files is intentional: upgrades must repair logs created by older releases
// with broader permissions instead of preserving an unsafe historical mode.
func OpenRotatingFile(path string, perm os.FileMode, maxSizeBytes int64, maxBackups int) (*RotatingFile, error) {
	if perm == 0 {
		perm = DefaultFilePerm
	}
	if perm.Perm() != DefaultFilePerm {
		return nil, fmt.Errorf("agent log permission must be %04o, got %04o", DefaultFilePerm, perm.Perm())
	}
	if maxSizeBytes == 0 {
		maxSizeBytes = DefaultMaxSizeBytes
	}
	if maxBackups == 0 {
		maxBackups = DefaultMaxBackups
	}
	budget, err := diskBudgetPolicyFromEnv()
	if err != nil {
		return nil, err
	}
	if budget.enabled {
		maxSizeBytes, maxBackups = retentionWithinBudget(maxSizeBytes, maxBackups, budget.perFileBytes)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, perm)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(perm); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("enforce active log permissions: %w", err)
	}
	if err := enforceBackupPermissions(path, perm, maxBackups); err != nil {
		_ = file.Close()
		return nil, err
	}
	if budget.enabled {
		if err := enforceRetentionBudget(path, maxBackups, budget.perFileBytes); err != nil {
			_ = file.Close()
			return nil, err
		}
	}
	size := int64(0)
	if info, err := file.Stat(); err == nil {
		size = info.Size()
	}
	return &RotatingFile{
		path:         path,
		perm:         perm,
		maxSizeBytes: maxSizeBytes,
		maxBackups:   maxBackups,
		file:         file,
		size:         size,
		budget:       budget,
	}, nil
}

func (f *RotatingFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return 0, os.ErrClosed
	}
	if err := f.checkDiskBudgetLocked(false); err != nil {
		return 0, err
	}
	if f.shouldRotate(len(p)) {
		if err := f.checkDiskBudgetLocked(true); err != nil {
			return 0, err
		}
		if err := f.rotateLocked(); err != nil {
			return 0, err
		}
	}
	n, err := f.file.Write(p)
	f.size += int64(n)
	return n, err
}

// checkDiskBudgetLocked protects the host reserve without statfs on every
// record. On pressure it removes only this output's numeric backups, then
// rechecks before refusing the write with an observable module error.
func (f *RotatingFile) checkDiskBudgetLocked(force bool) error {
	if !f.budget.enabled {
		return nil
	}
	now := time.Now()
	if !force && now.Before(f.nextCheck) {
		return f.budgetErr
	}
	f.nextCheck = now.Add(f.budget.checkInterval)
	available, err := availableDiskBytes(filepath.Dir(f.path))
	if err != nil {
		f.budgetErr = fmt.Errorf("check output disk reserve: %w", err)
		return f.budgetErr
	}
	required := f.budget.requiredFreeBytes()
	if available >= required {
		f.budgetErr = nil
		return nil
	}
	for index := f.maxBackups; index >= 1 && available < required; index-- {
		backup := fmt.Sprintf("%s.%d", f.path, index)
		if removeErr := os.Remove(backup); removeErr != nil && !os.IsNotExist(removeErr) {
			f.budgetErr = fmt.Errorf("remove output backup under disk pressure %s: %w", backup, removeErr)
			return f.budgetErr
		}
		available, err = availableDiskBytes(filepath.Dir(f.path))
		if err != nil {
			f.budgetErr = fmt.Errorf("recheck output disk reserve: %w", err)
			return f.budgetErr
		}
	}
	if available < required {
		// Retry quickly after a refusal so collection resumes promptly when an
		// external shipper or operator frees space.
		f.nextCheck = now.Add(time.Second)
		f.budgetErr = fmt.Errorf("output disk reserve exhausted: available=%d required=%d priority=%s", available, required, f.budget.priority)
		return f.budgetErr
	}
	f.budgetErr = nil
	return nil
}

func (f *RotatingFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return nil
	}
	err := f.file.Close()
	f.file = nil
	return err
}

func (f *RotatingFile) Sync() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return os.ErrClosed
	}
	return f.file.Sync()
}

func (f *RotatingFile) shouldRotate(writeLen int) bool {
	return f.maxSizeBytes > 0 && f.size > 0 && f.size+int64(writeLen) > f.maxSizeBytes
}

func (f *RotatingFile) rotateLocked() error {
	if err := f.file.Close(); err != nil {
		return err
	}
	f.file = nil
	if f.maxBackups > 0 {
		last := fmt.Sprintf("%s.%d", f.path, f.maxBackups)
		if err := os.Remove(last); err != nil && !os.IsNotExist(err) {
			return err
		}
		for i := f.maxBackups - 1; i >= 1; i-- {
			src := fmt.Sprintf("%s.%d", f.path, i)
			dst := fmt.Sprintf("%s.%d", f.path, i+1)
			if err := renameIfExists(src, dst); err != nil {
				return err
			}
		}
		if err := renameIfExists(f.path, f.path+".1"); err != nil {
			return err
		}
	} else if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(f.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, f.perm)
	if err != nil {
		return err
	}
	if err := file.Chmod(f.perm); err != nil {
		_ = file.Close()
		return fmt.Errorf("enforce rotated log permissions: %w", err)
	}
	f.file = file
	f.size = 0
	if f.budget.enabled {
		if err := enforceRetentionBudget(f.path, f.maxBackups, f.budget.perFileBytes); err != nil {
			_ = f.file.Close()
			f.file = nil
			return err
		}
	}
	return nil
}

// enforceRetentionBudget removes oldest numeric backups until existing files
// fit the assigned share. The active file is never truncated; if it alone is
// oversized, the next write rotates it and this function can then remove it as
// the oldest retained backup.
func enforceRetentionBudget(path string, maxBackups int, budget int64) error {
	if budget <= 0 {
		return nil
	}
	total := int64(0)
	if info, err := os.Stat(path); err == nil {
		total += info.Size()
	} else if !os.IsNotExist(err) {
		return err
	}
	sizes := make(map[int]int64, maxBackups)
	matches, err := filepath.Glob(path + ".*")
	if err != nil {
		return err
	}
	for _, backup := range matches {
		index, err := strconv.Atoi(strings.TrimPrefix(backup, path+"."))
		if err != nil || index < 1 {
			continue
		}
		info, err := os.Lstat(backup)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("backup log %s is not a regular file", backup)
		}
		if index > maxBackups {
			if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		sizes[index] = info.Size()
		total += info.Size()
	}
	for index := maxBackups; index >= 1 && total > budget; index-- {
		size, exists := sizes[index]
		if !exists {
			continue
		}
		backup := fmt.Sprintf("%s.%d", path, index)
		if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
			return err
		}
		total -= size
	}
	return nil
}

// enforceBackupPermissions repairs numeric backups retained by RotatingFile.
// Missing backups are normal; any other chmod/stat failure is returned because
// continuing would leave historical security telemetry more widely readable.
func enforceBackupPermissions(path string, perm os.FileMode, maxBackups int) error {
	for index := 1; index <= maxBackups; index++ {
		backup := fmt.Sprintf("%s.%d", path, index)
		info, err := os.Lstat(backup)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("inspect backup log permissions for %s: %w", backup, err)
		}
		// Refuse symlinks and special files so permission repair never follows an
		// attacker-controlled backup path outside the Agent log directory.
		if !info.Mode().IsRegular() {
			return fmt.Errorf("backup log %s is not a regular file", backup)
		}
		if err := os.Chmod(backup, perm); err != nil {
			return fmt.Errorf("enforce backup log permissions for %s: %w", backup, err)
		}
	}
	return nil
}

func renameIfExists(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(src, dst)
}

// OpenAppend creates a buffered rotating log writer. File-backed outputs are
// always private and opening an existing log repairs permissions on the active
// file and retained numeric backups before any new event is accepted.
func OpenAppend(opts AppendOptions) (io.Writer, func(), error) {
	if opts.Path == "" || opts.Path == "-" {
		if opts.Fallback == nil {
			opts.Fallback = io.Discard
		}
		return opts.Fallback, func() {}, nil
	}
	if opts.Perm == 0 {
		opts.Perm = DefaultFilePerm
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultBufferSize
	}
	if opts.FlushInterval == 0 {
		opts.FlushInterval = DefaultFlushInterval
	}
	file, err := OpenRotatingFile(opts.Path, opts.Perm, opts.MaxSizeBytes, opts.MaxBackups)
	if err != nil {
		return nil, nil, err
	}
	writer := NewPeriodicFlushWriter(file, opts.BufferSize, opts.FlushInterval)
	cleanup := func() {
		_ = writer.Close()
		_ = file.Close()
	}
	return writer, cleanup, nil
}

// OpenEventAppend adds trusted enterprise and host identity to each JSON Lines
// record before it reaches the private rotating output managed by OpenAppend.
func OpenEventAppend(opts AppendOptions) (io.Writer, func(), error) {
	enterpriseID, err := EnterpriseIDFromEnv()
	if err != nil {
		return nil, nil, err
	}
	destination, closeDestination, err := OpenAppend(opts)
	if err != nil {
		return nil, nil, err
	}
	writer, err := NewEnterpriseJSONLinesWriter(destination, enterpriseID)
	if err != nil {
		closeDestination()
		return nil, nil, err
	}
	cleanup := func() {
		_ = writer.Flush()
		closeDestination()
	}
	return writer, cleanup, nil
}

// Checkpoint makes all event bytes durable before a caller advances state or a cursor.
func Checkpoint(w io.Writer) error {
	if syncer, ok := w.(interface{ Sync() error }); ok {
		return syncer.Sync()
	}
	if flusher, ok := w.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

func (w *EnterpriseJSONLinesWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(bytes.TrimSpace(w.pending)) > 0 {
		line := append([]byte(nil), w.pending...)
		w.pending = nil
		if err := w.writeRecord(line); err != nil {
			return err
		}
	}
	if syncer, ok := w.destination.(interface{ Sync() error }); ok {
		return syncer.Sync()
	}
	if flusher, ok := w.destination.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}
