package auditportexecmon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func auditArches() []string {
	// Do not add b32 automatically on a 64-bit host. Each arch doubles every
	// PID/PPID rule group and most current deployments execute only b64 code.
	switch runtime.GOARCH {
	case "386", "arm":
		return []string{"b32"}
	case "amd64":
		return []string{"b64"}
	default:
		return []string{"b64"}
	}
}

func normalizeAuditArches(values []string) []string {
	if len(values) == 0 {
		return auditArches()
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	if len(out) == 0 {
		return auditArches()
	}
	return out
}

func validAuditArch(arch string) bool {
	switch arch {
	case "b64", "b32":
		return true
	default:
		return false
	}
}

func auditCloneSyscalls() []string {
	// auditctl accepts multiple -S values in one rule. Keeping the process
	// creation family grouped avoids four rules per arch and filter field.
	return []string{"clone", "clone3", "fork", "vfork"}
}

func fileAuditSyscalls() []string {
	return []string{"creat", "open", "openat", "mkdir", "mkdirat", "mknod", "mknodat", "link", "linkat", "symlink", "symlinkat", "rename", "renameat", "renameat2", "unlink", "unlinkat", "rmdir"}
}

type auditRule struct {
	Arch     string
	Field    string
	PID      int
	Exe      string
	Key      string
	Syscalls []string
}

// auditWatchRule is an ownership token for a path watch added by this process.
// It is tracked separately because watch syntax and deletion semantics differ
// from syscall rules, but both consume the same max_rules budget.
type auditWatchRule struct {
	Path string
	Perm string
	Key  string
}

func auditSyscallUnsupported(arch, syscallName string) bool {
	_, ok := unsupportedAuditSyscalls.Load(auditSyscallKey(arch, syscallName))
	return ok
}

func markUnsupportedAuditSyscall(arch, syscallName string, err error) bool {
	if !isUnknownAuditSyscallError(err) {
		return false
	}
	key := auditSyscallKey(arch, syscallName)
	_, loaded := unsupportedAuditSyscalls.LoadOrStore(key, true)
	return !loaded
}

func auditSyscallKey(arch, syscallName string) string {
	return arch + ":" + syscallName
}

func isUnknownAuditSyscallError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "syscall name unknown") || strings.Contains(msg, "unknown syscall") || strings.Contains(msg, "invalid syscall")
}

func supportedAuditSyscalls(arch string, syscalls []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(syscalls))
	for _, syscallName := range syscalls {
		syscallName = strings.TrimSpace(syscallName)
		if syscallName == "" || seen[syscallName] || auditSyscallUnsupported(arch, syscallName) {
			continue
		}
		seen[syscallName] = true
		out = append(out, syscallName)
	}
	return out
}

func unknownSyscallsFromError(err error, candidates []string) []string {
	// auditctl error text is not a stable structured API. Restrict matching to
	// the requested syscall set so unrelated words in stderr cannot disable a
	// valid syscall globally.
	if !isUnknownAuditSyscallError(err) {
		return nil
	}
	msg := strings.ToLower(err.Error())
	var fragments []string
	for _, indicator := range []string{"syscall name unknown", "unknown syscall", "invalid syscall"} {
		if idx := strings.LastIndex(msg, indicator); idx >= 0 {
			fragments = append(fragments, msg[idx:])
		}
	}
	if len(fragments) == 0 {
		return nil
	}
	tokens := map[string]bool{}
	for _, fragment := range fragments {
		for _, token := range strings.FieldsFunc(fragment, func(r rune) bool {
			return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_')
		}) {
			if token != "" {
				tokens[token] = true
			}
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, syscallName := range candidates {
		lookup := strings.ToLower(strings.TrimSpace(syscallName))
		if lookup == "" || seen[lookup] || !tokens[lookup] {
			continue
		}
		seen[lookup] = true
		out = append(out, syscallName)
	}
	return out
}

func markUnknownSyscallsFromError(arch string, syscalls []string, err error) bool {
	unknown := unknownSyscallsFromError(err, syscalls)
	for _, syscallName := range unknown {
		if markUnsupportedAuditSyscall(arch, syscallName, err) {
			fmt.Fprintf(os.Stderr, "skip unsupported audit syscall: arch=%s syscall=%s err=%v\n", arch, syscallName, err)
		}
	}
	return len(unknown) > 0
}

func addAuditWatchRules(paths []string, perm, key string) ([]auditWatchRule, error) {
	// Return the successfully added prefix on failure. The caller must record or
	// roll back that prefix; discarding it would leave unmanaged kernel watches.
	added := make([]auditWatchRule, 0, len(paths))
	for _, path := range paths {
		if err := runAuditctl("-w", path, "-p", perm, "-k", key); err != nil {
			return added, fmt.Errorf("add watch rule path=%s perm=%s key=%s: %w", path, perm, key, err)
		}
		added = append(added, auditWatchRule{Path: path, Perm: perm, Key: key})
	}
	return added, nil
}

// addAuditRules installs one logical PID rule group across all requested filter
// fields and arches. The group is atomic from the monitor's perspective: any
// failed member rolls back successful members, and only rollback residuals are
// returned so the caller can retain ownership and retry cleanup.
func addAuditRules(pid int, key string, includePPID bool, syscalls []string, arches []string) ([]auditRule, error) {
	fields := []string{"pid"}
	if includePPID {
		fields = append(fields, "ppid")
	}
	arches = normalizeAuditArches(arches)
	var rules []auditRule
	var failures []string
	for _, field := range fields {
		for _, arch := range arches {
			added, errs := addAuditRuleGroup(auditRule{Arch: arch, Field: field, PID: pid, Key: key, Syscalls: syscalls})
			rules = append(rules, added...)
			failures = append(failures, errs...)
		}
	}
	if len(failures) > 0 || len(rules) == 0 {
		if len(failures) == 0 {
			failures = append(failures, "all requested audit syscalls are unsupported for configured arches")
		}
		residual, rollbackErr := rollbackAuditRules(rules)
		if rollbackErr != nil {
			failures = append(failures, "rollback partial rules: "+rollbackErr.Error())
		}
		return residual, fmt.Errorf("incomplete audit rules for pid=%d key=%s: %s", pid, key, strings.Join(failures, "; "))
	}
	return rules, nil
}

// addAuditRulesByExe provides the same all-or-rollback contract for executable
// filters. Executable coverage is shared by all matching worker processes and
// therefore avoids dynamic per-PID growth where the kernel supports it.
func addAuditRulesByExe(exe, key string, syscalls []string, arches []string) ([]auditRule, error) {
	arches = normalizeAuditArches(arches)
	var rules []auditRule
	var failures []string
	for _, arch := range arches {
		added, errs := addAuditRuleGroup(auditRule{Arch: arch, Field: "exe", Exe: exe, Key: key, Syscalls: syscalls})
		rules = append(rules, added...)
		failures = append(failures, errs...)
	}
	if len(failures) > 0 || len(rules) == 0 {
		if len(failures) == 0 {
			failures = append(failures, "all requested audit syscalls are unsupported for configured arches")
		}
		residual, rollbackErr := rollbackAuditRules(rules)
		if rollbackErr != nil {
			failures = append(failures, "rollback partial rules: "+rollbackErr.Error())
		}
		return residual, fmt.Errorf("incomplete audit rules for exe=%s key=%s: %s", exe, key, strings.Join(failures, "; "))
	}
	return rules, nil
}

// addGlobalAuditRules installs one filter-free syscall rule per configured
// architecture. These rules deliberately trade a wider audit event stream for a
// fixed kernel rule count; listener ownership is enforced before accumulation
// and again before serialization in the userspace reader.
func addGlobalAuditRules(key string, syscalls []string, arches []string) ([]auditRule, error) {
	arches = normalizeAuditArches(arches)
	var rules []auditRule
	var failures []string
	for _, arch := range arches {
		added, errs := addAuditRuleGroup(auditRule{Arch: arch, Key: key, Syscalls: syscalls})
		rules = append(rules, added...)
		failures = append(failures, errs...)
	}
	if len(failures) > 0 || len(rules) == 0 {
		if len(failures) == 0 {
			failures = append(failures, "all requested audit syscalls are unsupported for configured arches")
		}
		residual, rollbackErr := rollbackAuditRules(rules)
		if rollbackErr != nil {
			failures = append(failures, "rollback partial rules: "+rollbackErr.Error())
		}
		return residual, fmt.Errorf("incomplete global audit rules for key=%s: %s", key, strings.Join(failures, "; "))
	}
	return rules, nil
}

// addAuditRuleGroup emits exactly one kernel rule for one arch/filter pair. If
// auditctl identifies an unsupported syscall, the function removes only that
// syscall and retries the grouped rule. It intentionally does not split the
// group into one rule per syscall, which previously multiplied rule count.
func addAuditRuleGroup(rule auditRule) ([]auditRule, []string) {
	rule.Syscalls = supportedAuditSyscalls(rule.Arch, rule.Syscalls)
	if len(rule.Syscalls) == 0 {
		return nil, nil
	}
	if len(rule.Syscalls) == 1 {
		if err := runAuditctl(rule.auditctlArgs("-a")...); err != nil {
			logSkippedAuditRule(rule, err)
			return nil, []string{err.Error()}
		}
		return []auditRule{rule}, nil
	}
	if err := runAuditctl(rule.auditctlArgs("-a")...); err == nil {
		return []auditRule{rule}, nil
	} else if markUnknownSyscallsFromError(rule.Arch, rule.Syscalls, err) {
		retry := rule
		retry.Syscalls = supportedAuditSyscalls(rule.Arch, rule.Syscalls)
		if len(retry.Syscalls) > 0 && len(retry.Syscalls) < len(rule.Syscalls) {
			if retryErr := runAuditctl(retry.auditctlArgs("-a")...); retryErr == nil {
				return []auditRule{retry}, nil
			} else {
				logSkippedAuditRule(retry, retryErr)
				return nil, []string{retryErr.Error()}
			}
		}
		return nil, []string{err.Error()}
	} else {
		logSkippedAuditRule(rule, err)
		return nil, []string{err.Error()}
	}
}

func logSkippedAuditRule(rule auditRule, err error) {
	if len(rule.Syscalls) == 1 && markUnsupportedAuditSyscall(rule.Arch, rule.Syscalls[0], err) {
		fmt.Fprintf(os.Stderr, "skip unsupported audit syscall: arch=%s syscall=%s err=%v\n", rule.Arch, rule.Syscalls[0], err)
		return
	}
	syscallLabel := strings.Join(rule.Syscalls, ",")
	if rule.Field == "exe" {
		fmt.Fprintf(os.Stderr, "skip unsupported audit rule: exe=%s arch=%s syscall=%s key=%s err=%v\n", rule.Exe, rule.Arch, syscallLabel, rule.Key, err)
		return
	}
	if rule.Field == "" {
		fmt.Fprintf(os.Stderr, "skip unsupported global audit rule: arch=%s syscall=%s key=%s err=%v\n", rule.Arch, syscallLabel, rule.Key, err)
		return
	}
	fmt.Fprintf(os.Stderr, "skip unsupported audit rule: pid=%d field=%s arch=%s syscall=%s key=%s err=%v\n", rule.PID, rule.Field, rule.Arch, syscallLabel, rule.Key, err)
}

func deleteAuditRules(rules []auditRule) error {
	_, err := rollbackAuditRules(rules)
	return err
}

// rollbackAuditRules deletes in reverse apply order and returns every rule whose
// deletion failed. Residuals are part of the live ownership ledger: callers must
// keep them in processTreeMonitor.rules so budget accounting and later cleanup
// remain correct.
func rollbackAuditRules(rules []auditRule) ([]auditRule, error) {
	var errs []string
	var residual []auditRule
	for i := len(rules) - 1; i >= 0; i-- {
		if err := runAuditctl(rules[i].auditctlArgs("-d")...); err != nil {
			errs = append(errs, err.Error())
			residual = append(residual, rules[i])
		}
	}
	if len(errs) > 0 {
		return residual, errors.New(strings.Join(errs, "; "))
	}
	return nil, nil
}

// cleanupSessionRules removes all syscall and watch rules owned by the current
// monitor. Kernel state is cleared before the in-memory ledger; on failure the
// ledger remains intact so ExecStopPost or the next startup can retry safely.
func (m *processTreeMonitor) cleanupSessionRules() (int, error) {
	rules := m.rulesSnapshot()
	watches := m.watchRulesSnapshot()
	if len(rules) == 0 && len(watches) == 0 {
		return 0, nil
	}
	keySet := map[string]bool{}
	for _, rule := range rules {
		if rule.Key != "" {
			keySet[rule.Key] = true
		}
	}
	for _, watch := range watches {
		if watch.Key != "" {
			keySet[watch.Key] = true
		}
	}
	keys := make([]string, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return 0, nil
	}
	if err := deleteAuditRulesByKeysFast(keys...); err != nil {
		return 0, err
	}
	m.mu.Lock()
	m.rules = nil
	m.watchRules = nil
	m.mu.Unlock()
	return len(keys), nil
}

// cleanupStaleToolAuditRules runs before bootstrap. Explicit current keys use
// the fast path, then the reserved tb_ namespace catches per-port and historical
// keys left by a crash or an older release.
func cleanupStaleToolAuditRules(keys ...string) (int, error) {
	removed := 0
	if err := deleteAuditRulesByKeysFast(keys...); err != nil {
		fmt.Fprintf(os.Stderr, "fast cleanup by key failed: %v\n", err)
	}
	extra, err := deleteAuditRulesByKeyPrefix(toolAuditRuleKeyPrefix)
	removed += extra
	return removed, err
}

// deleteAuditRulesByKeyPrefix is the compatibility cleanup for keys that cannot
// be enumerated in advance. It reconstructs exact delete commands from the
// kernel's normalized auditctl -l output.
func deleteAuditRulesByKeyPrefix(prefix string) (int, error) {
	out, err := runAuditctlCommand(auditctlTimeout, "-l")
	if err != nil {
		return 0, fmt.Errorf("auditctl -l: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-a ") {
			continue
		}
		key := auditRuleKeyFromListLine(line)
		if key == "" || !strings.HasPrefix(key, prefix) {
			continue
		}
		lines = append(lines, line)
	}
	var errs []string
	removed := 0
	for _, line := range lines {
		args := append([]string{"-d"}, strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "-a")))...)
		if err := runAuditctl(args...); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		removed++
	}
	if len(errs) > 0 {
		return removed, errors.New(strings.Join(errs, "; "))
	}
	return removed, nil
}

// deleteAuditRulesByKeys handles both syscall (-a) and watch (-w) records. It is
// slower than -D -k because it lists and deletes each rule, but works on auditctl
// versions where key deletion is unavailable or incomplete.
func deleteAuditRulesByKeys(keys ...string) (int, error) {
	keySet := map[string]bool{}
	for _, key := range keys {
		keySet[key] = true
	}
	out, err := runAuditctlCommand(auditctlTimeout, "-l")
	if err != nil {
		return 0, fmt.Errorf("auditctl -l: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var errs []string
	removed := 0
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		key := auditRuleKeyFromListLine(line)
		if key == "" || !keySet[key] {
			continue
		}
		var args []string
		switch {
		case strings.HasPrefix(line, "-a "):
			args = append([]string{"-d"}, strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "-a")))...)
		case strings.HasPrefix(line, "-w "):
			path, perm, ok := auditWatchFromListLine(line)
			if !ok {
				continue
			}
			args = []string{"-W", path}
			if perm != "" {
				args = append(args, "-p", perm)
			}
			args = append(args, "-k", key)
		default:
			continue
		}
		if err := runAuditctl(args...); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		removed++
	}
	if len(errs) > 0 {
		return removed, errors.New(strings.Join(errs, "; "))
	}
	return removed, nil
}

func auditWatchFromListLine(line string) (path, perm string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || fields[0] != "-w" {
		return "", "", false
	}
	path = fields[1]
	for i := 2; i+1 < len(fields); i++ {
		if fields[i] == "-p" {
			perm = fields[i+1]
			break
		}
	}
	return path, perm, path != ""
}

func deleteAuditRulesByKeysFast(keys ...string) error {
	// Prefer one kernel operation per key. Any failed key is reconciled through
	// the exact listing path rather than treating an unsupported -D as success.
	var errs []string
	var fallbackKeys []string
	for _, key := range keys {
		if key == "" {
			continue
		}
		out, err := runAuditctlCommand(auditctlTimeout, "-D", "-k", key)
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = err.Error()
			}
			errs = append(errs, fmt.Sprintf("auditctl -D -k %s: %s", key, msg))
			fallbackKeys = append(fallbackKeys, key)
		}
	}
	if len(fallbackKeys) > 0 {
		removed, err := deleteAuditRulesByKeys(fallbackKeys...)
		if err == nil {
			fmt.Fprintf(os.Stderr, "fallback cleanup removed %d audit rules by listing rules\n", removed)
			return nil
		}
		errs = append(errs, fmt.Sprintf("fallback cleanup by auditctl -l failed: %v", err))
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// auditRuleKeyFromListLine accepts the key forms emitted by different auditctl
// versions: "-k key", "-F key=key", and compact "-Fkey=key".
func auditRuleKeyFromListLine(line string) string {
	fields := strings.Fields(line)
	for i, field := range fields {
		if field == "-k" && i+1 < len(fields) {
			return strings.Trim(fields[i+1], `"`)
		}
		if field == "-F" && i+1 < len(fields) {
			if key := auditRuleKeyFromField(fields[i+1]); key != "" {
				return key
			}
			continue
		}
		if key := auditRuleKeyFromField(field); key != "" {
			return key
		}
	}
	return ""
}

func auditRuleKeyFromField(field string) string {
	field = strings.TrimSpace(field)
	for _, prefix := range []string{"key=", "-Fkey="} {
		if strings.HasPrefix(field, prefix) {
			return strings.Trim(strings.TrimPrefix(field, prefix), `"`)
		}
	}
	return ""
}

func (r auditRule) auditctlArgs(action string) []string {
	// Build add and delete arguments from the same value object. Exact symmetry
	// matters because auditctl deletion fails when fields or syscall sets differ.
	args := []string{
		action, "always,exit",
		"-F", "arch=" + r.Arch,
	}
	for _, syscallName := range r.Syscalls {
		args = append(args, "-S", syscallName)
	}
	if r.Field == "exe" {
		args = append(args, "-F", "exe="+r.Exe)
	} else if r.Field != "" {
		args = append(args, "-F", fmt.Sprintf("%s=%d", r.Field, r.PID))
	}
	args = append(args, "-k", r.Key)
	return args
}

func runAuditctl(args ...string) error {
	return runAuditctlWithTimeout(auditctlTimeout, args...)
}

func runAuditctlWithTimeout(timeout time.Duration, args ...string) error {
	out, err := runAuditctlCommand(timeout, args...)
	if err != nil {
		return err
	}
	_ = out
	return nil
}

func runAuditctlOutputWithTimeout(timeout time.Duration, args ...string) ([]byte, error) {
	// A wedged audit subsystem must not hang module shutdown or rule workers.
	// CombinedOutput is preserved in the error because auditctl reports useful
	// compatibility details only on stderr.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "auditctl", args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("auditctl %s timed out after %s", strings.Join(args, " "), timeout)
	}
	if err != nil {
		return out, fmt.Errorf("auditctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
