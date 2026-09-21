package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const auditCleanupTimeout = 3 * time.Second

var auditCleanupExactKeys = []string{
	"tb_external_listener_exec",
	"tb_external_listener_connect",
	"tb_external_listener_file",
	"tb_external_listener_sensitive",
	"tb_external_listener_clone",
	"tb_host_persistence",
}

// auditCleanupReport separates fast key deletion attempts from exact fallback
// deletions so uninstallers can report partial cleanup without parsing logs.
type auditCleanupReport struct {
	FastKeysTried int
	FallbackRules int
	Errors        []string
}

// runAuditCleanupCommand implements the machine-callable cleanup subcommand.
// Cleanup is best-effort by default because package removal must still proceed
// on kernels that reject one stale rule; --strict is available to verification
// tooling that requires a non-zero result.
func runAuditCleanupCommand(args []string) int {
	fs := flag.NewFlagSet("audit-cleanup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	quiet := false
	strict := false
	dryRun := false
	fs.BoolVar(&quiet, "quiet", false, "suppress success output")
	fs.BoolVar(&strict, "strict", false, "return non-zero when cleanup reports errors")
	fs.BoolVar(&dryRun, "dry-run", false, "list matching rules without deleting them")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	report := cleanupSecweaverAuditRules(context.Background(), dryRun)
	if !quiet || dryRun || len(report.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "audit cleanup: fast_keys=%d fallback_rules=%d dry_run=%v\n", report.FastKeysTried, report.FallbackRules, dryRun)
		for _, item := range report.Errors {
			fmt.Fprintf(os.Stderr, "audit cleanup warning: %s\n", item)
		}
	}
	if strict && len(report.Errors) > 0 {
		return 1
	}
	return 0
}

// cleanupSecweaverAuditRules first uses auditctl's bulk key deletion, then
// always lists the kernel rules and deletes matching leftovers exactly. The
// second pass covers older auditctl versions and historical per-port keys that
// are not known in advance.
func cleanupSecweaverAuditRules(ctx context.Context, dryRun bool) auditCleanupReport {
	report := auditCleanupReport{}
	if runtime.GOOS != "linux" {
		return report
	}
	if _, err := exec.LookPath("auditctl"); err != nil {
		report.Errors = append(report.Errors, "auditctl not found")
		return report
	}

	if !dryRun {
		for _, key := range auditCleanupExactKeys {
			report.FastKeysTried++
			if out, err := runAuditCleanupCommandWithTimeout(ctx, auditCleanupTimeout, "auditctl", "-D", "-k", key); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("auditctl -D -k %s: %s", key, auditCleanupErrorMessage(out, err)))
			}
		}
	}

	out, err := runAuditCleanupCommandWithTimeout(ctx, auditCleanupTimeout, "auditctl", "-l")
	if err != nil {
		report.Errors = append(report.Errors, "auditctl -l: "+auditCleanupErrorMessage(out, err))
		return report
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !auditCleanupLineMatches(line) {
			continue
		}
		if dryRun {
			report.FallbackRules++
			fmt.Fprintln(os.Stderr, line)
			continue
		}
		if err := deleteAuditCleanupLine(ctx, line); err != nil {
			report.Errors = append(report.Errors, err.Error())
			continue
		}
		report.FallbackRules++
	}
	return report
}

func auditCleanupLineMatches(line string) bool {
	return isSecweaverAuditCleanupKey(auditCleanupKeyFromLine(line))
}

func auditCleanupKeyFromLine(line string) string {
	fields := strings.Fields(line)
	for i, field := range fields {
		if field == "-k" && i+1 < len(fields) {
			return strings.Trim(fields[i+1], `"`)
		}
		if field == "-F" && i+1 < len(fields) {
			if key := auditCleanupKeyFromField(fields[i+1]); key != "" {
				return key
			}
			continue
		}
		if key := auditCleanupKeyFromField(field); key != "" {
			return key
		}
	}
	return ""
}

func auditCleanupKeyFromField(field string) string {
	field = strings.Trim(strings.TrimSpace(field), `"`)
	for _, prefix := range []string{"key=", "-Fkey="} {
		if strings.HasPrefix(field, prefix) {
			return strings.Trim(strings.TrimPrefix(field, prefix), `"`)
		}
	}
	return ""
}

func isSecweaverAuditCleanupKey(key string) bool {
	// Keep this allowlist narrower than the general "tb_" namespace. Uninstall
	// must never remove audit rules belonging to another TigerSec component.
	key = strings.Trim(strings.TrimSpace(key), `"`)
	return key == "tb_host_persistence" ||
		strings.HasPrefix(key, "tb_external_listener_") ||
		strings.HasPrefix(key, "tb_port_")
}

// deleteAuditCleanupLine converts the normalized output of auditctl -l back to
// an exact delete operation. Watch deletion first includes the key for kernels
// that require an exact match, then falls back to path-only deletion.
func deleteAuditCleanupLine(ctx context.Context, line string) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	switch fields[0] {
	case "-a":
		args := append([]string{"-d"}, fields[1:]...)
		out, err := runAuditCleanupCommandWithTimeout(ctx, auditCleanupTimeout, "auditctl", args...)
		if err != nil {
			return fmt.Errorf("delete audit syscall rule %q: %s", line, auditCleanupErrorMessage(out, err))
		}
		return nil
	case "-w":
		path := auditCleanupWatchPath(fields)
		if path == "" {
			return fmt.Errorf("delete audit watch rule %q: missing path", line)
		}
		key := auditCleanupKeyFromLine(line)
		if key != "" {
			if out, err := runAuditCleanupCommandWithTimeout(ctx, auditCleanupTimeout, "auditctl", "-W", path, "-k", key); err == nil {
				_ = out
				return nil
			}
		}
		out, err := runAuditCleanupCommandWithTimeout(ctx, auditCleanupTimeout, "auditctl", "-W", path)
		if err != nil {
			return fmt.Errorf("delete audit watch rule %q: %s", line, auditCleanupErrorMessage(out, err))
		}
		return nil
	default:
		return fmt.Errorf("delete audit rule %q: unsupported rule type", line)
	}
}

func auditCleanupWatchPath(fields []string) string {
	for i, field := range fields {
		if field == "-w" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func runAuditCleanupCommandWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	// auditctl talks to a privileged kernel subsystem and can stall while auditd
	// is unhealthy. Every uninstall/cleanup call is bounded so service stop and
	// package removal cannot hang indefinitely.
	if timeout <= 0 {
		timeout = auditCleanupTimeout
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, name, args...)
	out, err := cmd.CombinedOutput()
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return out, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return out, err
}

func auditCleanupErrorMessage(out []byte, err error) string {
	msg := strings.TrimSpace(string(out))
	if msg == "" && err != nil {
		msg = err.Error()
	}
	if msg == "" {
		msg = "unknown error"
	}
	return msg
}
