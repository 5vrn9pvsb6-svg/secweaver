package hostpersistence

import (
	"context"

	"errors"
	"fmt"

	"os"
	"os/exec"

	"path/filepath"

	"sort"

	"strings"
	"sync"
	"time"

	"secweaver-agent/pkg/auditstream"
)

// This file owns audit watch installation, reconciliation, rollback, cleanup, and bounded auditctl execution.

func startAuditEnrichment(ctx context.Context, cfg runtimeConfig) (*auditTracker, func(), error) {
	if !cfg.Audit.Enabled {
		return nil, func() {}, nil
	}
	tracker := newAuditTracker(auditRetention, 20)
	addedRules := []string{}
	var rulesMu sync.Mutex
	if cfg.Audit.ManageRules {
		paths := concreteAuditWatchPaths(cfg.Watch)
		// Remove rules from an earlier unclean shutdown before claiming this
		// process's rule ownership. Cleanup is key-scoped, so foreign audit rules
		// are not touched.
		cleanupAuditRules(paths, cfg.Audit)
		managedPaths := map[string]bool{}
		lastReconcile := time.Time{}
		// Persistence targets may appear after startup (for example a newly
		// created cron file). Reconciliation compares desired, currently existing
		// paths with kernel state and only installs missing watches.
		ensureWatches := func(failOnError, forceReconcile bool) error {
			now := time.Now()
			if forceReconcile || lastReconcile.IsZero() || now.Sub(lastReconcile) >= auditWatchReconcile {
				if kernelPaths, err := listAuditWatchPathsByKey(cfg.Audit.Key); err == nil {
					rulesMu.Lock()
					managedPaths = kernelPaths
					rulesMu.Unlock()
					lastReconcile = now
				} else if failOnError {
					return fmt.Errorf("list audit watches for key %s: %w", cfg.Audit.Key, err)
				} else {
					fmt.Fprintf(os.Stderr, "WARN: reconcile host-persistence audit watches: %v\n", err)
				}
			}
			for _, path := range concreteAuditWatchPaths(cfg.Watch) {
				rulesMu.Lock()
				managed := managedPaths[path]
				rulesMu.Unlock()
				if managed {
					continue
				}
				if err := runAuditctl("-w", path, "-p", cfg.Audit.Perm, "-k", cfg.Audit.Key); err != nil {
					msg := fmt.Errorf("add audit watch %s: %w", path, err)
					if failOnError {
						return msg
					}
					fmt.Fprintf(os.Stderr, "WARN: %v\n", msg)
					continue
				}
				rulesMu.Lock()
				managedPaths[path] = true
				addedRules = append(addedRules, path)
				rulesMu.Unlock()
			}
			return nil
		}
		if err := ensureWatches(cfg.Audit.FailOnError, true); err != nil {
			cleanupAuditRules(addedRules, cfg.Audit)
			return nil, func() {}, err
		}
		tracker.refreshWatches = func() { _ = ensureWatches(false, false) }
		if len(addedRules) > 0 {
			fmt.Fprintf(os.Stderr, "host-persistence audit watch rules added: %d key=%s\n", len(addedRules), cfg.Audit.Key)
		}
	}
	if !cfg.Audit.FollowLog {
		fmt.Fprintf(os.Stderr, "host-persistence audit log follow disabled; audit actor enrichment will be unavailable\n")
		return tracker, func() { cleanupAuditRules(addedRules, cfg.Audit) }, nil
	}
	// Under the parent agent, modules consume one demultiplexed audit stream.
	// Standalone execution falls back to following audit.log directly.
	sharedAuditStream, usingSharedAuditStream, err := auditstream.ReaderFromEnv()
	if err != nil {
		msg := fmt.Errorf("open shared audit input: %w", err)
		if cfg.Audit.FailOnError {
			cleanupAuditRules(addedRules, cfg.Audit)
			return nil, func() {}, msg
		}
		fmt.Fprintf(os.Stderr, "WARN: %v\n", msg)
	} else if usingSharedAuditStream {
		fmt.Fprintf(os.Stderr, "host-persistence audit log input: shared secweaver-agent demux\n")
		go func() {
			if err := followAuditStream(ctx, sharedAuditStream, cfg.Audit, tracker); err != nil && !errors.Is(err, context.Canceled) {
				fmt.Fprintf(os.Stderr, "WARN: host-persistence shared audit follow failed: %v\n", err)
				// Losing the reader silently would leave polling events permanently
				// without actor data. Report it to the module supervisor so the
				// module can be restarted with a fresh shared stream.
				tracker.reportFatal(err)
			}
		}()
		return tracker, func() {
			_ = sharedAuditStream.Close()
			cleanupAuditRules(addedRules, cfg.Audit)
		}, nil
	}
	if _, err := os.Stat(cfg.Audit.AuditLog); err != nil {
		msg := fmt.Errorf("audit log unavailable %s: %w", cfg.Audit.AuditLog, err)
		if cfg.Audit.FailOnError {
			cleanupAuditRules(addedRules, cfg.Audit)
			return nil, func() {}, msg
		}
		fmt.Fprintf(os.Stderr, "WARN: %v\n", msg)
		return tracker, func() { cleanupAuditRules(addedRules, cfg.Audit) }, nil
	}
	go func() {
		if err := followAuditLog(ctx, cfg.Audit, tracker); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "WARN: host-persistence audit follow failed: %v\n", err)
			tracker.reportFatal(err)
		}
	}()
	return tracker, func() { cleanupAuditRules(addedRules, cfg.Audit) }, nil
}

func concreteAuditWatchPaths(targets []watchTarget) []string {
	// auditctl cannot watch a path that does not yet exist. The scanner calls
	// RefreshWatches after discovering later-created targets, at which point
	// they become concrete and can be installed.
	seen := map[string]bool{}
	var out []string
	for _, target := range targets {
		paths, err := expandTargetPaths(target.Path)
		if err != nil {
			continue
		}
		for _, path := range paths {
			path = filepath.Clean(path)
			if seen[path] {
				continue
			}
			if _, err := os.Lstat(path); err != nil {
				continue
			}
			seen[path] = true
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

func cleanupAuditRules(paths []string, cfg auditRuntimeConfig) {
	if !cfg.ManageRules {
		return
	}
	if strings.TrimSpace(cfg.Key) != "" {
		// Modern auditctl supports key-scoped bulk deletion. Older versions may
		// reject it, so retain an exact per-watch compatibility fallback.
		if err := runAuditctl("-D", "-k", cfg.Key); err == nil {
			return
		}
		cleanupAuditWatchRulesByKey(cfg.Key)
	}
	for _, path := range paths {
		if err := runAuditctl("-W", path, "-p", cfg.Perm, "-k", cfg.Key); err != nil {
			_ = runAuditctl("-W", path)
		}
	}
}

func cleanupAuditWatchRulesByKey(key string) {
	out, err := runAuditctlCommand(auditctlTimeout, "-l")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		path, perm, ok := parseAuditWatchListLine(line, key)
		if !ok {
			continue
		}
		if perm != "" {
			if err := runAuditctl("-W", path, "-p", perm, "-k", key); err == nil {
				continue
			}
		}
		_ = runAuditctl("-W", path)
	}
}

func listAuditWatchPathsByKey(key string) (map[string]bool, error) {
	out, err := runAuditctlCommand(auditctlTimeout, "-l")
	if err != nil {
		return nil, err
	}
	paths := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		path, _, ok := parseAuditWatchListLine(line, key)
		if ok {
			paths[filepath.Clean(path)] = true
		}
	}
	return paths, nil
}

func parseAuditWatchListLine(line, key string) (path, perm string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 || fields[0] != "-w" {
		return "", "", false
	}
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "-w":
			if i+1 < len(fields) {
				path = fields[i+1]
			}
		case "-p":
			if i+1 < len(fields) {
				perm = fields[i+1]
			}
		case "-k":
			if i+1 < len(fields) && strings.Trim(fields[i+1], `"`) == key {
				ok = true
			}
		}
	}
	return path, perm, ok && path != ""
}

func runAuditctl(args ...string) error {
	_, err := runAuditctlCommand(auditctlTimeout, args...)
	return err
}

func runAuditctlOutputWithTimeout(timeout time.Duration, args ...string) ([]byte, error) {
	// auditctl can block while auditd/kernel state is unhealthy. Every lifecycle
	// call is bounded so startup and systemd stop cannot hang indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "auditctl", args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("auditctl %s timed out after %s", strings.Join(args, " "), timeout)
	}
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return out, fmt.Errorf("auditctl %s: %s", strings.Join(args, " "), msg)
	}
	return out, nil
}
