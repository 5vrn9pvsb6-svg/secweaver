package auditportexecmon

import (
	"context"
	"fmt"
	"strings"

	"secweaver-agent/internal/modulecontract"
)

// CollectionProfile is the effective Linux evidence transport. Mode=ebpf_only means
// that no Audit-backed input or kernel rule is owned by this Agent run.
type CollectionProfile struct {
	Mode   string
	Reason string
}

// ResolveCollectionProfile shares config/CLI precedence and capability checks
// between the installer, supervisor and standalone collector. verifyAttach is
// used only before starting a real run: it temporarily loads/attaches the real
// programs and closes them without tracking processes or collecting evidence.
// Read-only diagnostics use Probe instead and explicitly cannot prove attach.
func ResolveCollectionProfile(ctx context.Context, args []string, verifyAttach bool) (CollectionProfile, error) {
	path, _ := modulecontract.StringFlag(args, "config")
	cfg, err := loadConfig(strings.TrimSpace(path))
	if err != nil {
		return CollectionProfile{}, fmt.Errorf("load collection config: %w", err)
	}
	if value, ok := modulecontract.StringFlag(args, "collection-mode"); ok {
		if !validAuditCollectionMode(value) {
			return CollectionProfile{}, fmt.Errorf("collection-mode must be auto, audit or ebpf_only")
		}
		cfg.Audit.Mode = normalizeAuditCollectionMode(value)
	}
	auditLog := "/var/log/audit/audit.log"
	if value, ok := modulecontract.StringFlag(args, "audit-log"); ok && strings.TrimSpace(value) != "" {
		auditLog = strings.TrimSpace(value)
	}
	return resolveCollectionProfile(ctx, cfg, verifyAttach, func() error { return requireAuditEnvironment(auditLog) })
}

// resolveCollectionProfile keeps availability separate from explicit policy.
// An unavailable Audit environment may degrade only an auto configuration; a
// forced Audit backend/mode remains an actionable error. Both unavailable
// transports fail before child workers, rules or enrollment are started.
func resolveCollectionProfile(ctx context.Context, cfg config, verifyAttach bool, auditAvailable func() error) (CollectionProfile, error) {
	mode := normalizeAuditCollectionMode(cfg.Audit.Mode)
	reason := "explicit eBPF-only configuration"
	if mode != auditCollectionModeEBPFOnly {
		if err := auditAvailable(); err == nil {
			// Freeze the complete Audit transport for this run. Process tracking
			// may still use auto eBPF/Audit fallback, but a restarting child must
			// not switch transports while its siblings keep Audit subscriptions.
			return CollectionProfile{Mode: auditCollectionModeAudit, Reason: "audit environment is available"}, nil
		} else {
			if mode == auditCollectionModeAudit {
				return CollectionProfile{}, fmt.Errorf("audit.mode=audit requires Audit: %w", err)
			}
			reason = "Audit unavailable: " + err.Error()
		}
	}
	backend := resolveProcessTreeConfig(cfg).Backend
	if backend == processTreeBackendAudit || backend == processTreeBackendAuditPID {
		return CollectionProfile{}, fmt.Errorf("%s; exec.process_tree_backend=%s explicitly requires Audit", reason, backend)
	}
	if !configMonitorExec(cfg) {
		return CollectionProfile{}, fmt.Errorf("%s; eBPF-only requires exec.monitor=true", reason)
	}
	tree := resolveProcessTreeConfig(cfg)
	tree.CollectionMode = auditCollectionModeEBPFOnly
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	_, tracker, _, err := startConfiguredProcessTracker(probeCtx, tree, true, verifyAttach)
	if err != nil {
		return CollectionProfile{}, fmt.Errorf("Linux collection unavailable: %s; %w", reason, err)
	}
	if tracker != nil {
		// Cancel the context worker and release maps/links before returning;
		// the capability probe must never leave programs attached to the host.
		cancel()
		if err := tracker.Close(); err != nil {
			return CollectionProfile{}, fmt.Errorf("close eBPF capability probe: %w", err)
		}
	}
	return CollectionProfile{Mode: auditCollectionModeEBPFOnly, Reason: reason}, nil
}
