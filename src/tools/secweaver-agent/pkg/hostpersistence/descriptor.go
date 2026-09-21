package hostpersistence

import (
	"fmt"
	"strings"

	"secweaver-agent/internal/modulecontract"
)

// Descriptor keeps host-persistence configuration semantics inside its owner
// package while exposing the narrow capabilities needed by the supervisor.
func Descriptor() modulecontract.Descriptor {
	return modulecontract.Descriptor{
		Name:        "host-persistence",
		Description: "Linux/Windows persistence change monitor for file-based autostart and profile paths",
		Platforms:   []string{"linux", "windows"},
		Flags: modulecontract.Flags(
			[]string{"config", "output", "state", "host-ip", "poll-interval", "max-hash-bytes", "max-content-bytes", "max-diff-lines", "audit-log", "audit-key"},
			[]string{"once", "emit-baseline", "hash", "content-diff", "audit", "audit-manage-rules", "stats", "version"},
		),
		OutputPaths:       descriptorOutputPaths,
		AuditSubscription: descriptorAuditSubscription,
		Run:               Main,
	}
}

func descriptorOutputPaths(args []string) []string {
	cfg, err := descriptorRuntimeConfig(args)
	if err != nil {
		return []string{defaultOutputLogPath()}
	}
	return []string{cfg.OutputLog}
}

// descriptorRuntimeConfig deliberately reuses the module's normal loader and
// then applies CLI precedence. It prevents the parent demux and child collector
// from interpreting audit enablement or paths differently.
func descriptorRuntimeConfig(args []string) (runtimeConfig, error) {
	configPath, _ := modulecontract.StringFlag(args, "config")
	cfg, err := loadRuntimeConfig(strings.TrimSpace(configPath))
	if err != nil {
		return runtimeConfig{}, err
	}
	if value, ok := modulecontract.StringFlag(args, "output"); ok {
		cfg.OutputLog = value
	}
	if value, ok, parseErr := modulecontract.BoolFlag(args, "audit"); parseErr != nil {
		return runtimeConfig{}, parseErr
	} else if ok {
		cfg.Audit.Enabled = value
	}
	if value, ok := modulecontract.StringFlag(args, "audit-log"); ok {
		cfg.Audit.AuditLog = strings.TrimSpace(value)
	}
	if value, ok := modulecontract.StringFlag(args, "audit-key"); ok && strings.TrimSpace(value) != "" {
		cfg.Audit.Key = strings.TrimSpace(value)
	}
	cfg.Audit.normalize()
	return cfg, nil
}

func descriptorAuditSubscription(args []string) (modulecontract.AuditSubscription, bool, error) {
	cfg, err := descriptorRuntimeConfig(args)
	if err != nil {
		return modulecontract.AuditSubscription{}, false, fmt.Errorf("resolve host-persistence config: %w", err)
	}
	if !cfg.Audit.Enabled || !cfg.Audit.FollowLog {
		return modulecontract.AuditSubscription{}, false, nil
	}
	return modulecontract.AuditSubscription{
		Path:      cfg.Audit.AuditLog,
		FromStart: cfg.Audit.FromStart,
		Keys:      []string{cfg.Audit.Key},
	}, true, nil
}
