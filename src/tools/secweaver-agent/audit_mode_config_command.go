package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"secweaver-agent/pkg/auditportexecmon"
)

const (
	configAuditModeAuto     = "auto"
	configAuditModeAudit    = "audit"
	configAuditModeEBPFOnly = "ebpf_only"
)

// runAuditModeCommand persists the product-level transport decision made by
// the installer. It preserves the original feature policy: the supervisor
// suppresses Audit-only capabilities in memory and keeps persistence polling.
func runAuditModeCommand(args []string) int {
	fs := flag.NewFlagSet("config set-audit-mode", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	auditConfigPath := ""
	mode := configAuditModeAuto
	autoOnly := false
	fs.StringVar(&auditConfigPath, "config", "", "audit-port-execmon JSON config path")
	fs.StringVar(&mode, "mode", configAuditModeAuto, "collection mode: auto, audit, or ebpf_only")
	fs.BoolVar(&autoOnly, "auto-only", false, "refuse to replace an explicit existing mode")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "set audit mode failed: unexpected arguments")
		return 2
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != configAuditModeAuto && mode != configAuditModeAudit && mode != configAuditModeEBPFOnly {
		fmt.Fprintf(os.Stderr, "set audit mode failed: mode must be %s, %s, or %s\n", configAuditModeAuto, configAuditModeAudit, configAuditModeEBPFOnly)
		return 2
	}
	if strings.TrimSpace(auditConfigPath) == "" {
		fmt.Fprintln(os.Stderr, "set audit mode failed: -config is required")
		return 2
	}
	changed, backend, err := setAuditModeInModuleConfig(auditConfigPath, mode, autoOnly)
	if err != nil {
		fmt.Fprintf(os.Stderr, "set audit mode failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "audit collection configured: mode=%s process_backend=%s changed=%v (%s)\n", mode, backend, changed, auditConfigPath)
	return 0
}

// runCheckLinuxCollectionCommand verifies the transport before an installer
// registers or replaces this host. Real eBPF load/attach is temporary and owns
// no listener roots, Audit rules, event output, or learning state.
func runCheckLinuxCollectionCommand(args []string) int {
	fs := flag.NewFlagSet("config check-linux-collection", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := ""
	fs.StringVar(&path, "config", "", "audit-port-execmon JSON config path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(path) == "" {
		fmt.Fprintln(os.Stderr, "check Linux collection failed: -config is required and trailing arguments are not allowed")
		return 2
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "check Linux collection failed: command requires a Linux host")
		return 1
	}
	profile, err := auditportexecmon.ResolveCollectionProfile(context.Background(), []string{"-config", path}, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check Linux collection failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "Linux collection verified: mode=%s reason=%s\n", profile.Mode, profile.Reason)
	return 0
}

// setAuditModeInModuleConfig updates only the transport fields and preserves
// all event scope, learning state, pressure thresholds, and custom policies.
// Explicit audit backends are rejected in eBPF-only mode so an operator's
// forced choice is never silently rewritten during an upgrade.
func setAuditModeInModuleConfig(path, mode string, autoOnly bool) (bool, string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return false, "", err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, "", fmt.Errorf("parse audit config: %w", err)
	}
	if payload == nil {
		return false, "", fmt.Errorf("audit config must be a JSON object")
	}

	audit := map[string]json.RawMessage{}
	if raw := payload["audit"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &audit); err != nil {
			return false, "", fmt.Errorf("parse audit settings: %w", err)
		}
	}
	if audit == nil {
		audit = map[string]json.RawMessage{}
	}
	current := ""
	if raw := audit["mode"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &current); err != nil {
			return false, "", fmt.Errorf("parse existing audit.mode: %w", err)
		}
		current = strings.ToLower(strings.TrimSpace(current))
	}
	if current == "" {
		current = configAuditModeAuto
	}
	if current != configAuditModeAuto && current != configAuditModeAudit && current != configAuditModeEBPFOnly {
		return false, "", fmt.Errorf("invalid existing audit.mode=%q", current)
	}
	if autoOnly && current != configAuditModeAuto && current != mode {
		return false, "", fmt.Errorf("existing audit.mode=%q is explicit; refusing automatic replacement", current)
	}

	backend := "auto"
	if raw := payload["exec"]; len(raw) > 0 {
		var execSettings map[string]json.RawMessage
		if err := json.Unmarshal(raw, &execSettings); err != nil {
			return false, "", fmt.Errorf("parse exec settings: %w", err)
		}
		if raw := execSettings["process_tree_backend"]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &backend); err != nil {
				return false, "", fmt.Errorf("parse process_tree_backend: %w", err)
			}
			backend = strings.ToLower(strings.TrimSpace(backend))
		}
		if backend == "" {
			backend = "auto"
		}
		if mode == configAuditModeEBPFOnly {
			if backend == "audit" || backend == "audit_pid" {
				return false, backend, fmt.Errorf("exec.process_tree_backend=%q explicitly requires audit; set it to auto or ebpf before selecting eBPF-only", backend)
			}
		}
	}
	audit["mode"], _ = json.Marshal(mode)
	encodedAudit, err := json.Marshal(audit)
	if err != nil {
		return false, backend, fmt.Errorf("encode audit settings: %w", err)
	}
	payload["audit"] = encodedAudit
	changed := current != mode
	if !changed {
		return false, backend, nil
	}
	if err := writeJSONMapPreservingMode(path, payload); err != nil {
		return false, backend, err
	}
	return true, backend, nil
}

// writeJSONMapPreservingMode publishes a complete config atomically and retains
// its file permissions. A failed write leaves the previous configuration valid.
func writeJSONMapPreservingMode(path string, payload map[string]json.RawMessage) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	return writeFileAtomic(path, append(encoded, '\n'), info.Mode().Perm())
}
