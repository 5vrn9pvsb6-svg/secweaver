package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	deploymentSLS = "sls_saas"
	deploymentES  = "es_private"
)

// validateDeploymentMode leaves legacy and standalone configurations valid.
// A mode selects delivery diagnostics, never a different collection engine.
func validateDeploymentMode(mode string) error {
	if mode != "" && mode != deploymentSLS && mode != deploymentES {
		return fmt.Errorf("deployment_mode must be sls_saas or es_private, got %q", mode)
	}
	return nil
}

// installedDeploymentMode only trusts product-owned files next to the config.
// Global Logtail/Filebeat installations can belong to another application.
// Conflicting evidence is an error: choosing one could overwrite its credentials.
func installedDeploymentMode(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var cfg struct {
		DeploymentMode string `json:"deployment_mode"`
	}
	if err == nil {
		if err := json.Unmarshal(body, &cfg); err != nil {
			return "", err
		}
		if err := validateDeploymentMode(cfg.DeploymentMode); err != nil {
			return "", err
		}
	}
	modes := map[string]bool{}
	if cfg.DeploymentMode != "" {
		modes[cfg.DeploymentMode] = true
	}
	dir := filepath.Dir(path)
	marker, err := os.ReadFile(filepath.Join(dir, "shipper-kind"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if strings.TrimSpace(string(marker)) == "logtail" {
		modes[deploymentSLS] = true
	}
	for _, root := range []string{filepath.Join(dir, "shipper"), filepath.Join(filepath.Dir(dir), "shipper")} {
		for _, name := range []string{"filebeat.yml", "shipper.json", "fluent-bit.conf"} {
			info, err := os.Stat(filepath.Join(root, name))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
			if err == nil && info.Mode().IsRegular() {
				modes[deploymentES] = true
			}
		}
	}
	if len(modes) > 1 {
		return "", fmt.Errorf("conflicting SLS/ES deployment evidence in %s; resolve the previous installation before proceeding", dir)
	}
	for mode := range modes {
		return mode, nil
	}
	return "", nil
}

// configureDeploymentMode checks before installer side effects and rechecks at
// persistence. Installers must be serialized by their operator; this command
// performs an atomic config replacement, not a cross-process install lock.
func configureDeploymentMode(path, requested string, checkOnly bool) (string, error) {
	if err := validateDeploymentMode(requested); err != nil {
		return "", err
	}
	current, err := installedDeploymentMode(path)
	if err != nil {
		return "", err
	}
	if current != "" && requested != "" && current != requested {
		return "", fmt.Errorf("deployment mode conflict: installed=%s requested=%s; ordinary upgrades cannot migrate delivery channels", current, requested)
	}
	if requested == "" {
		requested = current
	}
	if checkOnly || requested == "" {
		return requested, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if payload == nil {
		return "", fmt.Errorf("config must be a JSON object")
	}
	payload["deployment_mode"], _ = json.Marshal(requested)
	body, err = json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	// Do not validate unrelated CA/module files here: bootstrap has not yet
	// installed them. Normal preflight validates the completed configuration.
	if err := writeFileAtomic(path, append(body, '\n'), 0600); err != nil {
		return "", err
	}
	return requested, nil
}

func runDeploymentModeCommand(args []string) int {
	fs := flag.NewFlagSet("config set-deployment-mode", flag.ContinueOnError)
	path := fs.String("config", defaultAgentConfigPath(), "Agent config path")
	mode := fs.String("mode", "", "sls_saas or es_private; omitted preserves existing mode")
	check := fs.Bool("check-only", false, "validate without changing files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	value, err := configureDeploymentMode(*path, *mode, *check)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if value == "" {
		value = "unspecified"
	}
	fmt.Fprintln(os.Stdout, value)
	return 0
}

// preserveDeploymentMode runs after signature verification. Delivery ownership
// is local installation state: old policies may omit it, but cannot replace it.
func preserveDeploymentMode(current, candidate []byte) ([]byte, error) {
	var old, next map[string]json.RawMessage
	if err := json.Unmarshal(current, &old); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(candidate, &next); err != nil {
		return nil, err
	}
	if old == nil || next == nil {
		return nil, fmt.Errorf("deployment policy must be a JSON object")
	}
	var before, after string
	if v := old["deployment_mode"]; v != nil {
		if err := json.Unmarshal(v, &before); err != nil {
			return nil, err
		}
	}
	if v := next["deployment_mode"]; v != nil {
		if err := json.Unmarshal(v, &after); err != nil {
			return nil, err
		}
	}
	if err := validateDeploymentMode(before); err != nil {
		return nil, err
	}
	if err := validateDeploymentMode(after); err != nil {
		return nil, err
	}
	if after != "" && after != before {
		return nil, fmt.Errorf("remote policy cannot change deployment_mode")
	}
	if before != "" && after == "" {
		next["deployment_mode"] = old["deployment_mode"]
		return json.MarshalIndent(next, "", "  ")
	}
	return candidate, nil
}
