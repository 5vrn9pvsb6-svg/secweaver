package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/layout"
)

// runLearningModeCommand applies an explicit installer choice while preserving
// every unrelated audit policy field. preserve is intentionally a no-op for an
// existing configuration, which prevents upgrades from silently enabling a
// high-volume filtering policy.
func runLearningModeCommand(args []string) int {
	fs := flag.NewFlagSet("config set-learning-mode", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := layout.LinuxEtc + "/audit-port-execmon.json"
	mode := "preserve"
	fs.StringVar(&configPath, "config", configPath, "audit-port-execmon JSON config path")
	fs.StringVar(&mode, "mode", mode, "learning mode: preserve, shadow, enable, or disable")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	status, err := setLearningModeInConfig(configPath, mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "set learning mode failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "behavior learning: %s\n", status)
	return 0
}

// setLearningModeInConfig validates the policy before writing it atomically.
// Explicit modes only touch enabled/shadow; preserve reports the effective
// existing choice without changing the file or its generation.
func setLearningModeInConfig(path, mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "preserve", "shadow", "enable", "disable":
	default:
		return "", fmt.Errorf("mode must be preserve, shadow, enable, or disable")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil || payload == nil {
		if err == nil {
			err = fmt.Errorf("config must be a JSON object")
		}
		return "", fmt.Errorf("parse config: %w", err)
	}
	var policy behaviorlearning.Config
	learning := map[string]json.RawMessage{}
	if raw := payload["behavior_learning"]; len(raw) > 0 && strings.TrimSpace(string(raw)) != "null" {
		policy, err = behaviorlearning.Decode(raw)
		if err != nil && mode == "preserve" {
			return "disabled; reason=existing-config-invalid", nil
		}
		if err != nil {
			return "", fmt.Errorf("behavior_learning: %w", err)
		}
		if err := json.Unmarshal(raw, &learning); err != nil || learning == nil {
			return "", fmt.Errorf("behavior_learning must be a JSON object")
		}
	}
	if mode == "preserve" {
		if !policy.Enabled {
			return "disabled; reason=existing-config-preserved", nil
		}
		if policy.Shadow {
			return "enabled; mode=shadow; reason=existing-config-preserved", nil
		}
		return "enabled; mode=enable; reason=existing-config-preserved", nil
	}
	learning["enabled"], _ = json.Marshal(mode != "disable")
	learning["shadow"], _ = json.Marshal(mode == "shadow")
	encoded, err := json.Marshal(learning)
	if err != nil {
		return "", err
	}
	if _, err := behaviorlearning.Decode(encoded); err != nil {
		return "", fmt.Errorf("behavior_learning: %w", err)
	}
	payload["behavior_learning"] = encoded
	body, err = json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	// This is a module configuration, not the supervisor's config.json. Do
	// not apply supervisor validation here or add default policy fields: only
	// the two explicit choices may change, leaving generation and scope intact.
	if err := writeFileAtomic(path, append(body, '\n'), 0600); err != nil {
		return "", err
	}
	if mode == "disable" {
		return "disabled; reason=explicit-install-choice", nil
	}
	if mode == "shadow" {
		return "enabled; mode=shadow; reason=explicit-install-choice", nil
	}
	return "enabled; mode=enable; reason=explicit-install-choice", nil
}
