package hostpersistence

import (
	"encoding/json"

	"os"

	"path/filepath"

	"strings"

	"time"
)

// This file owns configuration loading, default selection, and normalization before any scanner or audit goroutine starts.

func loadRuntimeConfig(path string) (runtimeConfig, error) {
	cfg := runtimeConfig{
		OutputLog:          defaultOutputLogPath(),
		StatePath:          defaultStatePath(),
		PollInterval:       defaultPollInterval,
		IncludeHash:        true,
		MaxHashBytes:       defaultMaxHashBytes,
		IncludeContentDiff: true,
		MaxContentBytes:    defaultMaxContentBytes,
		MaxDiffLines:       defaultMaxDiffLines,
		Audit:              defaultAuditRuntimeConfig(),
		Watch:              copyDefaultTargets(),
	}
	if strings.TrimSpace(path) == "" {
		return cfg, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return runtimeConfig{}, err
	}
	var raw config
	if err := json.Unmarshal(body, &raw); err != nil {
		return runtimeConfig{}, err
	}
	if strings.TrimSpace(raw.OutputLog) != "" {
		cfg.OutputLog = strings.TrimSpace(raw.OutputLog)
	}
	if strings.TrimSpace(raw.StatePath) != "" {
		cfg.StatePath = strings.TrimSpace(raw.StatePath)
	}
	if raw.PollIntervalSeconds > 0 {
		cfg.PollInterval = time.Duration(raw.PollIntervalSeconds) * time.Second
	}
	if strings.TrimSpace(raw.HostIP) != "" {
		cfg.HostIP = strings.TrimSpace(raw.HostIP)
	}
	if raw.IncludeHash != nil {
		cfg.IncludeHash = *raw.IncludeHash
	}
	if raw.MaxHashBytes > 0 {
		cfg.MaxHashBytes = raw.MaxHashBytes
	}
	if raw.IncludeContentDiff != nil {
		cfg.IncludeContentDiff = *raw.IncludeContentDiff
	}
	if raw.MaxContentBytes > 0 {
		cfg.MaxContentBytes = raw.MaxContentBytes
	}
	if raw.MaxDiffLines > 0 {
		cfg.MaxDiffLines = raw.MaxDiffLines
	}
	cfg.EmitBaseline = raw.EmitBaseline
	cfg.Audit = mergeAuditConfig(cfg.Audit, raw.Audit)
	if len(raw.Watch) > 0 {
		cfg.Watch = normalizeTargets(raw.Watch)
	}
	cfg.normalize()
	return cfg, nil
}

func (cfg *runtimeConfig) normalize() {
	if strings.TrimSpace(cfg.OutputLog) == "" {
		cfg.OutputLog = defaultOutputLogPath()
	}
	cfg.StatePath = strings.TrimSpace(cfg.StatePath)
	cfg.HostIP = strings.TrimSpace(cfg.HostIP)
	if cfg.HostIP == "" {
		cfg.HostIP = detectPrimaryHostIP()
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.MaxHashBytes <= 0 {
		cfg.MaxHashBytes = defaultMaxHashBytes
	}
	if cfg.MaxContentBytes <= 0 {
		cfg.MaxContentBytes = defaultMaxContentBytes
	}
	if cfg.MaxDiffLines <= 0 {
		cfg.MaxDiffLines = defaultMaxDiffLines
	}
	cfg.Audit.normalize()
	if len(cfg.Watch) == 0 {
		cfg.Watch = copyDefaultTargets()
	}
	cfg.Watch = normalizeTargets(cfg.Watch)
}

func normalizeTargets(targets []watchTarget) []watchTarget {
	out := make([]watchTarget, 0, len(targets))
	for _, target := range targets {
		target.Path = filepath.Clean(strings.TrimSpace(target.Path))
		target.Category = strings.TrimSpace(target.Category)
		target.PersistenceType = strings.TrimSpace(target.PersistenceType)
		if target.Path == "." || target.Path == "" {
			continue
		}
		if target.Category == "" {
			target.Category = "persistence"
		}
		if target.PersistenceType == "" {
			target.PersistenceType = target.Category
		}
		out = append(out, target)
	}
	return out
}
