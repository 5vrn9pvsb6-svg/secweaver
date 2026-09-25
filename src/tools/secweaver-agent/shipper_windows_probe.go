package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"secweaver-agent/pkg/windowscollection"
)

// probeWindowsLogtail separates runtime, intended identity and delivered rules.
// Only the running worker's cache is accepted. Credentials never enter the probe;
// malformed/unsupported caches fail closed, and local success is not cloud proof.
func probeWindowsLogtail(configDir string, expected bool, agentConfigDir string, run func(time.Duration, string, ...string) ([]byte, error)) operationsShipper {
	s := operationsShipper{Type: "unknown", Configuration: "not_detected", ServiceStatus: "unknown", ProcessStatus: "unknown", CloudDelivery: "unverified", CheckedAt: time.Now().UTC().Format(time.RFC3339), Reason: "shipper_not_detected"}
	const script = `$ErrorActionPreference='Stop'; $s=Get-CimInstance Win32_Service -Filter "Name='LogtailDaemon'"; $p=@(Get-CimInstance Win32_Process -Filter "Name='ilogtail_worker.exe'"); $cache=''; if ($p.Count -eq 1 -and $p[0].ExecutablePath) { $cache=Join-Path (Split-Path -Parent $p[0].ExecutablePath) 'user_log_config.json' }; @{installed=($null -ne $s); state=$s.State; service_pid=$s.ProcessId; workers=$p.Count; user_config_path=$cache} | ConvertTo-Json -Compress`
	out, err := run(10*time.Second, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	var probe struct {
		Installed      bool   `json:"installed"`
		State          string `json:"state"`
		PID            uint32 `json:"service_pid"`
		Workers        int    `json:"workers"`
		UserConfigPath string `json:"user_config_path"`
	}
	valid := err == nil && json.Unmarshal(out, &probe) == nil
	if !expected && !pathExists(configDir) && (!valid || !probe.Installed) {
		return s
	}
	s.Type, s.Configuration, s.Reason = "logtail", "contract_missing", "logtail_collection_contract_missing"
	body, contractErr := windowscollection.ReadBounded(filepath.Join(agentConfigDir, "windows-collection.json"), 65536)
	key, keyErr := windowscollection.ReadBounded(filepath.Join(agentConfigDir, "windows-collection.pub"), 128)
	var manifest windowscollection.Manifest
	if contractErr == nil && keyErr == nil {
		manifest, contractErr = windowscollection.Verify(body, string(key))
	}
	if contractErr == nil && keyErr == nil {
		s.Configuration, s.Reason = "identity_missing", "logtail_identity_mismatch"
		info, accountErr := os.Stat(filepath.Join(configDir, "users", manifest.AliUID))
		groups, groupErr := windowscollection.ReadBounded(filepath.Join(configDir, "user_defined_id"), 65536)
		hasGroup := false
		for _, g := range strings.Split(string(groups), "\n") {
			if strings.TrimSpace(g) == manifest.MachineGroup {
				hasGroup = true
			}
		}
		if accountErr == nil && info.Mode().IsRegular() && groupErr == nil && hasGroup {
			s.Configuration, s.Reason = "collection_rules_missing", "logtail_collection_config_missing"
			if valid && probe.UserConfigPath != "" {
				s.ConfigPath = probe.UserConfigPath
				cache, cacheErr := windowscollection.ReadBounded(s.ConfigPath, 4<<20)
				if cacheErr == nil {
					s.MissingPaths, cacheErr = windowscollection.CheckCache(cache, manifest)
				}
				if cacheErr == nil && len(s.MissingPaths) == 0 {
					s.Configuration, s.Reason = "configured", "cloud_receipt_requires_server_side_verification"
				}
			}
		}
	}
	if !valid {
		s.Reason = "logtail_probe_failed"
		return s
	}
	s.Service = "LogtailDaemon"
	if !probe.Installed {
		s.ServiceStatus, s.ProcessStatus, s.Reason = "missing", "missing", "expected_logtail_not_installed"
		return s
	}
	s.ServiceStatus = "inactive"
	if probe.State == "Running" {
		s.ServiceStatus = "active"
	}
	s.ProcessStatus = "unhealthy"
	if probe.PID > 0 && probe.Workers == 1 {
		s.ProcessStatus = "running"
	}
	if s.Configuration == "configured" && shipperLocallyBroken(s) {
		s.Reason = "logtail_local_check_failed"
	}
	return s
}
