package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// probeLogtail separates identity, service, process and delivery evidence. The
// upstream service is often Type=oneshot with active(exited), so its init status
// must also confirm the collector daemon/worker pair. All subprocesses are
// bounded, read-only and invoked without a shell. No SLS credentials are needed.
func probeLogtail(configDir, binaryDir, initDir string, expected bool, run func(time.Duration, string, ...string) ([]byte, error)) operationsShipper {
	s := operationsShipper{Type: "unknown", Configuration: "not_detected", ServiceStatus: "unknown", ProcessStatus: "unknown", CloudDelivery: "unverified", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if !expected && !pathExists(configDir) && !pathExists(binaryDir) {
		return s
	}
	s.Type = "logtail"
	s.Reason = "cloud_receipt_requires_server_side_verification"
	if !pathExists(binaryDir) {
		s.ServiceStatus, s.ProcessStatus, s.Reason = "missing", "missing", "expected_logtail_not_installed"
		return s
	}
	s.Configuration = "identity_missing"
	users, _ := filepath.Glob(filepath.Join(configDir, "users", "*"))
	hasAccount := false
	for _, user := range users {
		if info, err := os.Stat(user); err == nil && info.Mode().IsRegular() {
			hasAccount = true
			break
		}
	}
	identity, err := os.ReadFile(filepath.Join(configDir, "user_defined_id"))
	if err == nil && strings.TrimSpace(string(identity)) != "" && hasAccount {
		s.Configuration = "configured"
	}
	for _, name := range []string{"loongcollectord", "ilogtaild"} {
		script := filepath.Join(initDir, name)
		// systemd 219 (CentOS 7) has no --value option.
		state, stateErr := run(3*time.Second, "systemctl", "show", "-p", "LoadState", name+".service")
		loaded := stateErr == nil && strings.TrimSpace(string(state)) == "LoadState=loaded"
		scriptInfo, scriptErr := os.Stat(script)
		hasScript := scriptErr == nil && scriptInfo.Mode().IsRegular() && scriptInfo.Mode().Perm()&0111 != 0
		if !loaded && !hasScript {
			continue
		}
		s.Service = name
		if loaded {
			state, stateErr = run(3*time.Second, "systemctl", "is-active", name+".service")
			s.ServiceStatus = "unknown"
			switch strings.TrimSpace(string(state)) {
			case "active":
				if stateErr == nil {
					s.ServiceStatus = "active"
				}
			case "inactive", "failed", "activating", "deactivating":
				s.ServiceStatus = strings.TrimSpace(string(state))
			}
		} else {
			s.ServiceStatus = "unmanaged"
		}
		if hasScript {
			_, err = run(5*time.Second, script, "status")
			if err == nil {
				s.ProcessStatus = "running"
			} else {
				s.ProcessStatus = "unhealthy"
			}
		}
		if shipperLocallyBroken(s) {
			s.Reason = "logtail_local_check_failed"
		}
		return s
	}
	s.ServiceStatus, s.ProcessStatus, s.Reason = "missing", "unknown", "logtail_service_not_found"
	return s
}

// Unknown delivery is deliberately not treated as proof of loss or success.
// Only observable local defects degrade the Agent health snapshot.
func shipperLocallyBroken(s operationsShipper) bool {
	if s.Type != "logtail" {
		return false
	}
	return s.Configuration != "configured" || s.ProcessStatus == "missing" || s.ProcessStatus == "unhealthy" || s.ServiceStatus == "missing" || s.ServiceStatus == "inactive" || s.ServiceStatus == "failed" || s.ServiceStatus == "deactivating" || s.ServiceStatus == "unmanaged"
}
