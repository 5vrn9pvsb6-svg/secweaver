package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// doctorCheckSLSIdentity reports local Logtail runtime/identity separately from
// cloud receipt, which requires a server-side query. An installer intent marker
// makes interrupted SLS setup visible without imposing SLS identity on ES hosts.
func doctorCheckSLSIdentity(cfg agentConfig, configPath string, add func(doctorLevel, string, string, string)) {
	if cfg.DeploymentMode == deploymentES {
		status := detectOperationsShipper(cfg.DeploymentMode, configPath)
		level := doctorWarn
		if status.Configuration == "configured" {
			level = doctorOK
		}
		add(level, "shipper/config", "ES delivery configuration", status.Type+": "+status.Configuration)
		add(doctorWarn, "shipper/cloud_delivery", "ES delivery is unverified", "Check shipper runtime and recent host events in the target ES/OpenSearch cluster")
		return
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		add(doctorOK, "logtail", "SLS Logtail identity check skipped on non-Linux platform", runtime.GOOS)
		return
	}
	status := detectOperationsShipper(cfg.DeploymentMode, configPath)
	if status.Type != "logtail" {
		add(doctorWarn, "logtail", "SLS Logtail not detected; delivery is unverified", "For ES, use shipper diagnostics; for SLS, complete bootstrap Logtail setup")
		return
	}
	level := doctorOK
	if shipperLocallyBroken(status) {
		level = doctorError
	} else if status.ServiceStatus == "unknown" || status.ProcessStatus == "unknown" {
		level = doctorWarn
	}
	add(level, "logtail/runtime", "Logtail local runtime check", fmt.Sprintf("service=%s state=%s processes=%s reason=%s", status.Service, status.ServiceStatus, status.ProcessStatus, status.Reason))
	if runtime.GOOS == "windows" {
		collectionLevel := doctorError
		if status.Configuration == "configured" {
			collectionLevel = doctorOK
		}
		add(collectionLevel, "logtail/collection", "Signed Windows collection contract and delivered rules", fmt.Sprintf("state=%s cache=%s missing_or_conflicting=%s reason=%s", status.Configuration, status.ConfigPath, strings.Join(status.MissingPaths, ","), status.Reason))
	}
	add(doctorWarn, "logtail/cloud_delivery", "SLS cloud delivery is unverified", "Local service/identity cannot prove Logstore delivery; verify machine-group heartbeat, collection binding and recent host events in SLS")

	configDir := "/etc/ilogtail"
	if runtime.GOOS == "windows" {
		configDir = `C:\LogtailData`
	}
	users, _ := filepath.Glob(filepath.Join(configDir, "users", "*"))
	if len(users) == 0 {
		add(doctorError, "logtail/aliuid", "Logtail AliUid identity file is missing", filepath.Join(configDir, "users", "<aliuid>"))
	} else {
		names := make([]string, 0, len(users))
		for _, path := range users {
			names = append(names, filepath.Base(path))
		}
		sort.Strings(names)
		add(doctorOK, "logtail/aliuid", "Logtail AliUid identity file exists", strings.Join(names, ","))
	}

	enrollment, err := os.ReadFile(filepath.Join(configDir, "user_defined_id"))
	if err != nil {
		add(doctorError, "logtail/enrollment_id", "custom identifier machine-group file is missing", filepath.Join(configDir, "user_defined_id"))
		return
	}
	value := strings.TrimSpace(string(enrollment))
	if value == "" {
		add(doctorError, "logtail/enrollment_id", "custom identifier machine-group file is empty", filepath.Join(configDir, "user_defined_id"))
		return
	}
	expected := strings.TrimSpace(cfg.License.EnrollmentID)
	// Windows uses its own SLS machine group, independent of legacy license IDs.
	if runtime.GOOS == "linux" && expected != "" && value != expected {
		add(doctorWarn, "logtail/enrollment_id", "Logtail enrollment ID differs from Agent license enrollment ID", fmt.Sprintf("logtail=%s agent=%s", value, expected))
		return
	}
	add(doctorOK, "logtail/enrollment_id", "custom identifier machine-group file is configured", value)
}
