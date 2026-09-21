package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// doctorCheckSLSIdentity validates only the Alibaba Cloud Logtail identity.
// Native ES/Filebeat/Fluent Bit diagnostics are owned by the private ES
// Operator, so the public Agent never treats an unrelated collector directory
// as an SLS enrollment requirement.
func doctorCheckSLSIdentity(cfg agentConfig, add func(doctorLevel, string, string, string)) {
	if runtime.GOOS != "linux" {
		add(doctorOK, "logtail", "SLS Logtail identity check skipped on non-Linux platform", runtime.GOOS)
		return
	}
	if !pathExists("/etc/ilogtail") && !pathExists("/usr/local/ilogtail") {
		add(doctorOK, "logtail", "SLS Logtail identity check skipped", "native ES shipper diagnostics are provided by secweaver-shipper doctor")
		return
	}

	add(doctorOK, "logtail/mode", "SLS Logtail/LoongCollector installation detected", "/etc/ilogtail or /usr/local/ilogtail")
	users, _ := filepath.Glob("/etc/ilogtail/users/*")
	if len(users) == 0 {
		add(doctorError, "logtail/aliuid", "Logtail AliUid identity file is missing", "/etc/ilogtail/users/<aliuid>")
	} else {
		names := make([]string, 0, len(users))
		for _, path := range users {
			names = append(names, filepath.Base(path))
		}
		sort.Strings(names)
		add(doctorOK, "logtail/aliuid", "Logtail AliUid identity file exists", strings.Join(names, ","))
	}

	enrollment, err := os.ReadFile("/etc/ilogtail/user_defined_id")
	if err != nil {
		add(doctorError, "logtail/enrollment_id", "custom identifier machine-group file is missing", "/etc/ilogtail/user_defined_id")
		return
	}
	value := strings.TrimSpace(string(enrollment))
	if value == "" {
		add(doctorError, "logtail/enrollment_id", "custom identifier machine-group file is empty", "/etc/ilogtail/user_defined_id")
		return
	}
	expected := strings.TrimSpace(cfg.License.EnrollmentID)
	if expected != "" && value != expected {
		add(doctorWarn, "logtail/enrollment_id", "Logtail enrollment ID differs from Agent license enrollment ID", fmt.Sprintf("logtail=%s agent=%s", value, expected))
		return
	}
	add(doctorOK, "logtail/enrollment_id", "custom identifier machine-group file is configured", value)
}
