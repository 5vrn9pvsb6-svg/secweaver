package main

import (
	"fmt"
	"strconv"

	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/pkg/auditportexecmon"
)

// doctorCheckLinuxBackends makes loopback coverage gaps visible without
// installing rules or claiming a local discovery check proves SLS delivery.
func doctorCheckLinuxBackends(modules []runtimeModule, add func(doctorLevel, string, string, string)) {
	for _, module := range modules {
		if module.Spec.Name != "audit-port-execmon" {
			continue
		}
		path, _ := modulecontract.StringFlag(module.Config.Args, "config")
		portText, _ := modulecontract.StringFlag(module.Config.Args, "port")
		port, _ := strconv.Atoi(portText)
		rows, err := auditportexecmon.InspectLocalBackendCoverage(path, port)
		if err != nil {
			add(doctorWarn, "exec/local-backends", "Local backend discovery is unavailable or incomplete", err.Error())
		}
		for _, row := range rows {
			level := doctorWarn
			if row.State == "eligible" {
				level = doctorOK
			}
			add(level, "exec/local-backends", "Local backend collection scope: "+row.State,
				fmt.Sprintf("address=%s port=%d pid=%d process=%s exe=%s; %s", row.Address, row.Port, row.PID, row.Process, row.Exe, row.Reason))
		}
		return
	}
}
