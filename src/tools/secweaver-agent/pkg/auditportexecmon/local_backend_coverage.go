package auditportexecmon

import "fmt"

// LocalBackendCoverage describes read-only discovery eligibility, not proof of
// installed kernel tracking, command output, or successful cloud delivery.
type LocalBackendCoverage struct {
	State   string
	Address string
	Port    int
	PID     int
	Process string
	Exe     string
	Reason  string
}

// InspectLocalBackendCoverage checks the module's local policy and current TCP
// listeners without changing rules, tracker maps, learning or configuration.
// Discovery is bounded like runtime discovery; partial scans return an error.
func InspectLocalBackendCoverage(configPath string, portFilter int) ([]LocalBackendCoverage, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}
	return inspectLocalBackendCoverage(cfg, portFilter, listenerDiscoverySources{
		netstatCandidates: readNetstatListenerCandidates,
		socketOwners:      buildSocketInodeMapWithStats,
		procListeners:     findListenersFromProc,
		inspectProcess:    readLocalBackendProcess,
	})
}

// inspectLocalBackendCoverage recognizes only the bounded, existing backend
// family list for unsolicited warnings. Explicit selectors can name any exact
// executable. Unknown loopback services are neither included nor inventoried.
func inspectLocalBackendCoverage(cfg config, portFilter int, sources listenerDiscoverySources) ([]LocalBackendCoverage, error) {
	scan, scanErr := sources.netstatCandidates()
	needsProc := scanErr != nil || scan.TCPListenLines == 0 || scan.RejectedListenLines > 0
	for _, l := range scan.Candidates {
		if isLoopback(l.Address) && l.PID <= 1 {
			needsProc = true
		}
	}
	candidates := scan.Candidates
	if needsProc {
		owners, stats := sources.socketOwners()
		if stats.BudgetExhausted {
			return nil, fmt.Errorf("local backend coverage incomplete: procfs FD budget exhausted")
		}
		candidates = append(candidates, sources.procListeners(owners)...)
		if scanErr != nil && len(candidates) == 0 {
			return nil, fmt.Errorf("local backend listener discovery unavailable: %w", scanErr)
		}
	}
	return localBackendCoverageFromCandidates(cfg, portFilter, candidates, sources.inspectProcess)
}

// localBackendCoverageFromCandidates shares admission with runtime discovery.
// The row limit prevents doctor from generating unbounded diagnostics on hosts
// with many loopback sockets. Exclusions are reported, never overridden.
func localBackendCoverageFromCandidates(cfg config, portFilter int, candidates []listenerInfo, inspect func(int) localBackendProcess) ([]LocalBackendCoverage, error) {
	const maxRows = 128
	var rows []LocalBackendCoverage
	seen := map[string]bool{}
	matched := make([]bool, len(cfg.Exec.LocalBackendListeners))
	for _, l := range candidates {
		if !isLoopback(l.Address) {
			continue
		}
		p := inspect(l.PID)
		configured := localBackendEndpointSelected(l, cfg.Exec.LocalBackendListeners)
		known := false
		for _, backend := range webGatewayCompanionBackends {
			known = known || matchesCompanionBackend(l.Process, p.Exe, backend) || matchesCompanionBackend(p.Comm, p.Exe, backend)
		}
		if !configured && !known {
			continue
		}
		row := LocalBackendCoverage{State: "unconfigured", Address: l.Address, Port: l.Port, PID: l.PID,
			Process: l.Process, Exe: p.Exe, Reason: "loopback backend has no explicit selector; verify external-listener ancestry or configure exec.local_backend_listeners for an independent backend"}
		root, eligible := resolveLocalBackendRoot(l, cfg.Exec.LocalBackendListeners, inspect)
		for i, selector := range cfg.Exec.LocalBackendListeners {
			if localBackendEndpointSelected(l, []localBackendListener{selector}) {
				matched[i] = true
			}
		}
		if configured {
			row.State, row.Reason = "identity_mismatch", "configured endpoint has no verified matching executable/lifetime; no guessed owner is admitted"
		}
		if eligible {
			row.PID, row.Process, row.Exe = root.PID, root.Process, p.Exe
			row.State, row.Reason = "eligible", "independent backend root; discovery eligibility only, not runtime or upload proof"
			if !configMonitorExec(cfg) || !configTrackDescendants(cfg) ||
				(portFilter > 0 && portFilter != l.Port) || !portSelected(l.Port, buildPortSet(cfg.Exec.ListenerPorts)) ||
				(cfg.WhitelistPorts != nil && buildPortSet(cfg.WhitelistPorts)[l.Port]) {
				row.State, row.Reason = "policy_limited", "exec.monitor/track_descendants, -port, exec.listener_ports or legacy whitelist_ports limits backend exec coverage; signed rules may impose further exclusions"
			}
		}
		key := fmt.Sprintf("%s/%d/%d/%s", row.Address, row.Port, row.PID, row.State)
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(rows) == maxRows {
			return rows, fmt.Errorf("local backend coverage incomplete: diagnostic row limit reached")
		}
		rows = append(rows, row)
	}
	for i, selector := range cfg.Exec.LocalBackendListeners {
		if !matched[i] {
			if len(rows) == maxRows {
				return rows, fmt.Errorf("local backend coverage incomplete: diagnostic row limit reached")
			}
			rows = append(rows, LocalBackendCoverage{State: "not_listening", Address: selector.Address,
				Port: selector.Port, Exe: selector.Exe, Reason: "configured backend socket is not currently discoverable; reconciliation will retry"})
		}
	}
	return rows, nil
}
