package core

// Status contains bounded operational metadata only. Rule values, sample events
// and commands never travel in the device inventory heartbeat.
type Status struct {
	Revision          int64                   `json:"revision"`
	Digest            string                  `json:"digest,omitempty"`
	State             string                  `json:"state"`
	Error             string                  `json:"error,omitempty"`
	UpdatedAt         string                  `json:"updated_at,omitempty"`
	Modules           map[string]ModuleStatus `json:"modules,omitempty"`
	EnvelopeExpiresAt string                  `json:"envelope_expires_at,omitempty"`
	LegacyPorts       []int                   `json:"legacy_ports,omitempty"`
	LegacyPortsDigest string                  `json:"legacy_ports_digest,omitempty"`
}
type ModuleStatus struct {
	Revision  int64             `json:"revision"`
	Digest    string            `json:"digest,omitempty"`
	State     string            `json:"state"`
	Error     string            `json:"error,omitempty"`
	ProcessID int               `json:"process_id"`
	UpdatedAt string            `json:"updated_at"`
	Counts    map[string]Counts `json:"counts,omitempty"`
}
type Counts struct {
	Matched       uint64 `json:"matched"`
	Observed      uint64 `json:"observed"`
	Suppressed    uint64 `json:"suppressed"`
	Kept          uint64 `json:"kept"`
	Passed        uint64 `json:"passed"`
	AlertsQueued  uint64 `json:"alerts_queued"`
	AlertFailures uint64 `json:"alert_failures"`
}

// ValidStatus refuses arbitrary nested maps and stale/unbounded diagnostics.
// Time validity is checked structurally; receipt success remains an Agent claim,
// distinct from independently verified cloud log delivery.
func ValidStatus(s *Status) bool {
	if s == nil {
		return true
	}
	if s.Revision < 0 || len(s.Digest) > 64 || len(s.Error) > 128 || len(s.State) > 32 || len(s.Modules) > 5 {
		return false
	}
	if len(s.LegacyPorts) > 65535 || s.LegacyPortsDigest != "" && (len(s.LegacyPortsDigest) != 64 || !allHex(s.LegacyPortsDigest)) {
		return false
	}
	for _, port := range s.LegacyPorts {
		if port < 1 || port > 65535 {
			return false
		}
	}
	if s.EnvelopeExpiresAt != "" {
		if _, err := parseTime(s.EnvelopeExpiresAt); err != nil {
			return false
		}
	}
	if s.Digest != "" && (len(s.Digest) != 64 || !allHex(s.Digest)) {
		return false
	}
	if s.UpdatedAt != "" {
		if _, err := parseTime(s.UpdatedAt); err != nil {
			return false
		}
	}
	for name, m := range s.Modules {
		if _, ok := Catalog[name]; !ok {
			return false
		}
		if m.Revision < 0 || len(m.Digest) > 64 || len(m.State) > 32 || len(m.Error) > 128 || m.ProcessID < 0 || len(m.Counts) > 256 {
			return false
		}
		if m.Digest != "" && (len(m.Digest) != 64 || !allHex(m.Digest)) {
			return false
		}
		if _, err := parseTime(m.UpdatedAt); err != nil {
			return false
		}
		for id := range m.Counts {
			if !text(id, 128) {
				return false
			}
		}
	}
	return true
}
func allHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
