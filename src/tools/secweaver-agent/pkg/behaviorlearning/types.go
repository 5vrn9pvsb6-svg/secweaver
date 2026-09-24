package behaviorlearning

import (
	"encoding/json"
	"time"
)

// Context is an adapter-verified canonical behavior. Instance IDs are explicitly
// excluded from Fingerprint; adapters must verify them before setting Complete.
type Context struct {
	Service    string   `json:"service"`
	Parent     string   `json:"parent"`
	Executable string   `json:"executable"`
	Digest     string   `json:"digest"`
	Args       []string `json:"argv"`
	CWD        string   `json:"cwd"`
	UID        string   `json:"uid"`
	EUID       string   `json:"euid"`
	GID        string   `json:"gid"`
	EGID       string   `json:"egid"`
	AUID       string   `json:"auid"`
	Session    string   `json:"session"`
	Capability string   `json:"capability"`
	// Omission preserves Linux fingerprints; Windows never invents Unix credentials.
	Windows *WindowsContext `json:"windows,omitempty"`
	// Operation is absent for exec, preserving existing execution fingerprints.
	Operation *Operation `json:"operation,omitempty"`
}

// Operation separates network/file matching from exec and includes the exact
// target. No PID, ephemeral source port, wildcard path or subnet is a match key.
type Operation struct {
	EventType     string `json:"event_type"`
	Action        string `json:"action"`
	Protocol      string `json:"protocol,omitempty"`
	SourceAddress string `json:"source_address,omitempty"`
	Address       string `json:"address,omitempty"`
	Port          int    `json:"port,omitempty"`
	Path          string `json:"path,omitempty"`
}

// WindowsContext binds a Sysmon execution to a noninteractive service token.
type WindowsContext struct {
	User       string `json:"user"`
	ParentUser string `json:"parent_user"`
	Integrity  string `json:"integrity"`
	LogonID    string `json:"logon_id"`
	SessionID  string `json:"session_id"`
}

// Observation owns its payload and verified evidence; no pooled parser memory
// may be retained. Unknown/always-emit records still pass through Process.
type Observation struct {
	Context        Context
	Complete       bool
	Reason         string
	EventID        string
	Instance       string
	ParentInstance string
	Raw            json.RawMessage
	At             time.Time
}

// Entry contains immutable promotion evidence. Samples intentionally omit argv:
// the HMAC retains exact matching without persisting command-line credentials.
type Entry struct {
	EventType   string         `json:"source_event_type,omitempty"`
	Fingerprint string         `json:"behavior_fingerprint"`
	Executable  string         `json:"executable"`
	Count       uint64         `json:"observed_count"`
	First       float64        `json:"first_healthy_second"`
	Last        float64        `json:"last_healthy_second"`
	Hours       map[int]bool   `json:"hour_buckets"`
	Buckets     map[int]uint32 `json:"five_minute_buckets,omitempty"`
	Limit       uint64         `json:"max_events_per_window"`
}

// State is a checkpoint, not an event log. Only Store may commit it. Runtime
// rate counters are not trusted across restart; a warm-up window restores them.
type State struct {
	Version        int                  `json:"schema_version"`
	CleanShutdown  bool                 `json:"clean_shutdown"`
	Device         string               `json:"device_id"`
	Policy         string               `json:"policy_hash"`
	Generation     uint64               `json:"generation"`
	BaselineID     string               `json:"baseline_id"`
	Mode           string               `json:"mode"`
	Reason         string               `json:"reason,omitempty"`
	HealthySeconds float64              `json:"healthy_seconds"`
	OnlineSeconds  float64              `json:"online_seconds"`
	Started        time.Time            `json:"started_at"`
	Entries        map[string]*Entry    `json:"entries"`
	Candidates     map[string]*Entry    `json:"candidates"`
	LastSeen       map[string]time.Time `json:"last_seen"`
}

// Summary deliberately has no PID: aggregate counts must not become process
// graph edges. Counts refer only to this qualified behavior's unique inputs.
type Summary struct {
	SourceEventType string    `json:"source_event_type,omitempty"`
	Time            time.Time `json:"time"`
	EventType       string    `json:"event_type"`
	AssetType       string    `json:"asset_type"`
	SourceHealthy   bool      `json:"source_healthy"`
	FilteringActive bool      `json:"filtering_active"`
	Shadow          bool      `json:"shadow"`
	DeviceID        string    `json:"device_id"`
	BaselineID      string    `json:"baseline_id"`
	Fingerprint     string    `json:"behavior_fingerprint,omitempty"`
	SummaryID       string    `json:"summary_id"`
	WindowStart     time.Time `json:"window_start"`
	WindowEnd       time.Time `json:"window_end"`
	Observed        uint64    `json:"observed_count"`
	Suppressed      uint64    `json:"suppressed_count"`
	Emitted         uint64    `json:"original_emitted_count"`
	Replayed        uint64    `json:"context_reemitted_count"`
	Complete        bool      `json:"counter_complete"`
	Mode            string    `json:"learning_state"`
	Reason          string    `json:"reason,omitempty"`
	HealthySeconds  float64   `json:"healthy_seconds"`
	Entries         int       `json:"baseline_entries"`
	Candidates      int       `json:"candidate_entries"`
}
