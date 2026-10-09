package behaviorlearning

import (
	"encoding/json"
	"time"
)

// Context is an adapter-verified behavior. Installed adapters use the exact
// Exec/File/Network/Risk tuples; legacy fields remain for checkpoint compatibility.
type Context struct {
	// Exec is the complete four-field contract. It excludes process
	// instance and credential enrichment, including when those fields are known.
	Exec       *ExecFields    `json:"exec_fields,omitempty"`
	File       *FileFields    `json:"file_fields,omitempty"`
	Network    *NetworkFields `json:"network_fields,omitempty"`
	Service    string         `json:"service"`
	Parent     string         `json:"parent"`
	Executable string         `json:"executable"`
	Digest     string         `json:"digest"`
	Args       []string       `json:"argv"`
	CWD        string         `json:"cwd"`
	UID        string         `json:"uid"`
	EUID       string         `json:"euid"`
	GID        string         `json:"gid"`
	EGID       string         `json:"egid"`
	AUID       string         `json:"auid"`
	Session    string         `json:"session"`
	Capability string         `json:"capability"`
	// Windows is retained only for the legacy identity-based contract.
	Windows *WindowsContext `json:"windows,omitempty"`
	// Operation is absent for exec, preserving existing execution fingerprints.
	Operation *Operation `json:"operation,omitempty"`
	// Risk uses native Event Log identity, not invented Sysmon process ancestry.
	// Omission preserves all existing execution/network/file fingerprints.
	Risk *WindowsRiskContext `json:"windows_risk,omitempty"`
}

// ExecFields is an exact string tuple; no case, whitespace or argument folding
// is allowed. Only its keyed fingerprint is persisted, never CommandLine.
type ExecFields struct {
	ListenerProcess string `json:"listener_process"`
	PIDName         string `json:"pid_name"`
	Exe             string `json:"exe"`
	CommandLine     string `json:"command_line"`
}

// FileFields extends the exact execution tuple with the ordered path array.
// It deliberately excludes action, PID, user and wildcard/normalized paths.
type FileFields struct {
	ExecFields
	FilePaths []string `json:"file_paths"`
}

// NetworkFields uses the exact process tuple and remote endpoint. Numeric PID,
// source port and process GUID correlate evidence but are not behavior keys.
type NetworkFields struct {
	ExecFields
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
}

// WindowsRiskContext binds a complete script to its exact origin and content.
// Fragment IDs and process IDs group evidence but are not stable match keys.
type WindowsRiskContext struct {
	Provider     string `json:"provider"`
	Channel      string `json:"channel"`
	UserSID      string `json:"user_sid"`
	Path         string `json:"path"`
	ModuleClass  string `json:"module_class"`
	ScriptSHA256 string `json:"script_sha256"`
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

// Entry holds bounded candidate evidence, then immutable promotion evidence.
// Samples omit argv; HMACs match commands without storing their credentials.
type Entry struct {
	// Recent holds at most five reception times while a simple candidate learns.
	// Promoted entries discard it; low-frequency later hits remain allowed.
	Recent      []time.Time    `json:"recent,omitempty"`
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

// State is a checkpoint, not an event log. Only Store may commit it. Legacy rate
// counters need restart warm-up; the simple strategy restores exact entries.
type State struct {
	Strategy string `json:"strategy,omitempty"`
	// Seen contains HMAC source IDs for the simple policy's one-hour dedup window.
	// Legacy checkpoints omit it, preserving their serialization and semantics.
	Seen           map[string]time.Time `json:"seen,omitempty"`
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
