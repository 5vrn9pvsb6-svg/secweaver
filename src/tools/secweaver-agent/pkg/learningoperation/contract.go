// Package learningoperation defines the bounded, purpose-separated wire contract
// for an additional learning window. It cannot describe commands or file paths.
package learningoperation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

const (
	Capability     = "behavior-relearning-v1"
	Purpose        = "secweaver-behavior-relearning-v1"
	HealthySeconds = 86400
	MaxGrantBytes  = 16 << 10
)

// Target binds one independently owned engine to its exact baseline identity.
type Target struct {
	Stream        string `json:"stream"`
	BaselineToken string `json:"expected_baseline_token"`
}

// Grant is a start permission, not proof of a started/completed operation.
// Sequence is decimal text to avoid JavaScript's 53-bit integer limit.
type Grant struct {
	Purpose         string    `json:"purpose"`
	OperationID     string    `json:"operation_id"`
	Sequence        string    `json:"sequence"`
	EnterpriseID    string    `json:"enterprise_id"`
	DeviceID        string    `json:"device_id"`
	InstallationID  string    `json:"installation_id"`
	IssuedAt        time.Time `json:"issued_at"`
	StartBefore     time.Time `json:"start_before"`
	RunNotAfter     time.Time `json:"run_not_after"`
	DurationSeconds int       `json:"duration_seconds"`
	Targets         []Target  `json:"targets"`
	Digest          string    `json:"digest"`
	Signature       string    `json:"signature"`
}

// StreamResult contains durable facts only, never commands or fingerprints.
type StreamResult struct {
	State            string    `json:"state"`
	Reason           string    `json:"reason,omitempty"`
	StartedAt        time.Time `json:"started_at,omitempty"`
	HealthySeconds   int64     `json:"healthy_seconds"`
	RemainingSeconds int64     `json:"remaining_seconds"`
	RetainedEntries  int       `json:"retained_entries"`
	AddedEntries     int       `json:"added_entries"`
}

// Receipt is monotonically revised by the coordinator from persisted engines.
type Receipt struct {
	OperationID string                  `json:"operation_id"`
	Sequence    string                  `json:"sequence"`
	Revision    string                  `json:"receipt_revision"`
	State       string                  `json:"state"`
	Streams     map[string]StreamResult `json:"streams"`
}

// Progress is the checkpoint-derived public result, excluding local clock
// bases and recovery material.
type Progress struct {
	OperationID string       `json:"operation_id"`
	Sequence    string       `json:"sequence"`
	Result      StreamResult `json:"result"`
}

// Snapshot exposes readiness and an opaque baseline identity, never entries.
type Snapshot struct {
	BaselineToken string `json:"baseline_token"`
	Eligible      bool   `json:"eligible"`
	Reason        string `json:"reason"`
}

// Report is optional full-heartbeat telemetry. Four leaves explicitly include
// disabled streams; old clients omit this object and receive no new delivery.
type Report struct {
	Capability string              `json:"capability"`
	Streams    map[string]Snapshot `json:"streams"`
	Receipt    *Receipt            `json:"receipt,omitempty"`
}

// ValidReport bounds optional data without making it license authority.
func ValidReport(r *Report) bool {
	if r == nil || r.Capability != Capability || len(r.Streams) != 4 {
		return false
	}
	for k, v := range r.Streams {
		if !StreamKnown(k) || len(v.Reason) > 128 || (v.BaselineToken != "" && !tokenOK(v.BaselineToken)) || (v.Eligible && !tokenOK(v.BaselineToken)) {
			return false
		}
	}
	if r.Receipt != nil {
		v := r.Receipt
		if !identityOK(v.OperationID) {
			return false
		}
		if _, err := SequenceValue(v.Sequence); err != nil {
			return false
		}
		if _, err := SequenceValue(v.Revision); err != nil {
			return false
		}
		if len(v.Streams) < 1 || len(v.Streams) > 4 {
			return false
		}
		for k, p := range v.Streams {
			if !StreamKnown(k) || len(p.Reason) > 128 || p.HealthySeconds < 0 || p.HealthySeconds > HealthySeconds || p.RemainingSeconds != HealthySeconds-p.HealthySeconds ||
				p.RetainedEntries < 0 || p.RetainedEntries > 10000 || p.AddedEntries < 0 || p.AddedEntries > 10000 {
				return false
			}
			switch p.State {
			case "pending", "learning", "completed", "failed", "rejected", "expired":
			default:
				return false
			}
			if (p.State == "learning" || p.State == "completed") && p.StartedAt.IsZero() {
				return false
			}
			if p.State == "completed" && p.HealthySeconds != HealthySeconds {
				return false
			}
		}
	}
	b, err := json.Marshal(r)
	return err == nil && len(b) <= 8192
}

// SequenceValue accepts only canonical positive signed-bigint decimal strings.
func SequenceValue(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != s {
		return 0, fmt.Errorf("invalid operation sequence")
	}
	return n, nil
}

func StreamKnown(s string) bool { return s == "exec" || s == "file" || s == "network" || s == "risk" }
func tokenOK(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == hex.EncodeToString(b)
}
func identityOK(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

// contentDigest excludes transport-renewal timestamps/signature. A renewed
// start permission for the same operation cannot silently change its targets.
func (g Grant) contentDigest() string {
	g.IssuedAt, g.StartBefore = time.Time{}, time.Time{}
	g.Digest, g.Signature = "", ""
	b, _ := json.Marshal(g)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (g Grant) message() []byte { g.Signature = ""; b, _ := json.Marshal(g); return b }

// Validate checks structure and maximum lifetimes independently of wall time.
// Signature-only verification is needed to recover an already-started window
// after the 30-second start permission has expired; it never starts a new one.
func (g Grant) Validate() error {
	_, seqErr := SequenceValue(g.Sequence)
	if g.Purpose != Purpose || seqErr != nil || !identityOK(g.OperationID) ||
		!identityOK(g.EnterpriseID) || !identityOK(g.DeviceID) || !identityOK(g.InstallationID) ||
		g.DurationSeconds != HealthySeconds || len(g.Targets) < 1 || len(g.Targets) > 4 ||
		g.IssuedAt.IsZero() || !g.StartBefore.After(g.IssuedAt) || g.StartBefore.Sub(g.IssuedAt) > 30*time.Second ||
		!g.RunNotAfter.After(g.StartBefore) || g.RunNotAfter.Sub(g.IssuedAt) > 8*24*time.Hour ||
		g.Digest != g.contentDigest() {
		return fmt.Errorf("invalid relearning grant")
	}
	seen := map[string]bool{}
	for _, t := range g.Targets {
		if !StreamKnown(t.Stream) || !tokenOK(t.BaselineToken) || seen[t.Stream] {
			return fmt.Errorf("invalid relearning target")
		}
		seen[t.Stream] = true
	}
	return nil
}

// Sign fixes the purpose/digest then signs all grant fields with the existing
// collection key. Distinct purpose and message shape prohibit cross-use.
func Sign(g Grant, key ed25519.PrivateKey) (Grant, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Grant{}, fmt.Errorf("relearning signing key unavailable")
	}
	g.Purpose = Purpose
	g.Signature = ""
	g.Digest = g.contentDigest()
	if err := g.Validate(); err != nil {
		return Grant{}, err
	}
	g.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, g.message()))
	return g, nil
}

// VerifyIdentity validates authenticated content even after start expiry. The
// engine must also call CanStart before opening any new window.
func (g Grant) VerifyIdentity(public, eid, device, installation string) error {
	key, e := base64.StdEncoding.DecodeString(public)
	sig, e2 := base64.StdEncoding.DecodeString(g.Signature)
	if e != nil || e2 != nil || len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize ||
		g.EnterpriseID != eid || g.DeviceID != device || g.InstallationID != installation {
		return fmt.Errorf("relearning identity/signature invalid")
	}
	if err := g.Validate(); err != nil {
		return err
	}
	if !ed25519.Verify(key, g.message(), sig) {
		return fmt.Errorf("relearning signature rejected")
	}
	return nil
}

// CanStart deliberately has no clock-skew grace extending the signed deadline.
func (g Grant) CanStart(now time.Time) bool {
	return !now.Before(g.IssuedAt) && now.Before(g.StartBefore) && now.Before(g.RunNotAfter)
}

// Decode rejects oversized, unknown-field and duplicate-key inputs before they
// can become persisted inbox data. Normal JSON decoders otherwise accept the
// last duplicate, making signed bytes and interpreted values ambiguous.
func Decode(raw []byte) (Grant, error) {
	var g Grant
	if len(raw) == 0 || len(raw) > MaxGrantBytes {
		return g, fmt.Errorf("relearning grant size invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueJSON(d); err != nil {
		return g, err
	}
	if _, err := d.Token(); err != io.EOF {
		return g, fmt.Errorf("trailing relearning input")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&g); err != nil {
		return Grant{}, err
	}
	return g, g.Validate()
}

// uniqueJSON is bounded by the protocol's shallow structure and byte limit;
// depth is checked explicitly so malicious nesting cannot exhaust the stack.
func uniqueJSON(d *json.Decoder) error { return uniqueValue(d, 0) }
func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 8 {
		return fmt.Errorf("relearning nesting limit")
	}
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return fmt.Errorf("invalid relearning JSON")
	}
	keys := map[string]bool{}
	for d.More() {
		if delim == '{' {
			k, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := k.(string)
			if !ok || keys[name] {
				return fmt.Errorf("duplicate relearning key")
			}
			keys[name] = true
		}
		if err := uniqueValue(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}
