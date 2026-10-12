package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Envelope signs the exact policy bytes plus their tenant/device binding. Its
// purpose domain prevents a release/config signature being reused as a rule.
type Envelope struct {
	Purpose      string          `json:"purpose"`
	EnterpriseID string          `json:"enterprise_id"`
	DeviceID     string          `json:"device_id"`
	Revision     int64           `json:"revision"`
	Digest       string          `json:"digest"`
	IssuedAt     string          `json:"issued_at"`
	ExpiresAt    string          `json:"expires_at"`
	Policy       json.RawMessage `json:"policy"`
	Signature    string          `json:"signature"`
}

func Digest(b []byte) string                { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (e Envelope) message() ([]byte, error) { e.Signature = ""; return json.Marshal(e) }

// Sign creates a short-lived per-device envelope. It never mutates a published
// policy or changes its revision when renewing the transport signature.
func Sign(raw []byte, eid, device string, key ed25519.PrivateKey, now time.Time) (Envelope, error) {
	p, err := Decode(raw)
	if err != nil {
		return Envelope{}, err
	}
	if _, err = Compile(p); err != nil {
		return Envelope{}, err
	}
	// Canonicalize before hashing: JSONB storage and JSON response encoding may
	// otherwise change whitespace/escaping without changing the policy value.
	raw, err = json.Marshal(p)
	if err != nil {
		return Envelope{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("collection signing key unavailable")
	}
	end := now.Add(24 * time.Hour)
	if p.ExpiresAt != "" {
		t, _ := parseTime(p.ExpiresAt)
		if t.Before(end) {
			end = t
		}
	}
	e := Envelope{Purpose: "secweaver-collection-rules-v1", EnterpriseID: eid, DeviceID: device, Revision: p.Revision, Digest: Digest(raw), IssuedAt: now.UTC().Format(time.RFC3339), ExpiresAt: end.UTC().Format(time.RFC3339), Policy: raw}
	b, _ := e.message()
	e.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))
	return e, nil
}

// Verify rejects replay to another identity, future signatures and expiry. A
// renewed envelope may retain the revision only when its content digest agrees.
func (e Envelope) Verify(public, eid, device string, now time.Time) (Policy, error) {
	var zero Policy
	key, err := base64.StdEncoding.DecodeString(public)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("invalid collection public key")
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return zero, fmt.Errorf("invalid collection signature")
	}
	issued, err := parseTime(e.IssuedAt)
	end, err2 := parseTime(e.ExpiresAt)
	if err != nil || err2 != nil || issued.IsZero() || end.IsZero() || issued.After(now.Add(5*time.Minute)) || !end.After(issued) || end.Sub(issued) > 24*time.Hour || !now.Before(end) || e.Purpose != "secweaver-collection-rules-v1" || e.EnterpriseID != eid || e.DeviceID != device || e.Digest != Digest(e.Policy) {
		return zero, fmt.Errorf("collection binding/time/digest invalid")
	}
	b, _ := e.message()
	if !ed25519.Verify(key, b, sig) {
		return zero, fmt.Errorf("collection signature rejected")
	}
	p, err := Decode(e.Policy)
	if err != nil {
		return zero, err
	}
	if p.Revision != e.Revision {
		return zero, fmt.Errorf("collection revision mismatch")
	}
	_, err = Compile(p)
	return p, err
}
