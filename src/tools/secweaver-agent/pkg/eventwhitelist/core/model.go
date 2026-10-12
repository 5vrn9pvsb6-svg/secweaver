// Package core defines the portable collection-rule contract. It has no file,
// network or collector dependencies; the same compiled matcher validates server
// sample tests and decides Agent events. Published revisions are immutable.
package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const Capability = "custom-event-whitelist-v1"
const AlertCapability = "custom-event-alert-v1"
const MaxPolicyBytes = 1 << 20

type Policy struct {
	SchemaVersion             int               `json:"schema_version"`
	PolicyID                  string            `json:"policy_id"`
	Revision                  int64             `json:"revision"`
	Enabled                   bool              `json:"enabled"`
	Mode                      string            `json:"mode"`
	AllowProtectedSuppression bool              `json:"allow_protected_suppression,omitempty"`
	ValidFrom                 string            `json:"valid_from,omitempty"`
	ExpiresAt                 string            `json:"expires_at,omitempty"`
	Rules                     []Rule            `json:"rules"`
	LegacyPortMigrations      map[string]string `json:"legacy_port_migrations,omitempty"`
}

type Rule struct {
	ID                        string    `json:"id"`
	Name                      string    `json:"name"`
	Description               string    `json:"description,omitempty"`
	Kind                      string    `json:"kind"`
	Enabled                   bool      `json:"enabled"`
	Mode                      string    `json:"mode"`
	Action                    string    `json:"action"`
	Priority                  int       `json:"priority"`
	Scope                     Scope     `json:"scope"`
	When                      Condition `json:"when"`
	ValidFrom                 string    `json:"valid_from,omitempty"`
	ExpiresAt                 string    `json:"expires_at,omitempty"`
	AllowProtectedSuppression bool      `json:"allow_protected_suppression,omitempty"`
	Reason                    string    `json:"reason,omitempty"`
	Alert                     *Alert    `json:"alert,omitempty"`
}

type Scope struct {
	DeviceIDs  []string `json:"device_ids,omitempty"`
	Platforms  []string `json:"platforms"`
	Modules    []string `json:"modules"`
	EventTypes []string `json:"event_types,omitempty"`
	AssetTypes []string `json:"asset_types,omitempty"`
}

type Alert struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description,omitempty"`
}

// Condition is a tagged union. Empty groups and mixed leaf/group shapes are
// rejected at compile time rather than broadening a rule accidentally.
type Condition struct {
	All           []Condition `json:"all,omitempty"`
	Any           []Condition `json:"any,omitempty"`
	Not           *Condition  `json:"not,omitempty"`
	Field         string      `json:"field,omitempty"`
	Op            string      `json:"op,omitempty"`
	Value         any         `json:"value,omitempty"`
	CaseSensitive *bool       `json:"case_sensitive,omitempty"`
}

// Event contains normalized semantic fields, not cloud enrichment. Incomplete
// fields are unknown for comparisons even when their partial value is present.
type Event struct {
	DeviceID   string          `json:"device_id,omitempty"`
	Platform   string          `json:"platform"`
	Module     string          `json:"module"`
	EventType  string          `json:"event_type"`
	AssetType  string          `json:"asset_type,omitempty"`
	Protected  bool            `json:"protected,omitempty"`
	Backfill   bool            `json:"backfill,omitempty"`
	Fields     map[string]any  `json:"fields"`
	Incomplete map[string]bool `json:"incomplete,omitempty"`
}

type Decision struct {
	Action          string `json:"action"`
	RuleID          string `json:"rule_id,omitempty"`
	Revision        int64  `json:"revision"`
	Reason          string `json:"reason"`
	PredictedAction string `json:"predicted_action,omitempty"`
	PredictedRuleID string `json:"predicted_rule_id,omitempty"`
	Alert           *Alert `json:"alert,omitempty"`
}

// Decode rejects unknown keys, duplicate keys at every nesting level and trailing
// JSON. Signing a permissively decoded document would allow validators to disagree.
func Decode(raw []byte) (Policy, error) {
	var p Policy
	if len(raw) > MaxPolicyBytes || !json.Valid(raw) {
		return p, fmt.Errorf("policy must be valid JSON within 1 MiB")
	}
	scan := json.NewDecoder(bytes.NewReader(raw))
	scan.UseNumber()
	if err := uniqueValue(scan); err != nil {
		return p, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, err
	}
	return p, nil
}

// uniqueValue consumes exactly one value. Resource bounds come from the policy
// byte limit and the JSON decoder's built-in nesting limit, before compilation.
func uniqueValue(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return fmt.Errorf("duplicate JSON key: %v", k)
			}
			seen[key] = true
			if e = uniqueValue(d); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if err := uniqueValue(d); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}

// DecodeEvent is used only by offline/HTTP sample tools, never collector output.
func DecodeEvent(r io.Reader) (Event, error) {
	var e Event
	d := json.NewDecoder(io.LimitReader(r, 1<<20))
	d.UseNumber()
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return e, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return e, fmt.Errorf("expected one event")
	}
	return e, nil
}

func parseTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, value)
}

func text(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
