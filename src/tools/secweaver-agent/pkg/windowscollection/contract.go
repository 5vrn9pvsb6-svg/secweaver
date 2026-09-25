// Package windowscollection validates the managed Windows Logtail contract.
// It does not create cloud resources or hold SLS credentials.
package windowscollection

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// Files is the version-one delivery surface, including quiet/event-driven logs.
// Requiring their rules before the first event avoids silently losing rare evidence.
var Files = []string{"windows-process-execmon.log", "windows-eventlog-risk-json.log", "host-persistence.log", "host-process-snapshot.log", "host-state-snapshot.log", "behavior-learning.log", "secweaver-agent-health.log", "secweaver-agent-update.log"}

// Route binds one file (including numeric rotations) to one physical destination.
type Route struct {
	File       string `json:"file"`
	Logstore   string `json:"logstore"`
	ConfigName string `json:"config_name"`
}

// Manifest is signed by the operator after cloud provisioning/read-back succeeds.
// It proves intended routing, not current cloud receipt or machine-group liveness.
type Manifest struct {
	Version      int     `json:"version"`
	AliUID       string  `json:"aliuid"`
	MachineGroup string  `json:"machine_group"`
	Project      string  `json:"project"`
	Region       string  `json:"region"`
	LogPath      string  `json:"log_path"`
	Routes       []Route `json:"routes"`
}

var name = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$")
var uid = regexp.MustCompile("^[0-9]{6,32}$")

// ReadBounded rejects large/special files and caps allocation even if the file grows.
func ReadBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > max {
		return nil, errors.New("invalid or oversized collection file")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("oversized collection file")
	}
	return b, err
}

// Verify authenticates the exact manifest bytes; whitespace changes invalidate
// the signature. The key is supplied by the trusted Bootstrap, never the envelope.
func Verify(body []byte, publicKey string) (Manifest, error) {
	var m Manifest
	var envelope struct {
		Manifest  json.RawMessage `json:"manifest"`
		Signature string          `json:"signature"`
	}
	if len(body) > 65536 || json.Unmarshal(body, &envelope) != nil {
		return m, errors.New("invalid collection envelope")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	sig, sigErr := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || sigErr != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, envelope.Manifest, sig) {
		return m, errors.New("collection signature invalid")
	}
	if err = json.Unmarshal(envelope.Manifest, &m); err != nil {
		return m, errors.New("invalid collection manifest")
	}
	return m, m.Validate()
}

// Validate deliberately limits v1 to exact Windows directories and eight JSON
// inputs. Filters/plugins require a separately reviewed contract version.
func (m Manifest) Validate() error {
	if m.Version != 1 || !uid.MatchString(m.AliUID) || !name.MatchString(m.MachineGroup) || !name.MatchString(m.Project) || !name.MatchString(m.Region) || len(m.Routes) != len(Files) {
		return errors.New("invalid collection manifest identity/routes")
	}
	p := NormalizePath(m.LogPath)
	if len(p) < 4 || p[0] < 'a' || p[0] > 'z' || p[1:3] != ":/" || strings.ContainsAny(p, "*?\r\n") {
		return errors.New("collection log_path must be an exact Windows directory")
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == ".." || segment == "." {
			return errors.New("collection log_path must not traverse directories")
		}
	}
	seen, configs := map[string]bool{}, map[string]bool{}
	for _, r := range m.Routes {
		if seen[r.File] || configs[r.ConfigName] || !name.MatchString(r.Logstore) || !name.MatchString(r.ConfigName) {
			return errors.New("invalid or duplicate collection route")
		}
		seen[r.File], configs[r.ConfigName] = true, true
	}
	for _, f := range Files {
		if !seen[f] {
			return fmt.Errorf("missing collection route: %s", f)
		}
	}
	return nil
}

// NormalizePath compares Windows paths independently of the CI host OS.
func NormalizePath(p string) string {
	return strings.ToLower(strings.TrimRight(strings.ReplaceAll(p, "\\", "/"), "/"))
}

// CheckCache accepts Logtail's metrics cache and the older log_config envelope.
// Both namespaces are checked together so duplicate routes cannot hide across
// versions during an upgrade. Unsupported
// plugin/newer formats fail closed instead of accepting text matches in unrelated
// fields. Directory and pattern are distinct; every match must parse JSON and
// deliver to the signed destination without filters that could drop evidence.
func CheckCache(body []byte, m Manifest) ([]string, error) {
	var cache struct {
		Configs map[string]json.RawMessage `json:"log_config"`
		Metrics map[string]json.RawMessage `json:"metrics"`
	}
	if len(body) > 4<<20 || json.Unmarshal(body, &cache) != nil || (cache.Configs == nil && cache.Metrics == nil) || len(cache.Configs)+len(cache.Metrics) > 256 {
		return nil, errors.New("unsupported or invalid Logtail cache")
	}
	type rule struct {
		Path        string          `json:"log_path"`
		Pattern     string          `json:"file_pattern"`
		Project     string          `json:"project_name"`
		Logstore    string          `json:"category"`
		Type        string          `json:"log_type"`
		Filters     []string        `json:"filter_keys"`
		FilterRegex []string        `json:"filter_regs"`
		Plugin      json.RawMessage `json:"plugin"`
		Enabled     *bool           `json:"enable"`
	}
	var rules []rule
	for _, namespace := range []map[string]json.RawMessage{cache.Configs, cache.Metrics} {
		for _, b := range namespace {
			var r rule
			if json.Unmarshal(b, &r) != nil {
				return nil, errors.New("invalid Logtail rule")
			}
			rules = append(rules, r)
		}
	}
	var missing []string
	for _, route := range m.Routes {
		matches, valid := 0, false
		for _, r := range rules {
			if !wildcard(NormalizePath(r.Path), NormalizePath(m.LogPath)) {
				continue
			}
			// Reject overlapping broad rules, including a second collector targeting
			// a different Logstore. Only the exact reviewed pattern passes readiness.
			if !wildcard(r.Pattern, route.File) {
				continue
			}
			matches++
			valid = NormalizePath(r.Path) == NormalizePath(m.LogPath) && r.Pattern == route.File+"*" && r.Project == m.Project && r.Logstore == route.Logstore && r.Type == "json_log" && len(r.Filters) == 0 && len(r.FilterRegex) == 0 && (len(r.Plugin) == 0 || string(r.Plugin) == "null" || string(r.Plugin) == "\"\"" || string(r.Plugin) == "{}") && (r.Enabled == nil || *r.Enabled)
		}
		if matches != 1 || !valid {
			missing = append(missing, route.File)
		}
	}
	return missing, nil
}

// wildcard is bounded glob matching for Windows filenames; brackets/backslashes
// are literals so Unix filepath.Match semantics cannot alter Windows behavior.
func wildcard(pattern, value string) bool {
	if len(pattern) > 256 {
		return false
	}
	p := "(?i)^" + strings.ReplaceAll(strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*"), "\\?", ".") + "$"
	return regexp.MustCompile(p).MatchString(value)
}
