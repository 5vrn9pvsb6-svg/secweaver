package windowscollection

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Fixtures mimic SLS's split directory/pattern representation, so a substring
// implementation cannot accidentally satisfy these delivery regressions.
func fixture() (Manifest, map[string]any) {
	m := Manifest{Version: 1, AliUID: "123456", MachineGroup: "fleet-windows", Project: "host-project", Region: "cn-hangzhou", LogPath: "C:\\ProgramData\\SecWeaver\\Agent\\logs"}
	rules := map[string]any{}
	for _, f := range Files {
		r := Route{File: f, Logstore: "store-" + strings.TrimSuffix(f, ".log"), ConfigName: "win-" + strings.TrimSuffix(f, ".log")}
		m.Routes = append(m.Routes, r)
		rules[r.ConfigName] = map[string]any{"log_path": m.LogPath, "file_pattern": f + "*", "project_name": m.Project, "category": r.Logstore, "log_type": "json_log"}
	}
	return m, rules
}

func TestSignedContract(t *testing.T) {
	m, _ := fixture()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := json.Marshal(m)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))
	body, _ := json.Marshal(struct {
		Manifest  json.RawMessage `json:"manifest"`
		Signature string          `json:"signature"`
	}{raw, sig})
	encoded := base64.StdEncoding.EncodeToString(pub)
	if _, err := Verify(body, encoded); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{[]byte("{}"), []byte(strings.Replace(string(body), "host-project", "evil-project", 1)), append(body, byte('x'))} {
		if _, err := Verify(bad, encoded); err == nil {
			t.Fatal("invalid signature/envelope accepted")
		}
	}
	m.Routes[1] = m.Routes[0]
	if err := m.Validate(); err == nil {
		t.Fatal("duplicate route accepted")
	}
}

func TestCacheRoutes(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong-store", "wrong-project", "missing", "directory-only", "disabled", "filter", "plugin", "duplicate", "broad-overlap", "wrong-root", "malformed", "only-text", "unsupported"} {
		t.Run(scenario, func(t *testing.T) {
			m, rules := fixture()
			first := m.Routes[0]
			r := rules[first.ConfigName].(map[string]any)
			switch scenario {
			case "wrong-store":
				r["category"] = "elsewhere"
			case "wrong-project":
				r["project_name"] = "elsewhere"
			case "missing":
				delete(rules, first.ConfigName)
			case "directory-only":
				r["file_pattern"] = "something-else.log"
			case "disabled":
				r["enable"] = false
			case "filter":
				r["filter_regs"] = []string{"DROP"}
			case "plugin":
				r["plugin"] = map[string]any{"processors": []any{}}
			case "duplicate":
				rules["duplicate"] = r
			case "broad-overlap":
				rules["duplicate"] = map[string]any{"log_path": m.LogPath, "file_pattern": "*.log"}
			case "wrong-root":
				r["log_path"] = "D:\\logs"
			}
			body, _ := json.Marshal(map[string]any{"log_config": rules})
			switch scenario {
			case "malformed":
				body = []byte("{")
			case "only-text":
				body, _ = json.Marshal(map[string]any{"description": string(body)})
			case "unsupported":
				body = []byte("{\"log_config\":[]}")
			}
			missing, err := CheckCache(body, m)
			if scenario == "valid" {
				if err != nil || len(missing) > 0 {
					t.Fatalf("%v %v", missing, err)
				}
			} else if err == nil && len(missing) == 0 {
				t.Fatal("broken route accepted")
			}
		})
	}
}

// The Windows vendor cache uses metrics; check the actual wire shape and ensure
// simultaneous legacy/new envelopes cannot conceal duplicate collection rules.
func TestMetricsCache(t *testing.T) {
	for _, scenario := range []string{"metrics", "both", "invalid", "missing", "wrong-store"} {
		t.Run(scenario, func(t *testing.T) {
			m, rules := fixture()
			cache := map[string]any{"metrics": rules, "region_list": []string{m.Region}}
			switch scenario {
			case "both":
				cache["log_config"] = rules
			case "invalid":
				cache["metrics"] = []any{}
			case "missing":
				delete(rules, m.Routes[0].ConfigName)
			case "wrong-store":
				rules[m.Routes[0].ConfigName].(map[string]any)["category"] = "wrong"
			}
			body, _ := json.Marshal(cache)
			missing, err := CheckCache(body, m)
			if valid := err == nil && len(missing) == 0; valid != (scenario == "metrics") {
				t.Fatalf("missing=%v error=%v", missing, err)
			}
		})
	}
}
