package eventwhitelist

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"secweaver-agent/pkg/eventwhitelist/core"
	"strings"
	"sync"
	"testing"
	"time"
)

func signedFixture(t *testing.T, revision int64, action string) (core.Envelope, string, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := core.Policy{SchemaVersion: 1, PolicyID: "enterprise:PA65QE2ZWK5B4466", Revision: revision, Enabled: true, Mode: "enforce", Rules: []core.Rule{{ID: "r1", Name: "Fixture", Kind: "event_filter", Enabled: true, Mode: "enforce", Action: action, Scope: core.Scope{Platforms: []string{"linux"}, Modules: []string{"audit-port-execmon"}, EventTypes: []string{"exec"}}, When: core.Condition{Field: "/exe", Op: "eq", Value: "/usr/bin/curl"}}}}
	if action == "alert" {
		p.Rules[0].Alert = &core.Alert{Title: "fixture", Severity: "medium"}
	}
	raw, _ := json.Marshal(p)
	env, err := core.Sign(raw, "PA65QE2ZWK5B4466", "device", key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return env, base64.StdEncoding.EncodeToString(pub), key
}
func startFixture(t *testing.T, env core.Envelope, public string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "current.json")
	raw, _ := json.Marshal(env)
	if err := AtomicFile(path, raw); err != nil {
		t.Fatal(err)
	}
	t.Setenv(PolicyEnv, path)
	t.Setenv(PublicKeyEnv, public)
	t.Setenv(ModuleEnv, "audit-port-execmon")
	t.Setenv("SECWEAVER_ENTERPRISE_ID", "PA65QE2ZWK5B4466")
	t.Setenv("SECWEAVER_DEVICE_ID", "device")
	close, err := InitFromEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(close)
	active.Load().platform = "linux" // Host-independent fixture; production uses GOOS.
	return path
}

// Tampering and stale generations must never replace a valid active policy.
func TestLastGoodGenerationAndLocalEmergencyDisable(t *testing.T) {
	env, pub, key := signedFixture(t, 2, "suppress")
	path := startFixture(t, env, pub)
	event := core.Event{EventType: "exec", Fields: map[string]any{"/exe": "/usr/bin/curl"}}
	if Decide(event).Action != "suppress" {
		t.Fatal("policy not applied")
	}
	bad := env
	bad.DeviceID = "other"
	raw, _ := json.Marshal(bad)
	_ = AtomicFile(path, raw)
	active.Load().reload()
	if Decide(event).Action != "suppress" {
		t.Fatal("tampering replaced last good")
	}
	var p core.Policy
	_ = json.Unmarshal(env.Policy, &p)
	p.Revision = 1
	body, _ := json.Marshal(p)
	old, err := core.Sign(body, env.EnterpriseID, env.DeviceID, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(old)
	_ = AtomicFile(path, raw)
	active.Load().reload()
	if active.Load().current.Load().policy.Revision != 2 {
		t.Fatal("replayed revision accepted")
	}
	_ = AtomicFile(path+".disabled", []byte("disabled"))
	active.Load().reload()
	if Decide(event).Action != "pass" {
		t.Fatal("emergency disable ignored")
	}
}

// Fixed counters and immutable snapshots remain race-free under publication.
func TestConcurrentDecisionsAndRenewalPreserveCounters(t *testing.T) {
	env, pub, key := signedFixture(t, 1, "keep")
	path := startFixture(t, env, pub)
	r := active.Load()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 200; n++ {
				Decide(core.Event{EventType: "exec", Fields: map[string]any{"/exe": "/usr/bin/curl"}})
			}
		}()
	}
	renewed, err := core.Sign(env.Policy, env.EnterpriseID, env.DeviceID, key, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(renewed)
	_ = AtomicFile(path, raw)
	r.reload()
	wg.Wait()
	if n := r.current.Load().counters["r1"].kept.Load(); n != 3200 {
		t.Fatalf("renewal reset/lost counters: %d", n)
	}
}
func TestExpiryBackfillAndStaleReceipt(t *testing.T) {
	env, pub, _ := signedFixture(t, 1, "suppress")
	path := startFixture(t, env, pub)
	r := active.Load()
	e := core.Event{EventType: "exec", Fields: map[string]any{"/exe": "/usr/bin/curl"}, Backfill: true}
	if Decide(e).Action != "pass" {
		t.Fatal("historical evidence filtered")
	}
	s := r.current.Load()
	copy := *s
	copy.envelope.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	r.current.Store(&copy)
	e.Backfill = false
	if Decide(e).Action != "keep" {
		t.Fatal("expired rule filtered")
	}
	c := &Controller{config: Config{PolicyFile: path}, device: "device"}
	if c.Status(map[string]int{"audit-port-execmon": os.Getpid() + 100}).State == "applied" {
		t.Fatal("previous PID receipt trusted")
	}
}
func TestAlertQueueIsBoundedAndRedactsBeforeAdmission(t *testing.T) {
	env, pub, _ := signedFixture(t, 1, "alert")
	startFixture(t, env, pub)
	r := active.Load()
	// Pause network work by using a deliberately absent local sink; the original
	// action remains alert/keep regardless of delivery availability.
	d := Decide(core.Event{EventType: "exec", Fields: map[string]any{"/exe": "/usr/bin/curl"}})
	Alert(d, "source", "2026-10-13T00:00:00Z", map[string]any{"/command_line": "sshpass -p secret ssh host"})
	if d.Action != "alert" || r.current.Load().counters["r1"].failed.Load() != 1 {
		t.Fatal("sink failure not counted")
	}
	fields := RedactFields(map[string]any{"/command_line": "sshpass%20-p%20topsecret%20ssh%20host?token%3Dprivate", "/token": "private"})
	body, _ := json.Marshal(fields)
	if strings.Contains(string(body), "topsecret") || strings.Contains(string(body), "private") {
		t.Fatal("secret survived alert redaction")
	}
}
func TestPrivateAtomicFileAndBoundedSymlinkRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy")
	if err := AtomicFile(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	alias := path + ".link"
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBounded(alias, 128); err == nil {
		t.Fatal("symlink accepted")
	}
}

// A successful local queue receipt means the single rotating writer has
// checkpointed a redacted, tenant-bound alert; it does not prove cloud delivery.
func TestAlertSinkWritesBoundIdentityAndRiskFields(t *testing.T) {
	env, pub, _ := signedFixture(t, 1, "alert")
	t.Setenv("SECWEAVER_ENTERPRISE_ID", env.EnterpriseID)
	t.Setenv("SECWEAVER_HOST_NAME", "fixture-host")
	t.Setenv("SECWEAVER_HOST_IP", "192.0.2.91")
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-risk-alert.log")
	c, closeSink, err := Start(Config{AlertOutput: path}, dir, dir, env.EnterpriseID, env.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeSink)
	t.Setenv(AlertURLEnv, c.url)
	t.Setenv(AlertTokenEnv, c.token)
	startFixture(t, env, pub)
	d := Decide(core.Event{EventType: "exec", Fields: map[string]any{"/exe": "/usr/bin/curl"}})
	Alert(d, "audit:fixture", "2026-10-13T01:00:00Z", map[string]any{"/severity": "high", "/command_line": "sshpass -p private ssh fixture"})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		body, _ := os.ReadFile(path)
		if len(body) > 0 {
			var record map[string]any
			if err := json.Unmarshal(body, &record); err != nil {
				t.Fatal(err)
			}
			if record["enterprise_id"] != env.EnterpriseID || record["host_ip"] != "192.0.2.91" || record["source_evidence_id"] != "audit:fixture" || record["risk_level"] != "high" || strings.Contains(string(body), "private") {
				t.Fatalf("invalid alert: %s", body)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("local alert sink did not checkpoint")
}
