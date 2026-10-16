package learningoperation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Controlled transport times exercise expiry without granting clock-skew grace.
func TestGrantSignatureBindingRenewalAndStrictJSON(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	g, err := Sign(Grant{OperationID: "op-1", Sequence: "9007199254740993", EnterpriseID: "enterprise", DeviceID: "device", InstallationID: "install",
		IssuedAt: now, StartBefore: now.Add(30 * time.Second), RunNotAfter: now.Add(8 * 24 * time.Hour), DurationSeconds: HealthySeconds,
		Targets: []Target{{Stream: "exec", BaselineToken: strings.Repeat("a", 64)}}}, key)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.StdEncoding.EncodeToString(pub)
	if err := g.VerifyIdentity(public, "enterprise", "device", "install"); err != nil {
		t.Fatal(err)
	}
	if !g.CanStart(now) || g.CanStart(g.StartBefore) || g.CanStart(now.Add(-time.Nanosecond)) {
		t.Fatal("start boundary extended")
	}
	for _, mutate := range []func(*Grant){
		func(g *Grant) { g.Purpose = "secweaver-collection-rules-v1" },
		func(g *Grant) { g.DeviceID = "other" }, func(g *Grant) { g.DurationSeconds++ },
		func(g *Grant) { g.Sequence = "01" }, func(g *Grant) { g.Targets = append([]Target{}, g.Targets...); g.Targets[0].Stream = "file" },
	} {
		bad := g
		mutate(&bad)
		if bad.VerifyIdentity(public, "enterprise", "device", "install") == nil {
			t.Fatal("tampering accepted")
		}
	}
	renew := g
	renew.IssuedAt = now.Add(time.Minute)
	renew.StartBefore = renew.IssuedAt.Add(30 * time.Second)
	renew, err = Sign(renew, key)
	if err != nil || renew.Digest != g.Digest {
		t.Fatalf("renewal changed immutable operation: %v", err)
	}
	body, _ := json.Marshal(g)
	if _, err := Decode(body); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.TrimSuffix(string(body), "}") + `,"sequence":"2"}`,
		strings.TrimSuffix(string(body), "}") + `,"command":"true"}`,
		string(body) + ` {}`, strings.Repeat(" ", MaxGrantBytes+1),
		strings.Replace(string(body), `"stream":"exec"`, `"stream":"exec","stream":"file"`, 1),
	} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Fatal("ambiguous/extended input accepted")
		}
	}
}
