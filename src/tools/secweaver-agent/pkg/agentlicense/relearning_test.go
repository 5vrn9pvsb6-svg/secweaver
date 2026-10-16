package agentlicense

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"secweaver-agent/pkg/learningoperation"
)

// Optional telemetry uses the exact device-signature body/path/nonce contract;
// neither a caller-selected enterprise nor the legacy API acquires authority.
func TestRelearningSignedClaimAndLegacyOmission(t *testing.T) {
	root := t.TempDir()
	cfg := Config{Enabled: true, Protocol: "device_v2", ServerURL: "https://gateway.invalid", StatePath: filepath.Join(root, "identity.json"), IdentityKeyPath: filepath.Join(root, "device.key")}.Normalize()
	state, key, err := ensureDeviceIdentity(cfg)
	if err != nil {
		t.Fatal(err)
	}
	state.EnterpriseID = "AAAABBBBCCCCDDDD"
	state.RegisteredAt = "2026-10-16T00:00:00Z"
	state.KeyVersion = 1
	if err = SaveState(cfg.StatePath, state); err != nil {
		t.Fatal(err)
	}
	report := &learningoperation.Report{Capability: learningoperation.Capability, Streams: map[string]learningoperation.Snapshot{}}
	for _, kind := range []string{"exec", "file", "network", "risk"} {
		report.Streams[kind] = learningoperation.Snapshot{Reason: "disabled"}
	}
	report.Streams["exec"] = learningoperation.Snapshot{Eligible: true, Reason: "active", BaselineToken: strings.Repeat("a", 64)}
	calls := 0
	client := Client{HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		body, e := io.ReadAll(r.Body)
		if e != nil {
			t.Fatal(e)
		}
		var got Request
		if e = json.Unmarshal(body, &got); e != nil {
			t.Fatal(e)
		}
		if got.EnterpriseID != state.EnterpriseID {
			t.Fatal("untrusted enterprise selected", got.EnterpriseID)
		}
		if calls == 3 {
			if got.BehaviorRelearning != nil || got.InstallationID != "" || got.RelearningClaim != nil {
				t.Fatal("old heartbeat changed", string(body))
			}
		} else {
			if !learningoperation.ValidReport(got.BehaviorRelearning) || got.InstallationID != state.InstallationID {
				t.Fatal("missing report binding", string(body))
			}
			if calls == 2 && (r.URL.Path != "/api/secweaver/v2/agent/relearning/claim" || got.RelearningClaim == nil || got.RelearningClaim.OperationID != "operation") {
				t.Fatal("claim missing identity")
			}
		}
		sig, e := base64.RawURLEncoding.DecodeString(r.Header.Get("X-SecWeaver-Signature"))
		if e != nil {
			t.Fatal(e)
		}
		message := deviceRequestMessage(r.URL.Path, body, r.Header.Get("X-SecWeaver-Timestamp"), r.Header.Get("X-SecWeaver-Nonce"))
		if !ed25519.Verify(key.Public().(ed25519.PublicKey), message, sig) {
			t.Fatal("invalid signed request")
		}
		return jsonResponse(200, Response{Allowed: true, EnterpriseID: state.EnterpriseID, DeviceID: state.DeviceID}), nil
	})}}
	if _, err = client.HeartbeatWithRelearning(context.Background(), cfg, "UNTRUSTEDCLIENT1", "0.3.106", map[string]ModuleHealth{}, nil, nil, nil, nil, report); err != nil {
		t.Fatal(err)
	}
	if _, err = client.ClaimRelearning(context.Background(), cfg, "0.3.106", "operation", report); err != nil {
		t.Fatal(err)
	}
	if _, err = client.HeartbeatWithCollectionRules(context.Background(), cfg, "UNTRUSTEDCLIENT1", "0.3.106", nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatal(calls)
	}
}
