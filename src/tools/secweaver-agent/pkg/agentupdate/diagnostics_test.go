package agentupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Check and persisted Install failures must agree: otherwise heartbeat still
// reports a permanent trust defect as a transient manifest network failure.
func TestManifestFailureDiagnostics(t *testing.T) {
	key, private, _ := ed25519.GenerateKey(rand.Reader)
	manifest := writeSignedManifestWithKeyID(t, t.TempDir(), Manifest{}, private, PublicKeyID(key))
	for _, tc := range []struct {
		name, reason, class string
		configure           func(*Options)
	}{
		{"unknown-signer", "manifest_signer_untrusted", "configuration", func(o *Options) { o.ManifestURL = manifest }},
		{"invalid-manifest", "manifest_invalid", "integrity", func(o *Options) {
			o.ManifestURL = filepath.Join(t.TempDir(), "bad.json")
			os.WriteFile(o.ManifestURL, []byte("{"), 0600)
		}},
		{"missing-ca", "update_ca_missing", "configuration", func(o *Options) { o.CAFile = filepath.Join(t.TempDir(), "missing.crt") }},
		{"invalid-ca", "update_ca_invalid", "configuration", func(o *Options) {
			o.CAFile = filepath.Join(t.TempDir(), "bad.crt")
			os.WriteFile(o.CAFile, []byte("not a certificate"), 0600)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := Options{ManifestURL: "https://unused.invalid/manifest.json", StateDir: t.TempDir()}
			tc.configure(&o)
			for _, action := range []func(Options) (Status, error){Check, Install} {
				status, err := action(o)
				if err == nil || status.Reason != tc.reason || status.FailureClass != tc.class || status.Retryable {
					t.Fatalf("wrong classification: %+v %v", status, err)
				}
			}
			state, err := LoadState(o.StateDir)
			if err != nil || state.LastError != tc.reason || state.FailureClass != tc.class {
				t.Fatalf("wrong persisted failure: %+v %v", state, err)
			}
		})
	}
}

func TestManifestHTTPAndTLSFailures(t *testing.T) {
	for _, code := range []int{401, 404, 429, 503} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
		status, err := Check(Options{ManifestURL: server.URL, StateDir: t.TempDir(), AllowInsecureHTTP: true})
		server.Close()
		retryable := code == 429 || code == 503
		if err == nil || status.Retryable != retryable {
			t.Fatalf("code=%d status=%+v err=%v", code, status, err)
		}
		if !retryable && status.Reason != "manifest_http_rejected" {
			t.Fatal(status.Reason)
		}
	}
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	status, err := Check(Options{ManifestURL: server.URL, StateDir: t.TempDir()})
	if err == nil || status.Reason != "update_tls_verification_failed" || status.Retryable {
		t.Fatalf("untrusted TLS: %+v %v", status, err)
	}
}
