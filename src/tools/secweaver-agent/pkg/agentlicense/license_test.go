package agentlicense

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfiguredCAFileTrustsPrivateControlPlane(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "control-plane-ca.crt")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := (Client{}).httpClient(Config{CAFile: caPath})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("private control-plane CA was not trusted: %v", err)
	}
	_ = response.Body.Close()
}

func TestCheckAndRegisterPersistsDeviceID(t *testing.T) {
	var got Request
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != authorizePath {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Header.Get("X-SecWeaver-Enrollment-ID") != "sw-enroll-test-token" {
			t.Fatalf("missing enrollment id")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return jsonResponse(200, Response{
			Allowed:               true,
			Registered:            true,
			EnterpriseID:          got.EnterpriseID,
			DeviceID:              got.DeviceID,
			MaxDevices:            3,
			UsedDevices:           1,
			SubscriptionExpiresAt: "2027-01-01T00:00:00Z",
		}), nil
	})}

	statePath := filepath.Join(t.TempDir(), "license-state.json")
	client := Client{
		HTTPClient: httpClient,
		Now:        func() time.Time { return time.Date(2026, 7, 14, 1, 2, 3, 0, time.UTC) },
	}
	result, err := client.CheckAndRegister(context.Background(), Config{
		Enabled:      true,
		ServerURL:    "https://shield.example.com",
		EnrollmentID: "sw-enroll-test-token",
		StatePath:    statePath,
	}, "6X13NGV4G9CVK92E", "0.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if got.EnterpriseID != "6X13NGV4G9CVK92E" || got.AgentVersion != "0.3.0" || got.DeviceID == "" {
		t.Fatalf("unexpected request: %+v", got)
	}
	if got.HostName == "" {
		t.Fatalf("host_name was not populated: %+v", got)
	}
	if got.OS == "" || got.Arch == "" {
		t.Fatalf("platform fields were not populated: %+v", got)
	}
	if !result.Response.Allowed || result.State.DeviceID == "" || result.State.RegisteredAt == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
	loaded, err := LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DeviceID != result.State.DeviceID || loaded.LastCheckAt == "" {
		t.Fatalf("state not persisted: %+v", loaded)
	}
}

func TestCheckAndRegisterPreservesKnownSubscriptionExpiryWhenResponseOmitsIt(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "license-state.json")
	const expiresAt = "2027-01-01T00:00:00Z"
	if err := SaveState(statePath, State{
		DeviceID:              "device-123",
		RegisteredAt:          "2026-07-14T00:00:00Z",
		SubscriptionExpiresAt: expiresAt,
	}); err != nil {
		t.Fatal(err)
	}

	httpClient := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, Response{
			Allowed:    true,
			Registered: true,
			DeviceID:   "device-123",
		}), nil
	})}
	_, err := (Client{HTTPClient: httpClient}).CheckAndRegister(context.Background(), Config{
		Enabled:      true,
		ServerURL:    "https://shield.example.com",
		EnrollmentID: "sw-enroll-test-token",
		StatePath:    statePath,
	}, "6X13NGV4G9CVK92E", "0.3.0")
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SubscriptionExpiresAt != expiresAt {
		t.Fatalf("subscription expiry = %q, want %q", loaded.SubscriptionExpiresAt, expiresAt)
	}
}

func TestCheckAndRegisterDeniesQuotaExceeded(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(200, Response{
			Allowed:     false,
			Registered:  false,
			Reason:      "device_quota_exceeded",
			Message:     "device quota exceeded",
			MaxDevices:  3,
			UsedDevices: 3,
		}), nil
	})}

	_, err := (Client{HTTPClient: httpClient}).CheckAndRegister(context.Background(), Config{
		Enabled:      true,
		ServerURL:    "https://shield.example.com",
		EnrollmentID: "sw-enroll-test-token",
		StatePath:    filepath.Join(t.TempDir(), "license-state.json"),
	}, "6X13NGV4G9CVK92E", "0.3.0")
	if err == nil || !strings.Contains(err.Error(), "device quota exceeded") {
		t.Fatalf("expected quota error, got %v", err)
	}
}

func TestHeartbeatPostsOnlineStatus(t *testing.T) {
	var got Request
	statePath := filepath.Join(t.TempDir(), "license-state.json")
	if err := SaveState(statePath, State{DeviceID: "device-123", RegisteredAt: "2026-07-14T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != heartbeatPath {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Header.Get("X-SecWeaver-Enrollment-ID") != "sw-enroll-test-token" {
			t.Fatalf("missing enrollment id")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return jsonResponse(200, Response{Allowed: true, Registered: true}), nil
	})}

	modules := map[string]ModuleHealth{
		"syslog-risk-json": {Status: "running", PID: 1234},
	}
	_, err := (Client{HTTPClient: httpClient}).Heartbeat(context.Background(), Config{
		Enabled:      true,
		ServerURL:    "https://shield.example.com",
		EnrollmentID: "sw-enroll-test-token",
		StatePath:    statePath,
	}, "6X13NGV4G9CVK92E", "0.3.0", modules)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != "device-123" || got.Status != "online" || got.EnterpriseID != "6X13NGV4G9CVK92E" {
		t.Fatalf("unexpected heartbeat request: %+v", got)
	}
	if got.Modules["syslog-risk-json"].Status != "running" || got.Modules["syslog-risk-json"].PID != 1234 {
		t.Fatalf("unexpected heartbeat modules: %+v", got.Modules)
	}
}

func TestFetchRemoteConfigPostsDeviceIdentity(t *testing.T) {
	var got Request
	statePath := filepath.Join(t.TempDir(), "license-state.json")
	if err := SaveState(statePath, State{DeviceID: "device-123", RegisteredAt: "2026-07-14T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != remoteConfigPath {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Header.Get("X-SecWeaver-Enrollment-ID") != "sw-enroll-test-token" {
			t.Fatalf("missing enrollment id")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return jsonResponse(200, RemoteConfigResponse{
			SchemaVersion: "1",
			Config:        json.RawMessage(`{"enterprise_id":"6X13NGV4G9CVK92E","modules":{"syslog-risk-json":{"enabled":true}}}`),
		}), nil
	})}

	resp, err := (Client{HTTPClient: httpClient}).FetchRemoteConfig(context.Background(), Config{
		Enabled:      true,
		ServerURL:    "https://shield.example.com",
		EnrollmentID: "sw-enroll-test-token",
		StatePath:    statePath,
	}, "6X13NGV4G9CVK92E", "0.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != "device-123" || got.Status != "config_pull" || got.EnterpriseID != "6X13NGV4G9CVK92E" {
		t.Fatalf("unexpected remote config request: %+v", got)
	}
	if !strings.Contains(string(resp.Config), "syslog-risk-json") {
		t.Fatalf("unexpected response config: %s", resp.Config)
	}
}

func TestConfigNormalizeDefaultsHeartbeatToThreeMinutes(t *testing.T) {
	cfg := (Config{}).Normalize()
	if cfg.HeartbeatSeconds != 180 {
		t.Fatalf("heartbeat default = %d, want 180", cfg.HeartbeatSeconds)
	}
	if cfg.OutageGracePeriod() != 24*time.Hour {
		t.Fatalf("outage grace default = %s, want 24h", cfg.OutageGracePeriod())
	}
}

func TestTransientControlPlaneErrorsAreNarrowlyClassified(t *testing.T) {
	for _, status := range []int{408, 425, 429, 500, 503} {
		if !IsTransient(&HTTPStatusError{StatusCode: status}) {
			t.Fatalf("HTTP %d should be transient", status)
		}
	}
	for _, status := range []int{400, 401, 403, 404} {
		if IsTransient(&HTTPStatusError{StatusCode: status}) {
			t.Fatalf("HTTP %d must not use cached authorization", status)
		}
	}
}

func TestNonJSONServiceUnavailableRemainsTransient(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Status:     "503 Service Unavailable",
			Body:       io.NopCloser(strings.NewReader("<html>temporarily unavailable</html>")),
			Header:     make(http.Header),
		}, nil
	})}
	_, err := (Client{HTTPClient: httpClient}).Authorize(context.Background(), Config{
		ServerURL: "https://shield.example.com",
	}, Request{})
	if err == nil || !IsTransient(err) {
		t.Fatalf("non-JSON HTTP 503 should remain transient, got %v", err)
	}
}

func TestConfigValidateBoundsOutageGrace(t *testing.T) {
	tooLong := maxOutageGraceSecs + 1
	err := (Config{
		Enabled: true, ServerURL: "https://shield.example.com", EnrollmentID: "sw-enroll-test-token",
		OutageGraceSeconds: &tooLong,
	}).Validate()
	if err == nil || !strings.Contains(err.Error(), "outage_grace_seconds") {
		t.Fatalf("expected outage grace validation error, got %v", err)
	}
}

func TestAcquireStateLockSerializesAccess(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "license-state.json")
	unlock, err := acquireStateLock(context.Background(), statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := acquireStateLock(ctx, statePath); err == nil || !strings.Contains(err.Error(), "context deadline") {
		t.Fatalf("expected lock timeout, got %v", err)
	}
}

func TestAcquireStateLockRemovesStaleLock(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "license-state.json")
	lockPath := statePath + ".lock"
	if err := os.Mkdir(lockPath, 0700); err != nil {
		t.Fatal(err)
	}
	staleTime := time.Now().Add(-stateLockStaleAfter - time.Minute)
	if err := os.Chtimes(lockPath, staleTime, staleTime); err != nil {
		t.Fatal(err)
	}
	unlock, err := acquireStateLock(context.Background(), statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
}

func TestConfigValidateRequiresCredentialsWhenEnabled(t *testing.T) {
	err := (Config{Enabled: true, ServerURL: "https://shield.example.com"}).Validate()
	if err == nil || !strings.Contains(err.Error(), "enrollment_id") {
		t.Fatalf("expected enrollment id error, got %v", err)
	}
}

func TestConfigValidateRejectsPlaceholderServer(t *testing.T) {
	err := (Config{Enabled: true, ServerURL: "https://YOUR_WEB_SHIELD_HOST", EnrollmentID: "sw-enroll-test-token"}).Validate()
	if err == nil || !strings.Contains(err.Error(), "placeholder") {
		t.Fatalf("expected placeholder server error, got %v", err)
	}
}

func TestAddrIPSupportsCommonAddressTypes(t *testing.T) {
	if got := addrIP(&net.IPNet{IP: net.ParseIP("10.0.0.10")}); got.String() != "10.0.0.10" {
		t.Fatalf("IPNet address = %v", got)
	}
	if got := addrIP(&net.IPAddr{IP: net.ParseIP("2001:db8::1")}); got.String() != "2001:db8::1" {
		t.Fatalf("IPAddr address = %v", got)
	}
}

func TestParseOSReleasePrefersPrettyName(t *testing.T) {
	values := parseOSRelease([]byte("NAME=\"CentOS Stream\"\nVERSION_ID=\"9\"\nPRETTY_NAME=\"CentOS Stream 9\"\n"))
	if values["PRETTY_NAME"] != "CentOS Stream 9" {
		t.Fatalf("PRETTY_NAME = %q", values["PRETTY_NAME"])
	}
}

func TestLinuxOSVersionFallsBackToNameAndVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte("NAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := linuxOSVersion(path); got != "Debian GNU/Linux 12" {
		t.Fatalf("linux OS version = %q", got)
	}
}

func TestEndpointURLReplacesKnownAgentPath(t *testing.T) {
	got, err := endpointURL("https://shield.example.com/api/secweaver/v1/agent/authorize", heartbeatPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://shield.example.com/api/secweaver/v1/agent/heartbeat" {
		t.Fatalf("endpoint URL = %s", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResponse(status int, payload interface{}) *http.Response {
	body, _ := json.Marshal(payload)
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}
}
