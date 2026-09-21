package agentlicense

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestComputeHardwareFingerprintIsOrderIndependent(t *testing.T) {
	first := computeHardwareFingerprint(map[string]string{
		"machine_id":       "sha256:" + strings.Repeat("1", 64),
		"dmi_product_uuid": "sha256:" + strings.Repeat("2", 64),
	})
	second := computeHardwareFingerprint(map[string]string{
		"dmi_product_uuid": "sha256:" + strings.Repeat("2", 64),
		"machine_id":       "sha256:" + strings.Repeat("1", 64),
	})
	if first != second || !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("fingerprints differ: %q != %q", first, second)
	}
}

func TestLinuxMachineIDPathUsesExplicitContainerMount(t *testing.T) {
	t.Setenv("SECWEAVER_HOST_MACHINE_ID_PATH", "/host/etc/machine-id")
	if got := linuxMachineIDPath(); got != "/host/etc/machine-id" {
		t.Fatalf("container machine ID path = %q", got)
	}
	t.Setenv("SECWEAVER_HOST_MACHINE_ID_PATH", "")
	if got := linuxMachineIDPath(); got != "/etc/machine-id" {
		t.Fatalf("default machine ID path = %q", got)
	}
}

func TestEnrollAndHeartbeatUseIndependentDeviceKey(t *testing.T) {
	originalCollector := collectHardwareComponentsFn
	originalHostname := osHostname
	defer func() {
		collectHardwareComponentsFn = originalCollector
		osHostname = originalHostname
	}()
	initialComponents := map[string]string{"machine_id": "sha256:" + strings.Repeat("1", 64)}
	currentComponents := initialComponents
	collectHardwareComponentsFn = func() (map[string]string, error) {
		copy := make(map[string]string, len(currentComponents))
		for name, value := range currentComponents {
			copy[name] = value
		}
		return copy, nil
	}
	osHostname = func() (string, error) { return "web-01", nil }

	var enrolled EnrollmentRequest
	var publicKey ed25519.PublicKey
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		switch r.URL.Path {
		case enrollV2Path:
			if r.Header.Get("Authorization") != "SecWeaverEnrollment reusable-test-token" {
				t.Fatalf("unexpected enrollment authorization header")
			}
			if err := json.Unmarshal(body, &enrolled); err != nil {
				t.Fatal(err)
			}
			publicKey, err = base64.RawURLEncoding.DecodeString(enrolled.DevicePublicKey)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := base64.RawURLEncoding.DecodeString(enrolled.ProofOfPossession)
			if err != nil || !ed25519.Verify(publicKey, enrollmentProofMessage(enrolled), proof) {
				t.Fatalf("invalid enrollment proof: %v", err)
			}
			if enrolled.DeviceID != computeDeviceID(enrolled.HardwareFingerprint, publicKey) {
				t.Fatalf("device ID is not bound to the fingerprint and public key")
			}
			return jsonResponse(200, Response{
				Allowed:          true,
				Registered:       true,
				EnterpriseID:     "6X13NGV4G9CVK92E",
				DeviceID:         enrolled.DeviceID,
				DeviceKeyVersion: 1,
			}), nil
		case heartbeatV2Path:
			var heartbeat Request
			if err := json.Unmarshal(body, &heartbeat); err != nil {
				t.Fatal(err)
			}
			signature, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-SecWeaver-Signature"))
			if err != nil {
				t.Fatal(err)
			}
			message := deviceRequestMessage(
				heartbeatV2Path,
				body,
				r.Header.Get("X-SecWeaver-Timestamp"),
				r.Header.Get("X-SecWeaver-Nonce"),
			)
			if !ed25519.Verify(publicKey, message, signature) {
				t.Fatal("heartbeat signature is invalid")
			}
			if r.Header.Get("X-SecWeaver-Device-ID") != enrolled.DeviceID {
				t.Fatalf("heartbeat uses a different device ID")
			}
			if heartbeat.HardwareFingerprint != computeHardwareFingerprint(currentComponents) {
				t.Fatalf("heartbeat did not refresh hardware observation: %+v", heartbeat)
			}
			return jsonResponse(200, Response{
				Allowed:      true,
				Registered:   true,
				EnterpriseID: "6X13NGV4G9CVK92E",
				DeviceID:     enrolled.DeviceID,
			}), nil
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
			return nil, nil
		}
	})}

	root := t.TempDir()
	cfg := Config{
		Enabled:         true,
		Protocol:        "device_v2",
		ServerURL:       "https://shield.example.com",
		StatePath:       filepath.Join(root, "identity.json"),
		IdentityKeyPath: filepath.Join(root, "device-ed25519.key"),
	}
	now := time.Date(2026, 7, 23, 6, 30, 0, 0, time.UTC)
	client := Client{HTTPClient: httpClient, Now: func() time.Time { return now }}
	result, err := client.Enroll(context.Background(), cfg, "reusable-test-token", "0.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if result.State.EnterpriseID != "6X13NGV4G9CVK92E" || result.State.RegisteredAt == "" {
		t.Fatalf("unexpected enrollment result: %+v", result)
	}
	keyInfo, err := os.Stat(cfg.IdentityKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("identity key mode=%04o want 0600", keyInfo.Mode().Perm())
	}

	currentComponents = map[string]string{"machine_id": "sha256:" + strings.Repeat("2", 64)}
	if _, err := client.Heartbeat(
		context.Background(),
		cfg,
		"UNTRUSTEDCLIENT1",
		"0.3.0",
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureDeviceIdentityRefusesSilentLegacyReplacement(t *testing.T) {
	originalCollector := collectHardwareComponentsFn
	defer func() { collectHardwareComponentsFn = originalCollector }()
	collectHardwareComponentsFn = func() (map[string]string, error) {
		return map[string]string{"machine_id": "sha256:" + strings.Repeat("3", 64)}, nil
	}
	root := t.TempDir()
	cfg := Config{
		StatePath:       filepath.Join(root, "identity.json"),
		IdentityKeyPath: filepath.Join(root, "device-ed25519.key"),
	}
	legacy := State{SchemaVersion: "1", DeviceID: "legacy-random-device-id", RegisteredAt: "2026-01-01T00:00:00Z"}
	if err := SaveState(cfg.StatePath, legacy); err != nil {
		t.Fatal(err)
	}
	_, _, err := ensureDeviceIdentity(cfg)
	if err == nil || !strings.Contains(err.Error(), "legacy device identity") {
		t.Fatalf("expected explicit legacy migration error, got %v", err)
	}
}
