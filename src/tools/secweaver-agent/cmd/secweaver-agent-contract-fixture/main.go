// Command secweaver-agent-contract-fixture emits a signed Agent v2 request pair
// for cross-repository compatibility tests. Its deterministic private key is test
// material only and must never be accepted as a production device identity.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"secweaver-agent/pkg/agentlicense"
)

const (
	enrollmentPath = "/api/secweaver/v2/agent/enroll"
	heartbeatPath  = "/api/secweaver/v2/agent/heartbeat"
)

type requestFixture struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    json.RawMessage   `json:"body"`
}

type fixture struct {
	Format       int            `json:"format"`
	Protocol     string         `json:"protocol"`
	AgentVersion string         `json:"agent_version"`
	PublicKey    string         `json:"public_key"`
	Enrollment   requestFixture `json:"enrollment"`
	Heartbeat    requestFixture `json:"heartbeat"`
}

// main independently constructs the canonical signature messages used by the
// client. The server consumes this output without importing Community code, so
// a JSON-field or canonicalization drift fails the private compatibility gate.
func main() {
	agentVersion := flag.String("agent-version", "", "canonical Agent version")
	flag.Parse()
	if strings.TrimSpace(*agentVersion) == "" {
		fmt.Fprintln(os.Stderr, "-agent-version is required")
		os.Exit(2)
	}

	seed := sha256.Sum256([]byte("secweaver-agent-v2-contract-fixture"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicText := base64.RawURLEncoding.EncodeToString(publicKey)
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	identityDigest := sha256.Sum256(append([]byte("secweaver-device-v1\x00"+fingerprint+"\x00"), publicKey...))
	deviceID := "swd_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(identityDigest[:]))
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := "community-contract-nonce-0001"

	enrollment := agentlicense.EnrollmentRequest{
		ProtocolVersion:     "2",
		RequestID:           "community-contract-request",
		Timestamp:           timestamp,
		Nonce:               nonce,
		DeviceID:            deviceID,
		InstallationID:      "community-contract-installation",
		DevicePublicKey:     publicText,
		FingerprintVersion:  "hw-v1",
		HardwareFingerprint: fingerprint,
		HardwareComponents: map[string]string{
			"machine_id": fingerprint,
		},
		HostName:     "contract-host",
		HostIP:       "192.0.2.10",
		InternalIP:   "10.0.0.10",
		ExternalIP:   "198.51.100.10",
		OS:           "linux",
		OSVersion:    "contract",
		Arch:         "amd64",
		AgentVersion: *agentVersion,
	}
	enrollmentMessage := "SECWEAVER-ENROLL-V1\n" + enrollment.DeviceID + "\n" + enrollment.InstallationID + "\n" + enrollment.DevicePublicKey + "\n" + enrollment.HardwareFingerprint + "\n" + enrollment.Timestamp + "\n" + enrollment.Nonce
	enrollment.ProofOfPossession = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(enrollmentMessage)))
	enrollmentBody, err := json.Marshal(enrollment)
	if err != nil {
		panic(err)
	}

	heartbeat := agentlicense.Request{
		EnterpriseID:        "0123456789ABCDEF",
		DeviceID:            deviceID,
		HostName:            "contract-host",
		HostIP:              "192.0.2.10",
		InternalIP:          "10.0.0.10",
		ExternalIP:          "198.51.100.10",
		OS:                  "linux",
		OSVersion:           "contract",
		Arch:                "amd64",
		AgentVersion:        *agentVersion,
		Registered:          true,
		FingerprintVersion:  "hw-v1",
		HardwareFingerprint: fingerprint,
		HardwareComponents: map[string]string{
			"machine_id": fingerprint,
		},
	}
	heartbeatBody, err := json.Marshal(heartbeat)
	if err != nil {
		panic(err)
	}
	heartbeatNonce := "community-heartbeat-nonce-001"
	bodyDigest := sha256.Sum256(heartbeatBody)
	heartbeatMessage := "SECWEAVER-DEVICE-V1\n" + http.MethodPost + "\n" + heartbeatPath + "\n" + hex.EncodeToString(bodyDigest[:]) + "\n" + timestamp + "\n" + heartbeatNonce

	output := fixture{
		Format:       1,
		Protocol:     "device_v2",
		AgentVersion: *agentVersion,
		PublicKey:    publicText,
		Enrollment:   requestFixture{Path: enrollmentPath, Body: enrollmentBody},
		Heartbeat: requestFixture{Path: heartbeatPath, Body: heartbeatBody, Headers: map[string]string{
			"X-SecWeaver-Device-ID":   deviceID,
			"X-SecWeaver-Key-Version": "1",
			"X-SecWeaver-Timestamp":   timestamp,
			"X-SecWeaver-Nonce":       heartbeatNonce,
			"X-SecWeaver-Signature":   base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(heartbeatMessage))),
		}},
	}
	encoder := json.NewEncoder(os.Stdout)
	// Keep nested request bodies byte-identical to the bytes that were signed.
	// Pretty-printing RawMessage would rewrite whitespace and invalidate the
	// heartbeat signature even though its parsed JSON value stayed unchanged.
	if err := encoder.Encode(output); err != nil {
		panic(err)
	}
}
