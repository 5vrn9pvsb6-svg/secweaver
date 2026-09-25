package agentlicense

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var enterpriseIDPattern = regexp.MustCompile(`^[A-Z0-9]{16}$`)

type EnrollmentRequest struct {
	ProtocolVersion     string            `json:"protocol_version"`
	RequestID           string            `json:"request_id"`
	Timestamp           string            `json:"timestamp"`
	Nonce               string            `json:"nonce"`
	DeviceID            string            `json:"device_id"`
	InstallationID      string            `json:"installation_id"`
	DevicePublicKey     string            `json:"device_public_key"`
	ProofOfPossession   string            `json:"proof_of_possession"`
	FingerprintVersion  string            `json:"fingerprint_version"`
	HardwareFingerprint string            `json:"hardware_fingerprint"`
	HardwareComponents  map[string]string `json:"hardware_components,omitempty"`
	HostName            string            `json:"host_name,omitempty"`
	HostIP              string            `json:"host_ip,omitempty"`
	InternalIP          string            `json:"internal_ip,omitempty"`
	ExternalIP          string            `json:"external_ip,omitempty"`
	OS                  string            `json:"os"`
	OSVersion           string            `json:"os_version,omitempty"`
	Arch                string            `json:"arch"`
	AgentVersion        string            `json:"agent_version"`
}

func (c Client) Enroll(ctx context.Context, cfg Config, token, agentVersion string) (Result, error) {
	cfg = cfg.Normalize()
	if !cfg.DeviceAuthEnabled() {
		return Result{}, errors.New("device enrollment requires protocol=device_v2")
	}
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(token) == "" {
		return Result{}, errors.New("enterprise enrollment token is required")
	}
	unlock, err := acquireStateLock(ctx, cfg.StatePath)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	state, privateKey, err := ensureDeviceIdentity(cfg)
	if err != nil {
		return Result{}, err
	}
	timestamp := c.now().UTC().Format(time.RFC3339)
	nonce, err := randomNonce()
	if err != nil {
		return Result{State: state}, err
	}
	requestID, err := NewDeviceID()
	if err != nil {
		return Result{State: state}, err
	}
	hostname, _ := osHostname()
	networkIPs := hostNetworkIPs()
	payload := EnrollmentRequest{
		ProtocolVersion:     "2",
		RequestID:           requestID,
		Timestamp:           timestamp,
		Nonce:               nonce,
		DeviceID:            state.DeviceID,
		InstallationID:      state.InstallationID,
		DevicePublicKey:     state.DevicePublicKey,
		FingerprintVersion:  state.FingerprintVersion,
		HardwareFingerprint: state.HardwareFingerprint,
		HardwareComponents:  state.HardwareComponents,
		HostName:            hostname,
		HostIP:              primaryHostIP(),
		InternalIP:          networkIPs.internal,
		ExternalIP:          networkIPs.external,
		OS:                  runtime.GOOS,
		OSVersion:           detectOSVersion(),
		Arch:                runtime.GOARCH,
		AgentVersion:        agentVersion,
	}
	payload.ProofOfPossession = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(privateKey, enrollmentProofMessage(payload)),
	)
	body, err := json.Marshal(payload)
	if err != nil {
		return Result{State: state}, err
	}
	target, err := endpointURL(cfg.ServerURL, enrollV2Path)
	if err != nil {
		return Result{State: state}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return Result{State: state}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "SecWeaverEnrollment "+strings.TrimSpace(token))
	resp, status, err := c.do(req, 1<<20, cfg)
	if err != nil {
		return Result{State: state}, err
	}
	var enrollment Response
	var decodeErr error
	if len(resp) > 0 {
		decodeErr = json.Unmarshal(resp, &enrollment)
	}
	if status < 200 || status >= 300 {
		return Result{Response: enrollment, State: state}, &HTTPStatusError{Operation: "enrollment server", StatusCode: status, Reason: responseReason(enrollment)}
	}
	if len(bytes.TrimSpace(resp)) == 0 {
		return Result{State: state}, &ResponseValidationError{StatusCode: status, Check: "empty-json-response"}
	}
	if decodeErr != nil || bytes.Equal(bytes.TrimSpace(resp), []byte("null")) {
		return Result{State: state}, &ResponseValidationError{StatusCode: status, Check: "invalid-json-response"}
	}
	if !enrollment.Allowed {
		return Result{Response: enrollment, State: state}, DeniedError{Response: enrollment}
	}
	if enrollment.DeviceID != state.DeviceID {
		return Result{Response: enrollment, State: state}, errors.New("enrollment response device_id does not match local identity")
	}
	enterpriseID := strings.ToUpper(strings.TrimSpace(enrollment.EnterpriseID))
	if !enterpriseIDPattern.MatchString(enterpriseID) {
		return Result{Response: enrollment, State: state}, errors.New("enrollment response contains invalid enterprise_id")
	}
	state.EnterpriseID = enterpriseID
	state.RegisteredAt = timestamp
	state.LastCheckAt = timestamp
	state.SubscriptionExpiresAt = strings.TrimSpace(enrollment.SubscriptionExpiresAt)
	if enrollment.DeviceKeyVersion > 0 {
		state.KeyVersion = enrollment.DeviceKeyVersion
	}
	if err := SaveState(cfg.StatePath, state); err != nil {
		return Result{Response: enrollment, State: state}, fmt.Errorf("save enrolled device identity: %w", err)
	}
	return Result{Response: enrollment, State: state}, nil
}

func enrollmentProofMessage(payload EnrollmentRequest) []byte {
	return []byte(
		"SECWEAVER-ENROLL-V1\n" +
			payload.DeviceID + "\n" +
			payload.InstallationID + "\n" +
			payload.DevicePublicKey + "\n" +
			payload.HardwareFingerprint + "\n" +
			payload.Timestamp + "\n" +
			payload.Nonce,
	)
}

func (c Client) postSigned(ctx context.Context, cfg Config, path string, payload Request, state State) (Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return Response{}, err
	}
	responseBody, status, err := c.doSigned(ctx, cfg, path, body, state, 1<<20)
	if err != nil {
		return Response{}, err
	}
	var response Response
	var decodeErr error
	if len(responseBody) > 0 {
		decodeErr = json.Unmarshal(responseBody, &response)
	}
	if status < 200 || status >= 300 {
		return response, &HTTPStatusError{Operation: "device control server", StatusCode: status, Reason: responseReason(response)}
	}
	if decodeErr != nil {
		return Response{}, fmt.Errorf("decode device response: %w", decodeErr)
	}
	if !response.Allowed {
		return response, DeniedError{Response: response}
	}
	return response, nil
}

func (c Client) fetchRemoteConfigSigned(ctx context.Context, cfg Config, payload Request, state State) (RemoteConfigResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return RemoteConfigResponse{}, err
	}
	responseBody, status, err := c.doSigned(ctx, cfg, remoteConfigV2Path, body, state, 2<<20)
	if err != nil {
		return RemoteConfigResponse{}, err
	}
	var response RemoteConfigResponse
	var decodeErr error
	if len(responseBody) > 0 {
		decodeErr = json.Unmarshal(responseBody, &response)
	}
	if status < 200 || status >= 300 {
		return response, &HTTPStatusError{Operation: "remote config server", StatusCode: status}
	}
	if decodeErr != nil {
		return RemoteConfigResponse{}, fmt.Errorf("decode remote config response: %w", decodeErr)
	}
	if len(response.Config) == 0 {
		return response, errors.New("remote config response missing config")
	}
	return response, nil
}

func (c Client) doSigned(ctx context.Context, cfg Config, path string, body []byte, state State, limit int64) ([]byte, int, error) {
	privateKey, err := loadDevicePrivateKey(cfg.IdentityKeyPath)
	if err != nil {
		return nil, 0, fmt.Errorf("load device identity key: %w", err)
	}
	timestamp := c.now().UTC().Format(time.RFC3339)
	nonce, err := randomNonce()
	if err != nil {
		return nil, 0, err
	}
	target, err := endpointURL(cfg.ServerURL, path)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	signature := ed25519.Sign(privateKey, deviceRequestMessage(path, body, timestamp, nonce))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SecWeaver-Device-ID", state.DeviceID)
	req.Header.Set("X-SecWeaver-Key-Version", fmt.Sprintf("%d", state.KeyVersion))
	req.Header.Set("X-SecWeaver-Timestamp", timestamp)
	req.Header.Set("X-SecWeaver-Nonce", nonce)
	req.Header.Set("X-SecWeaver-Signature", base64.RawURLEncoding.EncodeToString(signature))
	return c.do(req, limit, cfg)
}

func deviceRequestMessage(path string, body []byte, timestamp, nonce string) []byte {
	digest := sha256.Sum256(body)
	return []byte(
		"SECWEAVER-DEVICE-V1\n" +
			http.MethodPost + "\n" +
			path + "\n" +
			hex.EncodeToString(digest[:]) + "\n" +
			timestamp + "\n" +
			nonce,
	)
}

func (c Client) do(req *http.Request, limit int64, cfg Config) ([]byte, int, error) {
	client, err := c.httpClient(cfg)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

var osHostname = func() (string, error) {
	return os.Hostname()
}
