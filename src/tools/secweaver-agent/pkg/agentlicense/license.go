package agentlicense

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"secweaver-agent/pkg/layout"
)

const (
	authorizePath          = "/api/secweaver/v1/agent/authorize"
	heartbeatPath          = "/api/secweaver/v1/agent/heartbeat"
	remoteConfigPath       = "/api/secweaver/v1/agent/config"
	enrollV2Path           = "/api/secweaver/v2/agent/enroll"
	heartbeatV2Path        = "/api/secweaver/v2/agent/heartbeat"
	remoteConfigV2Path     = "/api/secweaver/v2/agent/config"
	defaultHeartbeatSecs   = 180
	defaultOutageGraceSecs = 24 * 60 * 60
	maxOutageGraceSecs     = 7 * 24 * 60 * 60
	stateLockStaleAfter    = 10 * time.Minute
)

type Config struct {
	Enabled              bool   `json:"enabled,omitempty"`
	Protocol             string `json:"protocol,omitempty"`
	ServerURL            string `json:"server_url,omitempty"`
	CAFile               string `json:"ca_file,omitempty"`
	EnrollmentID         string `json:"enrollment_id,omitempty"`
	StatePath            string `json:"state_path,omitempty"`
	IdentityKeyPath      string `json:"identity_key_path,omitempty"`
	CheckIntervalSeconds int    `json:"check_interval_seconds,omitempty"`
	HeartbeatSeconds     int    `json:"heartbeat_interval_seconds,omitempty"`
	OutageGraceSeconds   *int   `json:"outage_grace_seconds,omitempty"`
	FailClosed           *bool  `json:"fail_closed,omitempty"`
}

type State struct {
	SchemaVersion         string            `json:"schema_version"`
	DeviceID              string            `json:"device_id"`
	EnterpriseID          string            `json:"enterprise_id,omitempty"`
	InstallationID        string            `json:"installation_id,omitempty"`
	DevicePublicKey       string            `json:"device_public_key,omitempty"`
	HardwareFingerprint   string            `json:"hardware_fingerprint,omitempty"`
	FingerprintVersion    string            `json:"fingerprint_version,omitempty"`
	HardwareComponents    map[string]string `json:"hardware_components,omitempty"`
	KeyVersion            int               `json:"key_version,omitempty"`
	RegisteredAt          string            `json:"registered_at,omitempty"`
	LastCheckAt           string            `json:"last_check_at,omitempty"`
	SubscriptionExpiresAt string            `json:"subscription_expires_at,omitempty"`
}

type Request struct {
	EnterpriseID        string                  `json:"enterprise_id"`
	DeviceID            string                  `json:"device_id"`
	HostName            string                  `json:"host_name"`
	HostIP              string                  `json:"host_ip"`
	InternalIP          string                  `json:"internal_ip,omitempty"`
	ExternalIP          string                  `json:"external_ip,omitempty"`
	OS                  string                  `json:"os"`
	OSVersion           string                  `json:"os_version,omitempty"`
	Arch                string                  `json:"arch"`
	AgentVersion        string                  `json:"agent_version"`
	Registered          bool                    `json:"registered"`
	Status              string                  `json:"status,omitempty"`
	Modules             map[string]ModuleHealth `json:"modules,omitempty"`
	Labels              map[string]string       `json:"labels,omitempty"`
	FingerprintVersion  string                  `json:"fingerprint_version,omitempty"`
	HardwareFingerprint string                  `json:"hardware_fingerprint,omitempty"`
	HardwareComponents  map[string]string       `json:"hardware_components,omitempty"`
	UpdateStatus        *UpdateReport           `json:"update_status,omitempty"`
}

type UpdateReport struct {
	CurrentVersion     string `json:"current_version,omitempty"`
	TargetVersion      string `json:"target_version,omitempty"`
	LatestVersion      string `json:"latest_version,omitempty"`
	Status             string `json:"status,omitempty"`
	LastCheckAt        string `json:"last_check_at,omitempty"`
	LastUpdateAt       string `json:"last_update_at,omitempty"`
	LastError          string `json:"last_error,omitempty"`
	HealthPending      bool   `json:"health_pending,omitempty"`
	HealthDeadline     string `json:"health_deadline,omitempty"`
	RollbackReason     string `json:"rollback_reason,omitempty"`
	AttemptID          string `json:"attempt_id,omitempty"`
	CampaignID         string `json:"campaign_id,omitempty"`
	PolicyRevision     int    `json:"policy_revision,omitempty"`
	FailureClass       string `json:"failure_class,omitempty"`
	Retryable          bool   `json:"retryable,omitempty"`
	NextRetryAt        string `json:"next_retry_at,omitempty"`
	ManifestGeneration int64  `json:"manifest_generation,omitempty"`
}

type UpdatePolicy struct {
	Enabled                 bool     `json:"enabled"`
	Paused                  bool     `json:"paused,omitempty"`
	Eligible                bool     `json:"eligible,omitempty"`
	TargetVersion           string   `json:"target_version,omitempty"`
	Channel                 string   `json:"channel,omitempty"`
	ManifestURL             string   `json:"manifest_url,omitempty"`
	AutoInstall             bool     `json:"auto_install,omitempty"`
	RolloutPercentage       int      `json:"rollout_percentage,omitempty"`
	RolloutBucket           int      `json:"rollout_bucket,omitempty"`
	MaintenanceWindowOpen   *bool    `json:"maintenance_window_open,omitempty"`
	MaintenanceTimezone     string   `json:"maintenance_timezone,omitempty"`
	MaintenanceDays         []string `json:"maintenance_days,omitempty"`
	MaintenanceStart        string   `json:"maintenance_start,omitempty"`
	MaintenanceEnd          string   `json:"maintenance_end,omitempty"`
	NextMaintenanceWindow   string   `json:"next_maintenance_window,omitempty"`
	MaxConcurrentPercentage int      `json:"max_concurrent_percentage,omitempty"`
	LeaseGranted            *bool    `json:"lease_granted,omitempty"`
	LeaseExpiresAt          string   `json:"lease_expires_at,omitempty"`
	Reason                  string   `json:"reason,omitempty"`
	CampaignID              string   `json:"campaign_id,omitempty"`
	PolicyRevision          int      `json:"policy_revision,omitempty"`
	AllowDowngrade          bool     `json:"allow_downgrade,omitempty"`
	RollbackReason          string   `json:"rollback_reason,omitempty"`
}

type ModuleHealth struct {
	Status              string `json:"status"`
	PID                 int    `json:"pid,omitempty"`
	RestartCount        int    `json:"restart_count,omitempty"`
	ConsecutiveFailures int    `json:"consecutive_failures,omitempty"`
	LastStartAt         string `json:"last_start_at,omitempty"`
	LastExitAt          string `json:"last_exit_at,omitempty"`
	NextRestartAt       string `json:"next_restart_at,omitempty"`
	CircuitOpenUntil    string `json:"circuit_open_until,omitempty"`
	LastError           string `json:"last_error,omitempty"`
}

type Response struct {
	Allowed               bool          `json:"allowed"`
	Registered            bool          `json:"registered"`
	Reason                string        `json:"reason,omitempty"`
	Message               string        `json:"message,omitempty"`
	EnterpriseID          string        `json:"enterprise_id,omitempty"`
	DeviceID              string        `json:"device_id,omitempty"`
	DeviceKeyVersion      int           `json:"device_key_version,omitempty"`
	MaxDevices            int           `json:"max_devices,omitempty"`
	UsedDevices           int           `json:"used_devices,omitempty"`
	SubscriptionExpiresAt string        `json:"subscription_expires_at,omitempty"`
	ServerTime            string        `json:"server_time,omitempty"`
	UpdatePolicy          *UpdatePolicy `json:"update_policy,omitempty"`
}

type RemoteConfigResponse struct {
	SchemaVersion string          `json:"schema_version"`
	Config        json.RawMessage `json:"config"`
	SHA256        string          `json:"sha256,omitempty"`
	Signature     string          `json:"signature,omitempty"`
	Restart       *bool           `json:"restart,omitempty"`
}

type Result struct {
	Response Response
	State    State
}

type DeniedError struct {
	Response Response
}

func (e DeniedError) Error() string {
	return "license denied: " + responseReason(e.Response)
}

type HTTPStatusError struct {
	Operation  string
	StatusCode int
	Reason     string
}

func (e *HTTPStatusError) Error() string {
	operation := strings.TrimSpace(e.Operation)
	if operation == "" {
		operation = "control plane"
	}
	reason := strings.TrimSpace(e.Reason)
	if reason == "" {
		reason = http.StatusText(e.StatusCode)
	}
	return fmt.Sprintf("%s returned HTTP %d: %s", operation, e.StatusCode, reason)
}

func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		status := statusErr.StatusCode
		return status == http.StatusRequestTimeout || status == http.StatusTooEarly ||
			status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary())
}

type Client struct {
	HTTPClient *http.Client
	Now        func() time.Time
}

func DefaultStatePath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(layout.WindowsRootDir(), "data", "license-state.json")
	}
	return layout.LinuxData + "/license-state.json"
}

func (c Config) Normalize() Config {
	if strings.TrimSpace(c.StatePath) == "" {
		c.StatePath = DefaultStatePath()
	}
	if c.CheckIntervalSeconds == 0 {
		c.CheckIntervalSeconds = 6 * 3600
	}
	if c.HeartbeatSeconds == 0 {
		c.HeartbeatSeconds = defaultHeartbeatSecs
	}
	if strings.TrimSpace(c.IdentityKeyPath) == "" {
		c.IdentityKeyPath = filepath.Join(filepath.Dir(c.StatePath), "device-ed25519.key")
	}
	return c
}

func (c Config) DeviceAuthEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(c.Protocol), "device_v2")
}

func (c Config) FailClosedEnabled() bool {
	if c.FailClosed == nil {
		return true
	}
	return *c.FailClosed
}

func (c Config) OutageGracePeriod() time.Duration {
	if c.OutageGraceSeconds == nil {
		return time.Duration(defaultOutageGraceSecs) * time.Second
	}
	return time.Duration(*c.OutageGraceSeconds) * time.Second
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.ServerURL) == "" {
		return errors.New("server_url is required")
	}
	parsed, err := url.Parse(strings.TrimSpace(c.ServerURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("server_url is invalid: %q", c.ServerURL)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("server_url must use https")
	}
	if strings.TrimSpace(c.CAFile) != "" {
		info, err := os.Stat(strings.TrimSpace(c.CAFile))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("ca_file must be a readable regular file: %q", c.CAFile)
		}
	}
	if strings.Contains(c.ServerURL, "YOUR_WEB_SHIELD_HOST") || strings.Contains(c.ServerURL, "YOUR_DATA_CLOUD_HOST") {
		return fmt.Errorf("server_url must not be a placeholder")
	}
	protocol := strings.TrimSpace(c.Protocol)
	if protocol != "" && protocol != "legacy_v1" && protocol != "device_v2" {
		return errors.New("protocol must be legacy_v1 or device_v2")
	}
	if !c.DeviceAuthEnabled() && strings.TrimSpace(c.EnrollmentID) == "" {
		return errors.New("enrollment_id is required")
	}
	if c.CheckIntervalSeconds < 0 {
		return errors.New("check_interval_seconds must be >= 0")
	}
	if c.HeartbeatSeconds < 0 {
		return errors.New("heartbeat_interval_seconds must be >= 0")
	}
	if c.OutageGraceSeconds != nil && (*c.OutageGraceSeconds < 0 || *c.OutageGraceSeconds > maxOutageGraceSecs) {
		return fmt.Errorf("outage_grace_seconds must be between 0 and %d", maxOutageGraceSecs)
	}
	return nil
}

func (c Client) CheckAndRegister(ctx context.Context, cfg Config, enterpriseID, agentVersion string) (Result, error) {
	cfg = cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	if cfg.DeviceAuthEnabled() {
		state, err := LoadState(cfg.StatePath)
		if err != nil {
			return Result{}, fmt.Errorf("load device identity state: %w", err)
		}
		if state.RegisteredAt == "" || state.EnterpriseID == "" || state.DevicePublicKey == "" {
			return Result{State: state}, errors.New("device is not enrolled; run secweaver-agent enroll first")
		}
		resp, err := c.Heartbeat(ctx, cfg, state.EnterpriseID, agentVersion, nil)
		if err != nil {
			return Result{Response: resp, State: state}, err
		}
		state.LastCheckAt = c.now().UTC().Format(time.RFC3339)
		if expiresAt := strings.TrimSpace(resp.SubscriptionExpiresAt); expiresAt != "" {
			state.SubscriptionExpiresAt = expiresAt
		}
		if err := SaveState(cfg.StatePath, state); err != nil {
			return Result{Response: resp, State: state}, fmt.Errorf("save device identity state: %w", err)
		}
		return Result{Response: resp, State: state}, nil
	}
	unlock, err := acquireStateLock(ctx, cfg.StatePath)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	state, err := LoadState(cfg.StatePath)
	if err != nil {
		return Result{}, fmt.Errorf("load license state: %w", err)
	}
	if state.DeviceID == "" {
		deviceID, err := NewDeviceID()
		if err != nil {
			return Result{}, fmt.Errorf("generate device id: %w", err)
		}
		state.DeviceID = deviceID
	}
	req := buildRequest(enterpriseID, state, agentVersion, "")
	resp, err := c.Authorize(ctx, cfg, req)
	if err != nil {
		return Result{State: state}, err
	}
	if !resp.Allowed {
		return Result{Response: resp, State: state}, DeniedError{Response: resp}
	}
	now := c.now().UTC().Format(time.RFC3339)
	if resp.Registered && state.RegisteredAt == "" {
		state.RegisteredAt = now
	}
	state.LastCheckAt = now
	if expiresAt := strings.TrimSpace(resp.SubscriptionExpiresAt); expiresAt != "" {
		state.SubscriptionExpiresAt = expiresAt
	}
	if resp.DeviceID != "" {
		state.DeviceID = resp.DeviceID
	}
	if err := SaveState(cfg.StatePath, state); err != nil {
		return Result{Response: resp, State: state}, fmt.Errorf("save license state: %w", err)
	}
	return Result{Response: resp, State: state}, nil
}

func (c Client) Authorize(ctx context.Context, cfg Config, payload Request) (Response, error) {
	return c.post(ctx, cfg, authorizePath, payload)
}

func (c Client) Heartbeat(ctx context.Context, cfg Config, enterpriseID, agentVersion string, modules map[string]ModuleHealth) (Response, error) {
	return c.HeartbeatWithUpdate(ctx, cfg, enterpriseID, agentVersion, modules, nil)
}

func (c Client) HeartbeatWithUpdate(ctx context.Context, cfg Config, enterpriseID, agentVersion string, modules map[string]ModuleHealth, updateStatus *UpdateReport) (Response, error) {
	cfg = cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return Response{}, err
	}
	state, err := LoadState(cfg.StatePath)
	if err != nil {
		return Response{}, fmt.Errorf("load license state: %w", err)
	}
	if state.DeviceID == "" {
		return Response{}, errors.New("device_id is missing; authorize before heartbeat")
	}
	req := buildRequest(enterpriseID, state, agentVersion, "online")
	req.Modules = modules
	req.UpdateStatus = updateStatus
	if cfg.DeviceAuthEnabled() {
		state = withCurrentHardwareObservation(state)
		req = buildRequest(state.EnterpriseID, state, agentVersion, "online")
		req.Modules = modules
		req.UpdateStatus = updateStatus
		req.EnterpriseID = state.EnterpriseID
		return c.postSigned(ctx, cfg, heartbeatV2Path, req, state)
	}
	resp, err := c.post(ctx, cfg, heartbeatPath, req)
	if err != nil {
		return resp, err
	}
	if !resp.Allowed {
		return resp, DeniedError{Response: resp}
	}
	return resp, nil
}

func (c Client) FetchRemoteConfig(ctx context.Context, cfg Config, enterpriseID, agentVersion string) (RemoteConfigResponse, error) {
	cfg = cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return RemoteConfigResponse{}, err
	}
	state, err := LoadState(cfg.StatePath)
	if err != nil {
		return RemoteConfigResponse{}, fmt.Errorf("load license state: %w", err)
	}
	if state.DeviceID == "" {
		return RemoteConfigResponse{}, errors.New("device_id is missing; authorize before config pull")
	}
	req := buildRequest(enterpriseID, state, agentVersion, "config_pull")
	if cfg.DeviceAuthEnabled() {
		state = withCurrentHardwareObservation(state)
		req = buildRequest(state.EnterpriseID, state, agentVersion, "config_pull")
		req.EnterpriseID = state.EnterpriseID
		return c.fetchRemoteConfigSigned(ctx, cfg, req, state)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return RemoteConfigResponse{}, err
	}
	target, err := endpointURL(cfg.ServerURL, remoteConfigPath)
	if err != nil {
		return RemoteConfigResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return RemoteConfigResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-SecWeaver-Enrollment-ID", cfg.EnrollmentID)
	client, err := c.httpClient(cfg)
	if err != nil {
		return RemoteConfigResponse{}, err
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return RemoteConfigResponse{}, err
	}
	defer httpResp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 2<<20))
	if err != nil {
		return RemoteConfigResponse{}, err
	}
	var resp RemoteConfigResponse
	var decodeErr error
	if len(respBody) > 0 {
		decodeErr = json.Unmarshal(respBody, &resp)
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return resp, &HTTPStatusError{Operation: "remote config server", StatusCode: httpResp.StatusCode, Reason: httpResp.Status}
	}
	if decodeErr != nil {
		return RemoteConfigResponse{}, fmt.Errorf("decode remote config response: %w", decodeErr)
	}
	if len(resp.Config) == 0 {
		return resp, errors.New("remote config response missing config")
	}
	return resp, nil
}

func (c Client) post(ctx context.Context, cfg Config, path string, payload Request) (Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return Response{}, err
	}
	target, err := endpointURL(cfg.ServerURL, path)
	if err != nil {
		return Response{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SecWeaver-Enrollment-ID", cfg.EnrollmentID)
	client, err := c.httpClient(cfg)
	if err != nil {
		return Response{}, err
	}
	httpResp, err := client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer httpResp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return Response{}, err
	}
	var resp Response
	var decodeErr error
	if len(respBody) > 0 {
		decodeErr = json.Unmarshal(respBody, &resp)
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		if resp.Reason == "" {
			resp.Reason = httpResp.Status
		}
		return resp, &HTTPStatusError{Operation: "license server", StatusCode: httpResp.StatusCode, Reason: responseReason(resp)}
	}
	if decodeErr != nil {
		return Response{}, fmt.Errorf("decode license response: %w", decodeErr)
	}
	return resp, nil
}

func (c Client) httpClient(cfg Config) (*http.Client, error) {
	if c.HTTPClient != nil {
		return c.HTTPClient, nil
	}
	client := &http.Client{Timeout: 15 * time.Second}
	caFile := strings.TrimSpace(cfg.CAFile)
	if caFile == "" {
		return client, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read control-plane CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("control-plane CA file contains no valid PEM certificate")
	}
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		baseTransport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	transport := baseTransport.Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	client.Transport = transport
	return client, nil
}

func buildRequest(enterpriseID string, state State, agentVersion, status string) Request {
	hostname, _ := os.Hostname()
	networkIPs := hostNetworkIPs()
	return Request{
		EnterpriseID:        enterpriseID,
		DeviceID:            state.DeviceID,
		HostName:            hostname,
		HostIP:              primaryHostIP(),
		InternalIP:          networkIPs.internal,
		ExternalIP:          networkIPs.external,
		OS:                  runtime.GOOS,
		OSVersion:           detectOSVersion(),
		Arch:                runtime.GOARCH,
		AgentVersion:        agentVersion,
		Registered:          state.RegisteredAt != "",
		Status:              status,
		FingerprintVersion:  state.FingerprintVersion,
		HardwareFingerprint: state.HardwareFingerprint,
		HardwareComponents:  state.HardwareComponents,
	}
}

// hostNetworkIPs classifies addresses assigned to local interfaces. It does
// not guess a NAT/public address; external remains empty when no public local
// interface exists, preventing the UI from displaying a false internet IP.
func hostNetworkIPs() (result struct{ internal, external string }) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip := addrIP(addr)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			value := ip.String()
			if ip.IsPrivate() && result.internal == "" {
				result.internal = value
			}
			if !ip.IsPrivate() && !ip.IsUnspecified() && result.external == "" {
				result.external = value
			}
		}
	}
	return
}

func LoadState(path string) (State, error) {
	if strings.TrimSpace(path) == "" {
		return State{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func SaveState(path string, state State) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if state.SchemaVersion == "" {
		state.SchemaVersion = "1"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		return os.Rename(tmpName, path)
	}
	return nil
}

func acquireStateLock(ctx context.Context, statePath string) (func(), error) {
	if strings.TrimSpace(statePath) == "" {
		return func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return nil, fmt.Errorf("prepare license state lock dir: %w", err)
	}
	lockPath := statePath + ".lock"
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := os.Mkdir(lockPath, 0700)
		if err == nil {
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("acquire license state lock: %w", err)
		}
		if staleLock(lockPath, time.Now()) {
			_ = os.Remove(lockPath)
			continue
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("acquire license state lock: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func staleLock(path string, now time.Time) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return now.Sub(info.ModTime()) > stateLockStaleAfter
}

func NewDeviceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func primaryHostIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var fallback string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := addrIP(addr)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
			if fallback == "" {
				fallback = ip.String()
			}
		}
	}
	return fallback
}

func addrIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

func detectOSVersion() string {
	switch runtime.GOOS {
	case "linux":
		if version := linuxOSVersion("/etc/os-release"); version != "" {
			return version
		}
		if version := linuxOSVersion("/usr/lib/os-release"); version != "" {
			return version
		}
		return commandOutput(2*time.Second, "uname", "-sr")
	case "windows":
		return commandOutput(2*time.Second, "cmd", "/c", "ver")
	case "darwin":
		return commandOutput(2*time.Second, "sw_vers", "-productVersion")
	default:
		return commandOutput(2*time.Second, "uname", "-sr")
	}
}

func linuxOSVersion(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	values := parseOSRelease(data)
	if pretty := strings.TrimSpace(values["PRETTY_NAME"]); pretty != "" {
		return pretty
	}
	name := strings.TrimSpace(values["NAME"])
	version := strings.TrimSpace(values["VERSION_ID"])
	if name != "" && version != "" {
		return name + " " + version
	}
	if name != "" {
		return name
	}
	return version
}

func parseOSRelease(data []byte) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if key != "" {
			values[key] = value
		}
	}
	return values
}

func commandOutput(timeout time.Duration, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func authorizeURL(base string) (string, error) {
	return endpointURL(base, authorizePath)
}

func endpointURL(base, path string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(base), "/"))
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(parsed.Path, path) {
		return parsed.String(), nil
	}
	if strings.HasSuffix(parsed.Path, authorizePath) {
		parsed.Path = strings.TrimSuffix(parsed.Path, authorizePath) + path
		return parsed.String(), nil
	}
	if strings.HasSuffix(parsed.Path, heartbeatPath) {
		parsed.Path = strings.TrimSuffix(parsed.Path, heartbeatPath) + path
		return parsed.String(), nil
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + path
	return parsed.String(), nil
}

func responseReason(resp Response) string {
	if resp.Message != "" {
		return resp.Message
	}
	if resp.Reason != "" {
		return resp.Reason
	}
	return "not allowed"
}

func (c Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
