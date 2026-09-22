package agentupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"secweaver-agent/pkg/layout"
	agentoutput "secweaver-agent/pkg/output"
)

const appName = "secweaver-agent"

type Options struct {
	Context              context.Context
	CommitGuard          func(context.Context) error
	ManifestURL          string
	CAFile               string
	Channel              string
	CurrentVersion       string
	DesiredVersion       string
	StateDir             string
	SelfPath             string
	DeviceID             string
	HostID               string // Deprecated: explicit legacy alias for DeviceID.
	PublicKey            ed25519.PublicKey
	TrustedPublicKeys    map[string]ed25519.PublicKey
	RevokedKeyIDs        []string
	AllowInsecureHTTP    bool
	AllowUnsignedLocal   bool // Deprecated: unsigned manifests are the default when no trust key is configured.
	ServerManaged        bool
	SkipDownloadDelay    bool
	LockStaleAfter       time.Duration
	MaxBackups           int
	MinFreeSpaceBytes    uint64
	CampaignID           string
	PolicyRevision       int
	AllowDowngrade       bool
	PolicyRollbackReason string
}

type State struct {
	CurrentVersion     string `json:"current_version"`
	PreviousVersion    string `json:"previous_version,omitempty"`
	TargetVersion      string `json:"target_version,omitempty"`
	LatestVersion      string `json:"latest_version"`
	LastCheckAt        string `json:"last_check_at"`
	LastUpdateAt       string `json:"last_update_at,omitempty"`
	LastUpdateStatus   string `json:"last_update_status"`
	LastError          string `json:"last_error,omitempty"`
	PreviousBinary     string `json:"previous_binary,omitempty"`
	PendingBinary      string `json:"pending_binary,omitempty"`
	HealthPending      bool   `json:"health_pending,omitempty"`
	HealthStartedAt    string `json:"health_started_at,omitempty"`
	HealthDeadline     string `json:"health_deadline,omitempty"`
	HealthConfirmedAt  string `json:"health_confirmed_at,omitempty"`
	RollbackReason     string `json:"rollback_reason,omitempty"`
	AttemptID          string `json:"attempt_id,omitempty"`
	CampaignID         string `json:"campaign_id,omitempty"`
	PolicyRevision     int    `json:"policy_revision,omitempty"`
	FailureClass       string `json:"failure_class,omitempty"`
	Retryable          bool   `json:"retryable,omitempty"`
	NextRetryAt        string `json:"next_retry_at,omitempty"`
	ManifestGeneration int64  `json:"manifest_generation,omitempty"`
	ManifestDigest     string `json:"manifest_digest,omitempty"`
	Phase              string `json:"phase,omitempty"`
}

type Status struct {
	Timestamp          string `json:"timestamp"`
	EventType          string `json:"event_type"`
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	App                string `json:"app"`
	Channel            string `json:"channel,omitempty"`
	Platform           string `json:"platform"`
	CurrentVersion     string `json:"current_version"`
	LatestVersion      string `json:"latest_version,omitempty"`
	DeviceID           string `json:"device_id,omitempty"`
	HostID             string `json:"host_id,omitempty"`
	RolloutBucket      *int   `json:"rollout_bucket,omitempty"`
	RolloutPercent     *int   `json:"rollout_percent,omitempty"`
	DownloadSpread     *int   `json:"download_spread_seconds,omitempty"`
	DownloadDelay      *int   `json:"download_delay_seconds,omitempty"`
	UpdateAvailable    bool   `json:"update_available"`
	BinaryURL          string `json:"binary_url,omitempty"`
	BinarySHA256       string `json:"binary_sha256,omitempty"`
	ManifestURL        string `json:"manifest_url,omitempty"`
	InstalledPath      string `json:"installed_path,omitempty"`
	BackupPath         string `json:"backup_path,omitempty"`
	PendingPath        string `json:"pending_path,omitempty"`
	StatePath          string `json:"state_path,omitempty"`
	SignerKeyID        string `json:"signer_key_id,omitempty"`
	EmergencyReason    string `json:"emergency_reason,omitempty"`
	AttemptID          string `json:"attempt_id,omitempty"`
	CampaignID         string `json:"campaign_id,omitempty"`
	PolicyRevision     int    `json:"policy_revision,omitempty"`
	FailureClass       string `json:"failure_class,omitempty"`
	Retryable          bool   `json:"retryable,omitempty"`
	NextRetryAt        string `json:"next_retry_at,omitempty"`
	ManifestGeneration int64  `json:"manifest_generation,omitempty"`
	ManifestDigest     string `json:"manifest_digest,omitempty"`
	Phase              string `json:"phase,omitempty"`
	CommitStarted      bool   `json:"commit_started,omitempty"`
}

var writeInstallState = writeState

func Check(opts Options) (status Status, resultErr error) {
	opts = normalizeOptions(opts)
	status = newStatus("secweaver_agent_update_check", opts)
	status.AttemptID = newAttemptID()
	defer func() { classifyStatusFailure(&status, resultErr) }()
	if strings.TrimSpace(opts.ManifestURL) == "" {
		status.Reason = "missing_manifest_url"
		return status, fmt.Errorf("missing -manifest-url")
	}
	manifest, err := fetchManifest(opts.ManifestURL, opts)
	if err != nil {
		status.Reason = "manifest_fetch_failed"
		return status, err
	}
	return checkManifest(manifest, opts, status)
}

func Install(opts Options) (status Status, resultErr error) {
	opts = normalizeOptions(opts)
	status = newStatus("secweaver_agent_update_install", opts)
	status.AttemptID = newAttemptID()
	defer func() { classifyStatusFailure(&status, resultErr) }()
	status.StatePath = filepath.Join(opts.StateDir, "state.json")
	if strings.TrimSpace(opts.ManifestURL) == "" {
		status.Reason = "missing_manifest_url"
		_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
		return status, fmt.Errorf("missing -manifest-url")
	}
	manifest, err := fetchManifest(opts.ManifestURL, opts)
	if err != nil {
		status.Reason = "manifest_fetch_failed"
		_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
		return status, err
	}
	status, err = checkManifest(manifest, opts, status)
	if err != nil {
		_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
		return status, err
	}
	if status.Status != "update_available" {
		_ = writeInstallState(status.StatePath, stateFromStatus(status, status.Status))
		return status, nil
	}
	if !opts.SkipDownloadDelay && status.DownloadDelay != nil && *status.DownloadDelay > 0 {
		time.Sleep(time.Duration(*status.DownloadDelay) * time.Second)
	}

	unlock, err := acquireLock(opts.StateDir, opts.LockStaleAfter)
	if err != nil {
		status.Status = "failed"
		status.Reason = "update_lock_unavailable"
		_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
		return status, err
	}
	defer unlock()

	selfPath, err := resolveSelfPath(opts.SelfPath)
	if err != nil {
		status.Status = "failed"
		status.Reason = "self_path_resolve_failed"
		_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
		return status, err
	}
	status.InstalledPath = selfPath

	artifact := manifest.Binaries[status.Platform]
	if err := ensureUpdateDiskSpace(opts, selfPath, artifact.Size); err != nil {
		status.Status = "failed"
		status.Reason = "insufficient_disk_space"
		_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
		return status, err
	}
	download, err := downloadArtifact(
		opts.Context,
		resolveArtifactLocation(opts.ManifestURL, artifact.URL),
		opts.AllowInsecureHTTP,
		opts.CAFile,
		opts.StateDir,
	)
	if err != nil {
		status.Status = "failed"
		status.Reason = "binary_download_failed"
		_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
		return status, err
	}
	defer os.Remove(download.Path)
	if artifact.Size > 0 && download.Size != artifact.Size {
		status.Status = "failed"
		status.Reason = "binary_size_mismatch"
		_ = writeState(status.StatePath, stateFromStatus(status, "failed"))
		return status, fmt.Errorf("binary size mismatch: got %d want %d", download.Size, artifact.Size)
	}
	if !strings.EqualFold(download.SHA256, strings.TrimSpace(artifact.SHA256)) {
		status.Status = "failed"
		status.Reason = "binary_sha256_mismatch"
		_ = writeState(status.StatePath, stateFromStatus(status, "failed"))
		return status, fmt.Errorf("binary sha256 mismatch")
	}
	if len(manifest.verifiedPublicKey) > 0 {
		var signedPayload []byte
		if artifact.SignatureFormat == "ed25519-sha256" {
			signedPayload, err = hex.DecodeString(download.SHA256)
		} else {
			signedPayload, err = os.ReadFile(filepath.Clean(download.Path))
		}
		if err == nil {
			err = verifyEd25519Signature(signedPayload, artifact.Signature, manifest.verifiedPublicKey)
		}
		if err != nil {
			status.Status = "failed"
			status.Reason = "binary_signature_invalid"
			_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
			return status, fmt.Errorf("verify binary signature: %w", err)
		}
	}
	if runtime.GOOS == "windows" && len(artifact.AuthenticodePublisherSHA256) > 0 {
		if err := verifyWindowsAuthenticode(opts.Context, download.Path, artifact.AuthenticodePublisherSHA256); err != nil {
			status.Status = "failed"
			status.Reason = "windows_authenticode_invalid"
			_ = writeState(status.StatePath, stateFromStatus(status, "failed"))
			return status, err
		}
	}
	if err := opts.Context.Err(); err != nil {
		status.Status = "failed"
		status.Reason = "update_cancelled"
		_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
		return status, err
	}

	backupPath, err := backupCurrentBinary(selfPath, opts.StateDir, opts.CurrentVersion, opts.MaxBackups)
	if err != nil {
		status.Status = "failed"
		status.Reason = "backup_failed"
		_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
		return status, err
	}
	status.BackupPath = backupPath
	if err := prepareRecoveryFiles(opts.StateDir, backupPath); err != nil {
		status.Status = "failed"
		status.Reason = "recovery_prepare_failed"
		_ = writeState(status.StatePath, stateFromStatus(status, "failed"))
		return status, err
	}

	if runtime.GOOS == "windows" {
		pendingPath, err := stageWindowsBinaryFromFile(selfPath, opts.StateDir, download.Path)
		if err != nil {
			clearRecoveryFiles(opts.StateDir)
			status.Status = "failed"
			status.Reason = "windows_stage_failed"
			_ = writeState(status.StatePath, stateFromStatus(status, "failed"))
			return status, err
		}
		status.PendingPath = pendingPath
		if err := beginInstallCommit(opts, &status); err != nil {
			_ = os.Remove(pendingPath)
			clearRecoveryFiles(opts.StateDir)
			status.Status = "failed"
			status.Reason = "update_cancelled_before_commit"
			_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
			return status, err
		}
		prepared := installTransactionState(status, opts, backupPath, pendingPath)
		if err := writeInstallState(status.StatePath, prepared); err != nil {
			clearRecoveryFiles(opts.StateDir)
			status.Status = "failed"
			status.Reason = "state_write_failed_before_commit"
			return status, err
		}
		if err := scheduleWindowsReplace(selfPath, pendingPath, opts.StateDir); err != nil {
			status.CommitStarted = false
			status.Phase = "failed"
			clearRecoveryFiles(opts.StateDir)
			status.Status = "failed"
			status.Reason = "windows_replace_schedule_failed"
			_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
			return status, err
		}
		status.Status = "install_scheduled"
		status.Reason = "replacement_scheduled_after_process_exit"
		status.Phase = "installed_pending_health"
		state := installTransactionState(status, opts, backupPath, pendingPath)
		state.LastUpdateStatus = "install_scheduled"
		state.Phase = status.Phase
		if err := writeInstallState(status.StatePath, state); err != nil {
			status.Status = "failed"
			status.Reason = "state_write_failed_after_install"
			return status, err
		}
		return status, nil
	}

	if err := beginInstallCommit(opts, &status); err != nil {
		clearRecoveryFiles(opts.StateDir)
		status.Status = "failed"
		status.Reason = "update_cancelled_before_commit"
		_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
		return status, err
	}
	prepared := installTransactionState(status, opts, backupPath, "")
	if err := writeInstallState(status.StatePath, prepared); err != nil {
		clearRecoveryFiles(opts.StateDir)
		status.Status = "failed"
		status.Reason = "state_write_failed_before_commit"
		return status, err
	}
	if err := atomicReplaceBinaryFromFile(selfPath, download.Path); err != nil {
		status.CommitStarted = false
		status.Phase = "failed"
		clearRecoveryFiles(opts.StateDir)
		status.Status = "failed"
		status.Reason = "atomic_replace_failed"
		_ = writeInstallState(status.StatePath, stateFromStatus(status, "failed"))
		return status, err
	}
	status.Status = "installed"
	status.Reason = "restart_required"
	status.Phase = "installed_pending_health"
	state := installTransactionState(status, opts, backupPath, "")
	state.LastUpdateStatus = "installed"
	state.Phase = status.Phase
	if err := writeInstallState(status.StatePath, state); err != nil {
		status.Status = "failed"
		status.Reason = "state_write_failed_after_install"
		return status, err
	}
	return status, nil
}

func beginInstallCommit(opts Options, status *Status) error {
	if err := opts.Context.Err(); err != nil {
		return err
	}
	if opts.CommitGuard != nil {
		if err := opts.CommitGuard(opts.Context); err != nil {
			return err
		}
	}
	status.CommitStarted = true
	status.Phase = "commit_started"
	return nil
}

func installTransactionState(status Status, opts Options, backupPath, pendingPath string) State {
	state := stateFromStatus(status, "commit_prepared")
	state.Phase = "commit_prepared"
	state.PreviousVersion = opts.CurrentVersion
	state.TargetVersion = status.LatestVersion
	state.PreviousBinary = backupPath
	state.PendingBinary = pendingPath
	state.HealthPending = true
	return state
}

func Rollback(opts Options) (Status, error) {
	return RollbackForReason(opts, "manual_rollback")
}

func RollbackForReason(opts Options, reason string) (Status, error) {
	opts = normalizeOptions(opts)
	status := newStatus("secweaver_agent_update_rollback", opts)
	statePath := filepath.Join(opts.StateDir, "state.json")
	status.StatePath = statePath
	state, err := readState(statePath)
	if err != nil {
		status.Reason = "state_read_failed"
		return status, err
	}
	status.LatestVersion = state.LatestVersion
	if state.PreviousBinary == "" {
		status.Reason = "missing_previous_binary"
		return status, fmt.Errorf("state previous_binary is empty")
	}
	selfPath, err := resolveSelfPath(opts.SelfPath)
	if err != nil {
		status.Reason = "self_path_resolve_failed"
		return status, err
	}
	status.InstalledPath = selfPath

	unlock, err := acquireLock(opts.StateDir, opts.LockStaleAfter)
	if err != nil {
		status.Reason = "update_lock_unavailable"
		return status, err
	}
	defer unlock()

	backupPath, err := backupCurrentBinary(selfPath, opts.StateDir, opts.CurrentVersion+"-rollback-from", opts.MaxBackups)
	if err != nil {
		status.Reason = "backup_failed"
		return status, err
	}
	payload, err := os.ReadFile(filepath.Clean(state.PreviousBinary))
	if err != nil {
		status.Reason = "previous_binary_read_failed"
		return status, err
	}
	status.BackupPath = backupPath

	if runtime.GOOS == "windows" {
		pendingPath, err := stageWindowsBinary(selfPath, opts.StateDir, payload)
		if err != nil {
			status.Reason = "windows_stage_failed"
			return status, err
		}
		status.PendingPath = pendingPath
		if err := scheduleWindowsReplace(selfPath, pendingPath, opts.StateDir); err != nil {
			status.Reason = "windows_replace_schedule_failed"
			return status, err
		}
		status.Status = "rollback_scheduled"
		status.Reason = "replacement_scheduled_after_process_exit"
		state.LastUpdateAt = time.Now().Format(time.RFC3339)
		state.LastUpdateStatus = "rollback_scheduled"
		state.Phase = "rolled_back"
		state.LastError = ""
		state.CurrentVersion = state.PreviousVersion
		state.PreviousVersion = opts.CurrentVersion
		state.PreviousBinary = backupPath
		state.PendingBinary = pendingPath
		state.HealthPending = false
		state.HealthStartedAt = ""
		state.HealthDeadline = ""
		state.RollbackReason = firstNonEmpty(state.RollbackReason, reason, "manual_rollback")
		if err := writeState(statePath, state); err != nil {
			status.Status = "failed"
			status.Reason = "state_write_failed_after_rollback"
			return status, err
		}
		// Keep the recovery marker for the Windows SCM failure command. It
		// performs the final locked-file replacement and restarts the service.
		return status, nil
	}

	if err := atomicReplaceBinary(selfPath, payload); err != nil {
		status.Reason = "atomic_replace_failed"
		return status, err
	}
	status.Status = "rolled_back"
	state.LastUpdateAt = time.Now().Format(time.RFC3339)
	state.LastUpdateStatus = "rolled_back"
	state.Phase = "rolled_back"
	state.LastError = ""
	state.CurrentVersion = state.PreviousVersion
	state.PreviousVersion = opts.CurrentVersion
	state.PreviousBinary = backupPath
	state.PendingBinary = ""
	state.HealthPending = false
	state.HealthStartedAt = ""
	state.HealthDeadline = ""
	state.RollbackReason = firstNonEmpty(state.RollbackReason, reason, "manual_rollback")
	if err := writeState(statePath, state); err != nil {
		status.Status = "failed"
		status.Reason = "state_write_failed_after_rollback"
		return status, err
	}
	clearRecoveryFiles(opts.StateDir)
	return status, nil
}

// PrepareHealthCheck starts the post-update probation period. A second startup
// before MarkHealthy is treated as a failed activation and restores the backup.
func PrepareHealthCheck(opts Options, timeout time.Duration) (bool, Status, error) {
	opts = normalizeOptions(opts)
	status := newStatus("secweaver_agent_update_health", opts)
	status.StatePath = filepath.Join(opts.StateDir, "state.json")
	state, err := readState(status.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		status.Status = "not_pending"
		return false, status, nil
	}
	if err != nil {
		status.Reason = "state_read_failed"
		return false, status, err
	}
	if !state.HealthPending {
		status.Status = "not_pending"
		return false, status, nil
	}
	targetVersion := firstNonEmpty(state.TargetVersion, state.LatestVersion)
	status.LatestVersion = targetVersion
	versionMatch, versionErr := compareVersions(opts.CurrentVersion, targetVersion)
	if targetVersion == "" || versionErr != nil || versionMatch != 0 {
		state.LastUpdateStatus = "activation_failed"
		state.LastError = "running version does not match pending target version"
		state.RollbackReason = "target_version_not_running"
		if err := writeState(status.StatePath, state); err != nil {
			return false, status, err
		}
		rollbackStatus, rollbackErr := RollbackForReason(opts, state.RollbackReason)
		return false, rollbackStatus, rollbackErr
	}
	if state.HealthStartedAt != "" {
		state.RollbackReason = "restarted_before_health_confirmation"
		state.LastError = state.RollbackReason
		if err := writeState(status.StatePath, state); err != nil {
			return false, status, err
		}
		rollbackStatus, rollbackErr := Rollback(opts)
		return false, rollbackStatus, rollbackErr
	}
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	now := time.Now().UTC()
	state.CurrentVersion = opts.CurrentVersion
	state.HealthStartedAt = now.Format(time.RFC3339)
	state.HealthDeadline = now.Add(timeout).Format(time.RFC3339)
	state.HealthConfirmedAt = ""
	state.LastUpdateStatus = "health_check_pending"
	state.Phase = "health_check_pending"
	state.LastError = ""
	if err := writeState(status.StatePath, state); err != nil {
		status.Reason = "state_write_failed"
		return false, status, err
	}
	status.Status = "health_check_pending"
	return true, status, nil
}

func MarkHealthy(opts Options) (State, error) {
	opts = normalizeOptions(opts)
	statePath := filepath.Join(opts.StateDir, "state.json")
	state, err := readState(statePath)
	if err != nil {
		return State{}, err
	}
	if !state.HealthPending {
		return state, nil
	}
	targetVersion := firstNonEmpty(state.TargetVersion, state.LatestVersion)
	versionMatch, versionErr := compareVersions(opts.CurrentVersion, targetVersion)
	if versionErr != nil {
		return state, fmt.Errorf("compare running and pending target versions: %w", versionErr)
	}
	if versionMatch != 0 {
		return state, fmt.Errorf("running version %s does not match pending target %s", opts.CurrentVersion, targetVersion)
	}
	state.CurrentVersion = opts.CurrentVersion
	state.HealthPending = false
	state.HealthConfirmedAt = time.Now().UTC().Format(time.RFC3339)
	state.LastUpdateStatus = "healthy"
	state.Phase = "healthy"
	state.LastError = ""
	state.RollbackReason = ""
	if err := writeState(statePath, state); err != nil {
		return State{}, err
	}
	clearRecoveryFiles(opts.StateDir)
	return state, nil
}

func LoadState(stateDir string) (State, error) {
	if strings.TrimSpace(stateDir) == "" {
		stateDir = DefaultStateDir()
	}
	state, err := readState(filepath.Join(stateDir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	return state, err
}

func WriteStatus(w io.Writer, status Status) error {
	return json.NewEncoder(w).Encode(status)
}

func OpenStatusOutput(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stderr, func() {}, nil
	}
	return agentoutput.OpenAppend(agentoutput.AppendOptions{
		Path: path,
		Perm: agentoutput.DefaultFilePerm,
	})
}

func DefaultStateDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(layout.WindowsRootDir(), "data", "update")
	}
	return layout.LinuxData + "/update"
}

func DefaultManifestURL() string {
	return strings.TrimSpace(os.Getenv("SECWEAVER_AGENT_UPDATE_MANIFEST_URL"))
}

func normalizeOptions(opts Options) Options {
	if opts.Context == nil {
		opts.Context = context.Background()
	}
	if opts.ManifestURL == "" {
		opts.ManifestURL = DefaultManifestURL()
	}
	if opts.Channel == "" {
		opts.Channel = "stable"
	}
	if opts.CurrentVersion == "" {
		opts.CurrentVersion = "dev"
	}
	if opts.StateDir == "" {
		opts.StateDir = DefaultStateDir()
	}
	if opts.DeviceID == "" && opts.HostID != "" {
		opts.DeviceID = strings.TrimSpace(opts.HostID)
	}
	if opts.HostID == "" && opts.DeviceID != "" {
		opts.HostID = opts.DeviceID
	}
	if opts.LockStaleAfter <= 0 {
		opts.LockStaleAfter = time.Hour
	}
	if opts.MaxBackups <= 0 {
		opts.MaxBackups = 3
	}
	if opts.MinFreeSpaceBytes == 0 {
		opts.MinFreeSpaceBytes = 256 * 1024 * 1024
	}
	return opts
}

func newStatus(eventType string, opts Options) Status {
	return Status{
		Timestamp:      time.Now().Format(time.RFC3339),
		EventType:      eventType,
		Status:         "failed",
		App:            appName,
		Channel:        opts.Channel,
		Platform:       runtime.GOOS + "_" + runtime.GOARCH,
		CurrentVersion: opts.CurrentVersion,
		DeviceID:       opts.DeviceID,
		HostID:         opts.HostID,
		ManifestURL:    opts.ManifestURL,
		CampaignID:     opts.CampaignID,
		PolicyRevision: opts.PolicyRevision,
	}
}

func newAttemptID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		return "swua_" + hex.EncodeToString(value[:])
	}
	return fmt.Sprintf("swua_%x_%d", os.Getpid(), time.Now().UTC().UnixNano())
}

func classifyStatusFailure(status *Status, err error) {
	if status == nil || (err == nil && status.Status != "failed") {
		return
	}
	retryableReasons := map[string]string{
		"manifest_fetch_failed":          "transport",
		"binary_download_failed":         "transport",
		"update_lock_unavailable":        "local_contention",
		"insufficient_disk_space":        "local_resource",
		"self_path_resolve_failed":       "local_resource",
		"update_cancelled":               "policy_change",
		"update_cancelled_before_commit": "policy_change",
	}
	if class, ok := retryableReasons[status.Reason]; ok {
		status.FailureClass = class
		status.Retryable = true
		return
	}
	securityReasons := map[string]bool{
		"binary_sha256_mismatch":              true,
		"binary_signature_invalid":            true,
		"binary_size_mismatch":                true,
		"manifest_app_mismatch":               true,
		"manifest_schema_version_unsupported": true,
		"manifest_generation_replayed":        true,
		"manifest_generation_conflict":        true,
		"manifest_generation_missing":         true,
		"manifest_generated_at_invalid":       true,
		"manifest_generated_in_future":        true,
		"manifest_expires_at_invalid":         true,
		"manifest_expiry_invalid":             true,
		"manifest_expired":                    true,
		"windows_authenticode_invalid":        true,
	}
	if securityReasons[status.Reason] {
		status.FailureClass = "integrity"
		return
	}
	status.FailureClass = "installation"
}

func RecordScheduledFailure(opts Options, status Status, err error, nextRetryAt time.Time) error {
	opts = normalizeOptions(opts)
	status.StatePath = filepath.Join(opts.StateDir, "state.json")
	if status.AttemptID == "" {
		status.AttemptID = newAttemptID()
	}
	status.Status = "failed"
	classifyStatusFailure(&status, err)
	status.NextRetryAt = nextRetryAt.UTC().Format(time.RFC3339)
	state := stateFromStatus(status, "failed")
	state.NextRetryAt = status.NextRetryAt
	return writeState(status.StatePath, state)
}

type updateLock struct {
	Owner     string `json:"owner"`
	PID       int    `json:"pid"`
	CreatedAt string `json:"created_at"`
}

func acquireLock(stateDir string, staleAfter time.Duration) (func(), error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(stateDir, "update.lock")
	owner := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UTC().UnixNano())
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			payload, _ := json.Marshal(updateLock{Owner: owner, PID: os.Getpid(), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
			if _, writeErr := f.Write(append(payload, '\n')); writeErr != nil {
				_ = f.Close()
				_ = os.Remove(lockPath)
				return nil, writeErr
			}
			if syncErr := f.Sync(); syncErr != nil {
				_ = f.Close()
				_ = os.Remove(lockPath)
				return nil, syncErr
			}
			if closeErr := f.Close(); closeErr != nil {
				_ = os.Remove(lockPath)
				return nil, closeErr
			}
			return func() {
				body, readErr := os.ReadFile(lockPath)
				var current updateLock
				if readErr == nil && json.Unmarshal(body, &current) == nil && current.Owner == owner {
					_ = os.Remove(lockPath)
				}
			}, nil
		}
		if !errors.Is(err, os.ErrExist) || attempt > 0 {
			return nil, err
		}
		info, statErr := os.Stat(lockPath)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return nil, statErr
		}
		if staleAfter <= 0 || time.Since(info.ModTime()) <= staleAfter {
			return nil, fmt.Errorf("update lock is active since %s", info.ModTime().UTC().Format(time.RFC3339))
		}
		if err := os.Remove(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("remove stale update lock: %w", err)
		}
	}
	return nil, errors.New("update lock acquisition failed")
}

func resolveSelfPath(path string) (string, error) {
	if path == "" {
		var err error
		path, err = os.Executable()
		if err != nil {
			return "", err
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("self path is directory: %s", abs)
	}
	return abs, nil
}

func backupCurrentBinary(selfPath, stateDir, currentVersion string, maxBackups int) (string, error) {
	backupDir := filepath.Join(stateDir, "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s_%s_%s.bak", filepath.Base(selfPath), sanitizePathPart(currentVersion), time.Now().Format("20060102T150405.000000000"))
	backupPath := filepath.Join(backupDir, name)
	if err := copyFile(selfPath, backupPath); err != nil {
		return "", err
	}
	if err := pruneBackups(backupDir, maxBackups, backupPath); err != nil {
		return "", err
	}
	return backupPath, nil
}

func pruneBackups(backupDir string, maxBackups int, keepPath string) error {
	if maxBackups <= 0 {
		return nil
	}
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return err
	}
	type backupFile struct {
		path    string
		modTime time.Time
	}
	backups := make([]backupFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".bak") {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		backups = append(backups, backupFile{path: filepath.Join(backupDir, entry.Name()), modTime: info.ModTime()})
	}
	sort.Slice(backups, func(i, j int) bool {
		if backups[i].modTime.Equal(backups[j].modTime) {
			return backups[i].path < backups[j].path
		}
		return backups[i].modTime.Before(backups[j].modTime)
	})
	for len(backups) > maxBackups {
		removeIndex := 0
		if backups[removeIndex].path == keepPath {
			removeIndex = 1
		}
		if removeIndex >= len(backups) {
			break
		}
		if err := os.Remove(backups[removeIndex].path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		backups = append(backups[:removeIndex], backups[removeIndex+1:]...)
	}
	return nil
}

var availableDiskBytes = diskFreeBytes

func ensureUpdateDiskSpace(opts Options, selfPath string, artifactSize int64) error {
	info, err := os.Stat(selfPath)
	if err != nil {
		return err
	}
	if artifactSize < 0 {
		artifactSize = 0
	}
	required := opts.MinFreeSpaceBytes + uint64(info.Size())*2 + uint64(artifactSize)
	checked := map[string]bool{}
	for _, path := range []string{filepath.Dir(selfPath), opts.StateDir} {
		existing, err := nearestExistingPath(path)
		if err != nil {
			return err
		}
		if checked[existing] {
			continue
		}
		checked[existing] = true
		available, err := availableDiskBytes(existing)
		if err != nil {
			return fmt.Errorf("check free disk space for %s: %w", existing, err)
		}
		if available < required {
			return fmt.Errorf("insufficient disk space on %s: available=%d required=%d", existing, available, required)
		}
	}
	return nil
}

func nearestExistingPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(absolute); err == nil {
			return absolute, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(absolute)
		if parent == absolute {
			return "", fmt.Errorf("no existing parent for %s", path)
		}
		absolute = parent
	}
}

func prepareRecoveryFiles(stateDir, backupPath string) error {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	payload, err := os.ReadFile(filepath.Clean(backupPath))
	if err != nil {
		return err
	}
	previousPath := filepath.Join(stateDir, "previous.bin")
	if err := writeBytesAtomic(previousPath, payload, 0700); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(stateDir, "activation.attempted"))
	return writeBytesAtomic(filepath.Join(stateDir, "health.pending"), []byte("pending\n"), 0600)
}

func clearRecoveryFiles(stateDir string) {
	_ = os.Remove(filepath.Join(stateDir, "health.pending"))
	_ = os.Remove(filepath.Join(stateDir, "activation.attempted"))
}

func writeBytesAtomic(path string, payload []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
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
	if err := replaceFileAtomic(tmpName, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func atomicReplaceBinary(selfPath string, payload []byte) error {
	info, err := os.Stat(selfPath)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if mode == 0 {
		mode = 0755
	}
	return writeBytesAtomic(selfPath, payload, mode)
}

func atomicReplaceBinaryFromFile(selfPath, sourcePath string) error {
	info, err := os.Stat(selfPath)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if mode == 0 {
		mode = 0755
	}
	tmp, err := os.CreateTemp(filepath.Dir(selfPath), "."+filepath.Base(selfPath)+".update.*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	source, err := os.Open(filepath.Clean(sourcePath))
	if err != nil {
		_ = tmp.Close()
		return err
	}
	_, copyErr := io.Copy(tmp, source)
	closeSourceErr := source.Close()
	if copyErr != nil || closeSourceErr != nil {
		_ = tmp.Close()
		return firstNonNil(copyErr, closeSourceErr)
	}
	if err := tmp.Chmod(mode); err != nil {
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
	if err := replaceFileAtomic(tmpPath, selfPath); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(selfPath))
}

func stageWindowsBinaryFromFile(selfPath, stateDir, sourcePath string) (string, error) {
	pendingDir := filepath.Join(stateDir, "pending")
	if err := os.MkdirAll(pendingDir, 0700); err != nil {
		return "", err
	}
	pendingPath := filepath.Join(pendingDir, fmt.Sprintf("%s.%d.new", filepath.Base(selfPath), os.Getpid()))
	if err := copyFile(sourcePath, pendingPath); err != nil {
		return "", err
	}
	return pendingPath, nil
}

func firstNonNil(values ...error) error {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func stageWindowsBinary(selfPath, stateDir string, payload []byte) (string, error) {
	pendingDir := filepath.Join(stateDir, "pending")
	if err := os.MkdirAll(pendingDir, 0700); err != nil {
		return "", err
	}
	pendingPath := filepath.Join(pendingDir, fmt.Sprintf("%s.%d.new", filepath.Base(selfPath), os.Getpid()))
	if err := os.WriteFile(pendingPath, payload, 0755); err != nil {
		return "", err
	}
	return pendingPath, nil
}

func scheduleWindowsReplace(selfPath, pendingPath, stateDir string) error {
	scriptPath := filepath.Join(stateDir, fmt.Sprintf("replace-%d.ps1", os.Getpid()))
	script := windowsAtomicReplaceScript(pendingPath, selfPath)
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return err
	}
	cmd := exec.Command(
		"cmd.exe", "/D", "/S", "/C", "start", "", "/B",
		"powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-File", scriptPath,
	)
	return cmd.Start()
}

func windowsAtomicReplaceScript(sourcePath, destinationPath string) string {
	encodedSource := base64.StdEncoding.EncodeToString([]byte(sourcePath))
	encodedDestination := base64.StdEncoding.EncodeToString([]byte(destinationPath))
	return fmt.Sprintf(`$ErrorActionPreference = "Stop"
$Source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("%s"))
$Destination = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("%s"))
for ($Attempt = 1; $Attempt -le 60; $Attempt++) {
  try {
    if ([IO.File]::Exists($Destination)) {
      [IO.File]::Replace($Source, $Destination, $null, $true)
    } else {
      [IO.File]::Move($Source, $Destination)
    }
    exit 0
  } catch {
    Start-Sleep -Seconds 1
  }
}
exit 1
`, encodedSource, encodedDestination)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func stateFromStatus(status Status, updateStatusText string) State {
	state := State{
		CurrentVersion:     status.CurrentVersion,
		LatestVersion:      status.LatestVersion,
		LastCheckAt:        status.Timestamp,
		LastUpdateStatus:   updateStatusText,
		LastError:          status.Reason,
		AttemptID:          status.AttemptID,
		CampaignID:         status.CampaignID,
		PolicyRevision:     status.PolicyRevision,
		FailureClass:       status.FailureClass,
		Retryable:          status.Retryable,
		NextRetryAt:        status.NextRetryAt,
		ManifestGeneration: status.ManifestGeneration,
		ManifestDigest:     status.ManifestDigest,
		Phase:              status.Phase,
	}
	if updateStatusText == "installed" || updateStatusText == "install_scheduled" || strings.HasPrefix(updateStatusText, "rollback") {
		state.LastUpdateAt = time.Now().Format(time.RFC3339)
	}
	return state
}

func writeState(path string, state State) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeBytesAtomic(path, data, 0600)
}

func readState(path string) (State, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func sanitizePathPart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
