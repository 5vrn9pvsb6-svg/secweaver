package agentupdate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type Manifest struct {
	SchemaVersion       string              `json:"schema_version"`
	App                 string              `json:"app,omitempty"`
	Channel             string              `json:"channel"`
	GeneratedAt         string              `json:"generated_at,omitempty"`
	Generation          int64               `json:"generation,omitempty"`
	ExpiresAt           string              `json:"expires_at,omitempty"`
	MinSupportedVersion string              `json:"min_supported_version,omitempty"`
	Latest              ManifestLatest      `json:"latest"`
	Binaries            map[string]Artifact `json:"binaries"`
	Rollout             Rollout             `json:"rollout,omitempty"`
	TrustUpdate         *TrustUpdate        `json:"trust_update,omitempty"`
	EmergencyStop       *EmergencyStop      `json:"emergency_stop,omitempty"`
	Rollback            *RollbackDirective  `json:"rollback,omitempty"`
	verifiedKeyID       string
	verifiedPublicKey   ed25519.PublicKey
	verifiedDigest      string
}

type ManifestEnvelope struct {
	KeyID     string `json:"key_id,omitempty"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type TrustUpdate struct {
	AddKeys      map[string]string `json:"add_keys,omitempty"`
	RevokeKeyIDs []string          `json:"revoke_key_ids,omitempty"`
}

type EmergencyStop struct {
	Enabled  bool   `json:"enabled"`
	Reason   string `json:"reason,omitempty"`
	IssuedAt string `json:"issued_at,omitempty"`
}

type RollbackDirective struct {
	Enabled       bool     `json:"enabled"`
	TargetVersion string   `json:"target_version"`
	FromVersions  []string `json:"from_versions"`
	Reason        string   `json:"reason"`
	ExpiresAt     string   `json:"expires_at"`
}

type ManifestLatest struct {
	Version      string `json:"version"`
	ReleaseNotes string `json:"release_notes,omitempty"`
}

type Artifact struct {
	URL                         string   `json:"url"`
	SHA256                      string   `json:"sha256"`
	Size                        int64    `json:"size,omitempty"`
	Signature                   string   `json:"signature,omitempty"`
	SignatureFormat             string   `json:"signature_format,omitempty"`
	AuthenticodePublisherSHA256 []string `json:"authenticode_publisher_sha256,omitempty"`
}

type Rollout struct {
	Percentage            *int     `json:"percentage,omitempty"`
	DownloadSpreadSeconds int      `json:"download_spread_seconds,omitempty"`
	AllowHosts            []string `json:"allow_hosts,omitempty"`
	DenyHosts             []string `json:"deny_hosts,omitempty"`
	AllowDeviceIDs        []string `json:"allow_device_ids,omitempty"`
	DenyDeviceIDs         []string `json:"deny_device_ids,omitempty"`
}

func fetchManifest(location string, opts Options) (Manifest, error) {
	data, err := readSmallURLOrFile(location, 4*1024*1024, opts.AllowInsecureHTTP, opts.CAFile)
	if err != nil {
		return Manifest{}, err
	}
	var envelope ManifestEnvelope
	if err := decodeJSONStrict(data, &envelope); err == nil && strings.TrimSpace(envelope.Payload) != "" {
		keys, revoked, err := effectiveTrustedKeys(opts)
		if err != nil {
			return Manifest{}, err
		}
		keyID := strings.TrimSpace(envelope.KeyID)
		if keyID == "" && len(opts.PublicKey) == ed25519.PublicKeySize {
			keyID = PublicKeyID(opts.PublicKey)
		}
		if keyID == "" {
			for candidate := range keys {
				if revoked[candidate] {
					continue
				}
				if keyID != "" {
					return Manifest{}, fmt.Errorf("legacy signed manifest without key_id is ambiguous across multiple trusted keys")
				}
				keyID = candidate
			}
		}
		if keyID == "" {
			return Manifest{}, fmt.Errorf("signed update manifest requires a trusted public key")
		}
		if revoked[keyID] {
			return Manifest{}, fmt.Errorf("update manifest signer %q is revoked", keyID)
		}
		publicKey, ok := keys[keyID]
		if !ok {
			return Manifest{}, fmt.Errorf("update manifest signer %q is not trusted", keyID)
		}
		payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.Payload))
		if err != nil {
			return Manifest{}, fmt.Errorf("update manifest payload must be base64: %w", err)
		}
		if err := verifyEd25519Signature(payload, envelope.Signature, publicKey); err != nil {
			return Manifest{}, fmt.Errorf("verify update manifest signature: %w", err)
		}
		var manifest Manifest
		if err := decodeJSONStrict(payload, &manifest); err != nil {
			return Manifest{}, fmt.Errorf("parse signed manifest: %w", err)
		}
		manifest.verifiedKeyID = keyID
		manifest.verifiedPublicKey = publicKey
		digest := sha256.Sum256(payload)
		manifest.verifiedDigest = hex.EncodeToString(digest[:])
		return manifest, nil
	}
	if !opts.AllowUnsignedLocal || isHTTPURL(location) {
		return Manifest{}, fmt.Errorf("update manifest must use a signed envelope")
	}
	var manifest Manifest
	if err := decodeJSONStrict(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if manifest.TrustUpdate != nil || manifest.EmergencyStop != nil || manifest.Rollback != nil {
		return Manifest{}, fmt.Errorf("trust updates, emergency stops, and rollbacks require a signed manifest")
	}
	return manifest, nil
}

func checkManifest(manifest Manifest, opts Options, status Status) (result Status, resultErr error) {
	generatedAt, _ := time.Parse(time.RFC3339, strings.TrimSpace(manifest.GeneratedAt))
	status.ManifestGeneration = effectiveManifestGeneration(manifest, generatedAt)
	status.ManifestDigest = manifest.verifiedDigest
	result = status
	if len(manifest.verifiedPublicKey) > 0 {
		if err := validateSignedManifestMetadata(manifest, opts); err != nil {
			result.Reason = manifestMetadataReason(err)
			return result, err
		}
		defer func() {
			if resultErr != nil {
				return
			}
			if err := persistTrustUpdate(opts, manifest.TrustUpdate); err != nil {
				result.Reason = "manifest_trust_update_failed"
				resultErr = fmt.Errorf("apply signed update trust change: %w", err)
				return
			}
			if err := persistManifestAcceptance(opts, manifest); err != nil {
				result.Reason = "manifest_acceptance_state_failed"
				resultErr = err
			}
		}()
	}
	platform := status.Platform
	status.Channel = firstNonEmpty(manifest.Channel, opts.Channel)
	status.LatestVersion = manifest.Latest.Version
	if manifest.SchemaVersion != "1" {
		status.Reason = "manifest_schema_version_unsupported"
		return status, fmt.Errorf("manifest schema_version %q is unsupported", manifest.SchemaVersion)
	}
	if manifest.App != appName {
		status.Reason = "manifest_app_mismatch"
		return status, fmt.Errorf("manifest app %q does not match %q", manifest.App, appName)
	}
	status.SignerKeyID = manifest.verifiedKeyID
	if manifest.EmergencyStop != nil && manifest.EmergencyStop.Enabled {
		status.Status = "emergency_stopped"
		status.Reason = "manifest_emergency_stop"
		status.EmergencyReason = strings.TrimSpace(manifest.EmergencyStop.Reason)
		return status, nil
	}
	if manifest.Latest.Version == "" {
		status.Reason = "manifest_missing_latest_version"
		return status, fmt.Errorf("manifest missing latest.version")
	}
	if _, err := normalizeSemver(manifest.Latest.Version); err != nil {
		status.Reason = "manifest_invalid_latest_version"
		return status, err
	}
	if _, err := normalizeSemver(opts.CurrentVersion); err != nil {
		status.Reason = "invalid_current_version"
		return status, err
	}
	if strings.TrimSpace(opts.DeviceID) == "" {
		status.Reason = "missing_device_id"
		return status, fmt.Errorf("immutable device_id is required for update rollout")
	}
	if opts.DesiredVersion != "" {
		comparison, err := compareVersions(manifest.Latest.Version, opts.DesiredVersion)
		if err != nil {
			status.Reason = "invalid_desired_version"
			return status, err
		}
		if comparison != 0 {
			status.Status = "policy_deferred"
			status.Reason = "manifest_version_does_not_match_server_policy"
			return status, nil
		}
	}
	if manifest.Channel != "" && opts.Channel != "" && manifest.Channel != opts.Channel {
		status.Reason = "manifest_channel_mismatch"
		return status, fmt.Errorf("manifest channel %q does not match requested channel %q", manifest.Channel, opts.Channel)
	}
	if manifest.MinSupportedVersion != "" {
		comparison, err := compareVersions(opts.CurrentVersion, manifest.MinSupportedVersion)
		if err != nil {
			status.Reason = "manifest_invalid_min_supported_version"
			return status, err
		}
		if comparison < 0 {
			status.Reason = "current_version_below_min_supported"
			return status, fmt.Errorf("current version %s is below min supported %s", opts.CurrentVersion, manifest.MinSupportedVersion)
		}
	}
	artifact := manifest.Binaries[platform]
	status.BinaryURL = resolveArtifactLocation(opts.ManifestURL, artifact.URL)
	status.BinarySHA256 = artifact.SHA256
	versionComparison, err := compareVersions(manifest.Latest.Version, opts.CurrentVersion)
	if err != nil {
		status.Reason = "version_compare_failed"
		return status, err
	}
	status.UpdateAvailable = versionComparison > 0
	if versionComparison < 0 {
		if err := validateRollbackDirective(manifest, opts); err != nil {
			status.Reason = "rollback_not_authorized"
			return status, err
		}
		status.UpdateAvailable = true
		status.Reason = "authorized_remote_rollback"
	}
	if status.UpdateAvailable {
		if artifact.URL == "" {
			status.Reason = "missing_platform_binary"
			return status, fmt.Errorf("manifest has no binary for platform %s", platform)
		}
		if artifact.SHA256 == "" {
			status.Reason = "missing_platform_binary_sha256"
			return status, fmt.Errorf("manifest binary for %s has no sha256", platform)
		}
		if err := validateRemoteLocation(status.BinaryURL, opts.AllowInsecureHTTP); err != nil {
			status.Reason = "insecure_platform_binary_url"
			return status, err
		}
		if len(manifest.verifiedPublicKey) > 0 {
			if artifact.SignatureFormat != "" && artifact.SignatureFormat != "ed25519-sha256" {
				status.Reason = "unsupported_platform_binary_signature_format"
				return status, fmt.Errorf("manifest binary for %s uses unsupported signature format %q", platform, artifact.SignatureFormat)
			}
			if strings.TrimSpace(artifact.Signature) == "" {
				status.Reason = "missing_platform_binary_signature"
				return status, fmt.Errorf("manifest binary for %s has no signature", platform)
			}
			signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(artifact.Signature))
			if err != nil {
				status.Reason = "invalid_platform_binary_signature"
				return status, fmt.Errorf("manifest binary signature for %s must be base64: %w", platform, err)
			}
			if len(signature) != ed25519.SignatureSize {
				status.Reason = "invalid_platform_binary_signature"
				return status, fmt.Errorf("manifest binary signature for %s must contain %d bytes", platform, ed25519.SignatureSize)
			}
		}
		for _, thumbprint := range artifact.AuthenticodePublisherSHA256 {
			normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(thumbprint), ":", ""))
			if len(normalized) != 64 {
				status.Reason = "invalid_authenticode_publisher_thumbprint"
				return status, fmt.Errorf("manifest binary for %s has an invalid Authenticode SHA-256 publisher thumbprint", platform)
			}
			if _, err := hex.DecodeString(normalized); err != nil {
				status.Reason = "invalid_authenticode_publisher_thumbprint"
				return status, fmt.Errorf("manifest binary for %s has an invalid Authenticode SHA-256 publisher thumbprint", platform)
			}
		}
		// Managed deployments receive an explicit per-device approval and lease
		// from their server. Reapplying manifest buckets here creates a second,
		// potentially conflicting rollout authority.
		if !opts.ServerManaged {
			allowed, reason, bucket, percentage := rolloutAllows(manifest.Rollout, status)
			status.RolloutBucket = intPtr(bucket)
			status.RolloutPercent = intPtr(percentage)
			if !allowed {
				status.Status = "rollout_deferred"
				status.Reason = reason
				return status, nil
			}
		}
		spread, delay := downloadSpreadDelay(manifest.Rollout, status)
		status.DownloadSpread = intPtr(spread)
		status.DownloadDelay = intPtr(delay)
		status.Status = "update_available"
		return status, nil
	}
	status.Status = "up_to_date"
	return status, nil
}

func validateRollbackDirective(manifest Manifest, opts Options) error {
	if !opts.AllowDowngrade {
		return fmt.Errorf("server policy does not authorize downgrade")
	}
	if len(manifest.verifiedPublicKey) == 0 || manifest.Rollback == nil || !manifest.Rollback.Enabled {
		return fmt.Errorf("signed manifest does not authorize rollback")
	}
	directive := manifest.Rollback
	if strings.TrimSpace(directive.Reason) == "" || strings.TrimSpace(opts.PolicyRollbackReason) == "" {
		return fmt.Errorf("rollback requires manifest and policy reasons")
	}
	if directive.TargetVersion != manifest.Latest.Version {
		return fmt.Errorf("rollback target %q does not match manifest latest %q", directive.TargetVersion, manifest.Latest.Version)
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(directive.ExpiresAt))
	if err != nil || !expiresAt.After(time.Now().UTC()) {
		return fmt.Errorf("rollback authorization is expired or invalid")
	}
	for _, version := range directive.FromVersions {
		comparison, err := compareVersions(version, opts.CurrentVersion)
		if err == nil && comparison == 0 {
			return nil
		}
	}
	return fmt.Errorf("running version %s is not authorized for rollback", opts.CurrentVersion)
}

func intPtr(value int) *int {
	return &value
}

func rolloutAllows(rollout Rollout, status Status) (bool, string, int, int) {
	percentage := 100
	if rollout.Percentage != nil {
		percentage = *rollout.Percentage
	}
	if percentage < 0 {
		percentage = 0
	}
	if percentage > 100 {
		percentage = 100
	}
	bucket := rolloutBucket(status.DeviceID, status.Channel, status.LatestVersion, status.Platform)
	deny := append(append([]string{}, rollout.DenyDeviceIDs...), rollout.DenyHosts...)
	allow := append(append([]string{}, rollout.AllowDeviceIDs...), rollout.AllowHosts...)
	if matchDeviceList(status.DeviceID, deny) {
		return false, "rollout_device_denied", bucket, percentage
	}
	if len(allow) > 0 {
		if matchDeviceList(status.DeviceID, allow) {
			return true, "", bucket, percentage
		}
		return false, "rollout_device_not_allowed", bucket, percentage
	}
	if bucket >= percentage {
		return false, "rollout_percentage_not_matched", bucket, percentage
	}
	return true, "", bucket, percentage
}

func downloadSpreadDelay(rollout Rollout, status Status) (int, int) {
	spread := rollout.DownloadSpreadSeconds
	if spread < 0 {
		spread = 0
	}
	if spread == 0 {
		return 0, 0
	}
	delay := stableBucket(spread+1, status.DeviceID, status.Channel, status.LatestVersion, status.Platform, "download")
	return spread, delay
}

func rolloutBucket(deviceID, channel, version, platform string) int {
	return stableBucket(100, deviceID, channel, version, platform)
}

func stableBucket(modulo int, parts ...string) int {
	if modulo <= 0 {
		return 0
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return int(binary.BigEndian.Uint64(sum[:8]) % uint64(modulo))
}

func matchDeviceList(deviceID string, patterns []string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if pattern == deviceID {
			return true
		}
		matched, err := filepath.Match(pattern, deviceID)
		if err == nil && matched {
			return true
		}
	}
	return false
}
