package agentupdate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type manifestAcceptance struct {
	Channels map[string]acceptedManifest `json:"channels"`
}

type acceptedManifest struct {
	Generation int64  `json:"generation"`
	Digest     string `json:"digest"`
	ExpiresAt  string `json:"expires_at"`
}

type manifestMetadataError struct {
	reason string
	err    error
}

func (e *manifestMetadataError) Error() string { return e.err.Error() }
func (e *manifestMetadataError) Unwrap() error { return e.err }

func manifestMetadataReason(err error) string {
	var metadataErr *manifestMetadataError
	if errors.As(err, &metadataErr) {
		return metadataErr.reason
	}
	return "manifest_metadata_invalid"
}

func metadataError(reason, format string, values ...any) error {
	return &manifestMetadataError{reason: reason, err: fmt.Errorf(format, values...)}
}

func validateSignedManifestMetadata(manifest Manifest, opts Options) error {
	if manifest.SchemaVersion != "1" {
		return metadataError("manifest_schema_version_unsupported", "manifest schema_version %q is unsupported", manifest.SchemaVersion)
	}
	if manifest.App != appName {
		return metadataError("manifest_app_mismatch", "manifest app %q does not match %q", manifest.App, appName)
	}
	generatedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(manifest.GeneratedAt))
	if err != nil {
		return metadataError("manifest_generated_at_invalid", "signed manifest generated_at must use RFC3339")
	}
	generation := effectiveManifestGeneration(manifest, generatedAt)
	if generation <= 0 {
		return metadataError("manifest_generation_missing", "signed manifest requires a positive generation")
	}
	expiresAt, err := effectiveManifestExpiry(manifest, generatedAt)
	if err != nil {
		return metadataError("manifest_expires_at_invalid", "%v", err)
	}
	now := time.Now().UTC()
	if generatedAt.After(now.Add(10 * time.Minute)) {
		return metadataError("manifest_generated_in_future", "signed manifest generated_at is too far in the future")
	}
	if !expiresAt.After(now) {
		return metadataError("manifest_expired", "signed manifest expired at %s", expiresAt.Format(time.RFC3339))
	}
	if !expiresAt.After(generatedAt) {
		return metadataError("manifest_expiry_invalid", "signed manifest expires_at must be after generated_at")
	}
	acceptance, err := loadManifestAcceptance(opts.StateDir)
	if err != nil {
		return metadataError("manifest_acceptance_state_failed", "read manifest acceptance state: %v", err)
	}
	previous, ok := acceptance.Channels[firstNonEmpty(manifest.Channel, opts.Channel)]
	if ok && generation < previous.Generation {
		return metadataError("manifest_generation_replayed", "manifest generation %d is older than accepted generation %d", generation, previous.Generation)
	}
	if ok && generation == previous.Generation && !strings.EqualFold(manifest.verifiedDigest, previous.Digest) {
		return metadataError("manifest_generation_conflict", "manifest generation %d has a different signed digest", generation)
	}
	return nil
}

func persistManifestAcceptance(opts Options, manifest Manifest) error {
	acceptance, err := loadManifestAcceptance(opts.StateDir)
	if err != nil {
		return err
	}
	if acceptance.Channels == nil {
		acceptance.Channels = map[string]acceptedManifest{}
	}
	channel := firstNonEmpty(manifest.Channel, opts.Channel)
	generatedAt, _ := time.Parse(time.RFC3339, strings.TrimSpace(manifest.GeneratedAt))
	expiresAt, _ := effectiveManifestExpiry(manifest, generatedAt)
	acceptance.Channels[channel] = acceptedManifest{
		Generation: effectiveManifestGeneration(manifest, generatedAt),
		Digest:     manifest.verifiedDigest,
		ExpiresAt:  expiresAt.UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(acceptance, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(opts.StateDir, 0700); err != nil {
		return err
	}
	return writeBytesAtomic(filepath.Join(opts.StateDir, "manifest-acceptance.json"), append(data, '\n'), 0600)
}

func effectiveManifestGeneration(manifest Manifest, generatedAt time.Time) int64 {
	if manifest.Generation > 0 {
		return manifest.Generation
	}
	return generatedAt.UTC().UnixNano()
}

func effectiveManifestExpiry(manifest Manifest, generatedAt time.Time) (time.Time, error) {
	if strings.TrimSpace(manifest.ExpiresAt) == "" {
		return generatedAt.Add(14 * 24 * time.Hour), nil
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(manifest.ExpiresAt))
	if err != nil {
		return time.Time{}, fmt.Errorf("signed manifest expires_at must use RFC3339")
	}
	return expiresAt, nil
}

func loadManifestAcceptance(stateDir string) (manifestAcceptance, error) {
	path := filepath.Join(stateDir, "manifest-acceptance.json")
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return manifestAcceptance{Channels: map[string]acceptedManifest{}}, nil
	}
	if err != nil {
		return manifestAcceptance{}, err
	}
	var value manifestAcceptance
	if err := json.Unmarshal(data, &value); err != nil {
		return manifestAcceptance{}, err
	}
	if value.Channels == nil {
		value.Channels = map[string]acceptedManifest{}
	}
	return value, nil
}
