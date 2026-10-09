package agentupdate

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
)

// updateFailure carries stable, secret-free telemetry separately from the local
// diagnostic. Local configuration failures must not look like retryable network
// outages in the control plane. Wrapping retains errors.Is/As and Retry-After.
type updateFailure struct {
	reason string
	class  string
	err    error
}

func (e *updateFailure) Error() string { return e.err.Error() }
func (e *updateFailure) Unwrap() error { return e.err }

func failUpdate(reason, class string, err error) error {
	return &updateFailure{reason: reason, class: class, err: err}
}

// readUpdateCA bounds CA reads and rejects special files before reading them.
// An absent override means system trust, never disabled TLS verification.
func readUpdateCA(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		reason := "update_ca_unreadable"
		if errors.Is(err, os.ErrNotExist) {
			reason = "update_ca_missing"
		}
		return nil, failUpdate(reason, "configuration", fmt.Errorf("read update CA file: %w", err))
	}
	if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return nil, failUpdate("update_ca_invalid", "configuration", errors.New("update CA must be a regular PEM file no larger than 1 MiB"))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, failUpdate("update_ca_unreadable", "configuration", fmt.Errorf("read update CA file: %w", err))
	}
	defer file.Close()
	pemData, err := readLimited(file, 1024*1024)
	if err != nil {
		return nil, failUpdate("update_ca_unreadable", "configuration", fmt.Errorf("read update CA file: %w", err))
	}
	if !x509.NewCertPool().AppendCertsFromPEM(pemData) {
		return nil, failUpdate("update_ca_invalid", "configuration", errors.New("update CA file does not contain a valid PEM certificate"))
	}
	return pemData, nil
}

// ValidateCAFile is a local, read-only installation/doctor check. Runtime update
// errors remain isolated from collectors; callers decide whether to stop a new
// installation rather than making this a fatal Agent startup validation.
func ValidateCAFile(path string) error {
	_, err := readUpdateCA(path)
	return err
}

// ValidateTrust checks configured AND persisted keys without changing the trust
// store or contacting a server. Managed installers require an active trust key;
// standalone unsigned deployments retain their existing compatibility behavior.
func ValidateTrust(opts Options, requireKey bool) error {
	opts = normalizeOptions(opts)
	keys, revoked, err := effectiveTrustedKeys(opts)
	if err != nil {
		return failUpdate("update_trust_invalid", "configuration", err)
	}
	if requireKey {
		for id := range keys {
			if !revoked[id] {
				return nil
			}
		}
		return failUpdate("update_trust_missing", "configuration", errors.New("managed updates require a non-revoked Ed25519 public key; provision public_key or trusted_public_keys from the release operator"))
	}
	return nil
}

// classifyFetchError keeps certificate/configuration failures out of transient
// transport statistics. HTTP 429/5xx and connection errors still use backoff.
func classifyFetchError(err error) error {
	var failure *updateFailure
	if errors.As(err, &failure) {
		return err
	}
	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		return failUpdate("update_tls_verification_failed", "configuration", err)
	}
	var status *HTTPStatusError
	if errors.As(err, &status) && status.StatusCode >= 400 && status.StatusCode < 500 && status.StatusCode != 408 && status.StatusCode != 429 {
		return failUpdate("manifest_http_rejected", "configuration", err)
	}
	return err
}
