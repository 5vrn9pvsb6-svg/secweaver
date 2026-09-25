package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"secweaver-agent/pkg/agentlicense"
)

var errRemoteConfigApplied = errors.New("secweaver-agent remote config applied; restart required")

func runScheduledRemoteConfig(ctx context.Context, cfg scheduledRemoteConfig) error {
	initialWait := cfg.InitialDelay + stableJitter(cfg.Jitter, licenseJitterSeed(cfg.License, cfg.EnterpriseID)+"|remote-config")
	if initialWait > 0 {
		fmt.Fprintf(os.Stderr, "remote config pull enabled: interval=%s initial_wait=%s signed=%v\n", cfg.Interval, initialWait, !cfg.AllowUnsigned)
		if !sleepContext(ctx, initialWait) {
			return nil
		}
	}
	retryDelay := time.Minute
	const maximumRetryDelay = 15 * time.Minute
	for {
		applied, err := pullAndApplyRemoteConfig(ctx, cfg)
		if err != nil {
			if agentlicense.IsTransient(err) {
				wait := remoteConfigRetryDelay(retryDelay, maximumRetryDelay, licenseJitterSeed(cfg.License, cfg.EnterpriseID))
				fmt.Fprintf(os.Stderr, "remote config pull unavailable; Agent remains active and will retry in %s: %v\n", wait, err)
				if !sleepContext(ctx, wait) {
					return nil
				}
				if retryDelay < maximumRetryDelay {
					retryDelay *= 2
					if retryDelay > maximumRetryDelay {
						retryDelay = maximumRetryDelay
					}
				}
				continue
			}
			fmt.Fprintf(os.Stderr, "remote config pull warning; Agent remains active and will retry on the next interval: %v\n", err)
		} else {
			retryDelay = time.Minute
		}
		if applied {
			return errRemoteConfigApplied
		}
		if !sleepContext(ctx, cfg.Interval) {
			return nil
		}
	}
}

// remoteConfigRetryDelay adds stable per-device jitter without exceeding the
// retry ceiling, preventing a recovered control plane from receiving a fleet-wide
// synchronized retry burst.
func remoteConfigRetryDelay(base, maximum time.Duration, seed string) time.Duration {
	if base <= 0 {
		base = time.Minute
	}
	if maximum < base {
		maximum = base
	}
	wait := base + stableJitter(base/4, seed+"|remote-config-retry")
	if wait > maximum {
		return maximum
	}
	return wait
}

func pullAndApplyRemoteConfig(ctx context.Context, cfg scheduledRemoteConfig) (bool, error) {
	checkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	licenseCfg := cfg.License
	if strings.TrimSpace(cfg.URL) != "" {
		licenseCfg.ServerURL = strings.TrimSpace(cfg.URL)
	}
	resp, err := (agentlicense.Client{}).FetchRemoteConfig(checkCtx, licenseCfg, cfg.EnterpriseID, version)
	if err != nil {
		return false, err
	}
	configBytes := bytesTrimSpace(resp.Config)
	if len(configBytes) == 0 {
		return false, fmt.Errorf("remote config is empty")
	}
	if err := verifyRemoteConfigIntegrity(configBytes, resp, cfg); err != nil {
		return false, err
	}
	if err := validateRemoteAgentConfig(configBytes, cfg.EnterpriseID); err != nil {
		return false, err
	}
	current, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		return false, err
	}
	configBytes, err = preserveDeploymentMode(current, configBytes)
	if err != nil {
		return false, err
	}
	if string(bytesTrimSpace(current)) == string(configBytes) {
		return false, nil
	}
	if err := writeFileAtomic(cfg.ConfigPath, append(configBytes, '\n'), 0600); err != nil {
		return false, err
	}
	fmt.Fprintf(os.Stderr, "remote config applied: path=%s sha256=%s\n", cfg.ConfigPath, sha256Hex(configBytes))
	return true, nil
}

func verifyRemoteConfigIntegrity(configBytes []byte, resp agentlicense.RemoteConfigResponse, cfg scheduledRemoteConfig) error {
	if strings.TrimSpace(resp.SHA256) != "" && !strings.EqualFold(strings.TrimSpace(resp.SHA256), sha256Hex(configBytes)) {
		return fmt.Errorf("remote config sha256 mismatch")
	}
	if len(cfg.PublicKey) == 0 {
		if cfg.AllowUnsigned {
			return nil
		}
		return fmt.Errorf("remote config signature required but public_key is not configured")
	}
	signatureText := strings.TrimSpace(resp.Signature)
	if signatureText == "" {
		return fmt.Errorf("remote config signature missing")
	}
	signature, err := base64.StdEncoding.DecodeString(signatureText)
	if err != nil {
		return fmt.Errorf("remote config signature must be base64: %w", err)
	}
	if !ed25519.Verify(cfg.PublicKey, configBytes, signature) {
		return fmt.Errorf("remote config signature verification failed")
	}
	return nil
}

func validateRemoteAgentConfig(configBytes []byte, enterpriseID string) error {
	tmp, err := os.CreateTemp("", "secweaver-agent-remote-config-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(configBytes); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	cfg, err := loadConfig(tmpPath)
	if err != nil {
		return err
	}
	if cfg.EnterpriseID != enterpriseID {
		return fmt.Errorf("remote config enterprise_id mismatch: got %s want %s", cfg.EnterpriseID, enterpriseID)
	}
	if _, err := enabledModules(cfg); err != nil {
		return err
	}
	if _, err := scheduledUpdateFromConfig(cfg.Update); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	licenseCfg := cfg.License.Normalize()
	if err := licenseCfg.Validate(); err != nil {
		return fmt.Errorf("license: %w", err)
	}
	if _, err := scheduledRemoteConfigFromConfig(cfg.RemoteConfig, tmpPath, licenseCfg, cfg.EnterpriseID); err != nil {
		return fmt.Errorf("remote_config: %w", err)
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func bytesTrimSpace(data []byte) []byte {
	return []byte(strings.TrimSpace(string(data)))
}

func isRemoteLocation(location string) bool {
	value := strings.ToLower(strings.TrimSpace(location))
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
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
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
