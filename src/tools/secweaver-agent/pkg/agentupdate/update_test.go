package agentupdate

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestInstallVerifiesManifestAndArtifactSignatures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows schedules replacement after process exit")
	}
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifactPayload := []byte("signed secweaver-agent")
	artifactPath := filepath.Join(dir, "new-agent")
	if err := os.WriteFile(artifactPath, artifactPayload, 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(artifactPayload)
	manifest := Manifest{
		SchemaVersion: "1",
		App:           appName,
		Channel:       "stable",
		Latest:        ManifestLatest{Version: "0.3.0"},
		Binaries: map[string]Artifact{
			runtime.GOOS + "_" + runtime.GOARCH: {
				URL:       artifactPath,
				SHA256:    hex.EncodeToString(sum[:]),
				Size:      int64(len(artifactPayload)),
				Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, artifactPayload)),
			},
		},
	}
	manifestPath := writeSignedManifest(t, dir, manifest, privateKey)
	selfPath := filepath.Join(dir, "secweaver-agent")
	if err := os.WriteFile(selfPath, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	status, err := Install(Options{
		ManifestURL:    manifestPath,
		Channel:        "stable",
		CurrentVersion: "0.2.0",
		StateDir:       filepath.Join(dir, "state"),
		SelfPath:       selfPath,
		DeviceID:       "device-signed-01",
		PublicKey:      publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "installed" {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestCheckRejectsTamperedSignedManifest(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"schema_version":"1","app":"secweaver-agent","channel":"stable","latest":{"version":"0.3.0"},"binaries":{}}`)
	envelope := ManifestEnvelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
	envelope.Payload = base64.StdEncoding.EncodeToString(append(payload, ' '))
	body, _ := json.Marshal(envelope)
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(Options{ManifestURL: path, Channel: "stable", CurrentVersion: "0.2.0", PublicKey: publicKey}); err == nil {
		t.Fatal("expected tampered manifest signature to be rejected")
	}
}

func TestReadManifestRejectsHTTPByDefault(t *testing.T) {
	if _, err := readSmallURLOrFile("http://updates.example.com/manifest.json", 1024, false, ""); err == nil {
		t.Fatal("expected insecure HTTP URL to be rejected")
	}
}

func TestHTTPClientRejectsHTTPSDowngradeRedirect(t *testing.T) {
	client, err := newHTTPClient(time.Second, false, "")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "http://updates.example.com/manifest.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(request, nil); err == nil {
		t.Fatal("expected HTTPS-to-HTTP redirect to be rejected")
	}
}

func TestParseRetryAfterAndWrappedStatusError(t *testing.T) {
	now := time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
	if got := parseRetryAfter("120", now); got != 2*time.Minute {
		t.Fatalf("delta Retry-After = %s", got)
	}
	if got := parseRetryAfter(now.Add(5*time.Minute).Format(http.TimeFormat), now); got != 5*time.Minute {
		t.Fatalf("date Retry-After = %s", got)
	}
	statusErr := &HTTPStatusError{RetryDelay: 3 * time.Minute}
	if got := RetryAfter(errors.Join(errors.New("download failed"), statusErr)); got != 3*time.Minute {
		t.Fatalf("wrapped Retry-After = %s", got)
	}
}

func TestArtifactDownloadStopsOnContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		for {
			select {
			case <-r.Context().Done():
				return
			default:
				_, _ = w.Write(make([]byte, 64*1024))
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				time.Sleep(time.Millisecond)
			}
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	stateDir := t.TempDir()
	if _, err := downloadArtifact(ctx, server.URL, true, "", stateDir); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("download error = %v, want context deadline", err)
	}
	entries, err := os.ReadDir(filepath.Join(stateDir, "downloads"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("cancelled download left temporary files: %v", entries)
	}
}

func TestSignedManifestGenerationPreventsReplayAndEquivocation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	manifestDir := t.TempDir()
	first := signedArtifactManifest(t, manifestDir, "0.3.1", privateKey)
	first.Generation = 200
	firstPath := writeSignedManifest(t, manifestDir, first, privateKey)
	opts := Options{ManifestURL: firstPath, CurrentVersion: "0.3.0", Channel: "stable", DeviceID: "device-replay-01", StateDir: stateDir, PublicKey: publicKey}
	if _, err := Check(opts); err != nil {
		t.Fatal(err)
	}

	replayedDir := t.TempDir()
	replayed := signedArtifactManifest(t, replayedDir, "0.3.2", privateKey)
	replayed.Generation = 199
	opts.ManifestURL = writeSignedManifest(t, replayedDir, replayed, privateKey)
	status, err := Check(opts)
	if err == nil || status.Reason != "manifest_generation_replayed" {
		t.Fatalf("replayed manifest status=%+v err=%v", status, err)
	}

	conflictDir := t.TempDir()
	conflict := signedArtifactManifest(t, conflictDir, "0.3.3", privateKey)
	conflict.Generation = 200
	opts.ManifestURL = writeSignedManifest(t, conflictDir, conflict, privateKey)
	status, err = Check(opts)
	if err == nil || status.Reason != "manifest_generation_conflict" {
		t.Fatalf("conflicting manifest status=%+v err=%v", status, err)
	}
}

func TestRemoteRollbackRequiresServerAndSignedManifestAuthorization(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	manifest := signedArtifactManifest(t, dir, "0.3.1", privateKey)
	manifest.Rollback = &RollbackDirective{
		Enabled: true, TargetVersion: "0.3.1", FromVersions: []string{"0.3.2"},
		Reason: "regression in 0.3.2", ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}
	path := writeSignedManifest(t, dir, manifest, privateKey)
	opts := Options{ManifestURL: path, CurrentVersion: "0.3.2", DesiredVersion: "0.3.1", Channel: "stable", DeviceID: "device-rollback-01", StateDir: t.TempDir(), PublicKey: publicKey}
	if status, err := Check(opts); err == nil || status.Reason != "rollback_not_authorized" {
		t.Fatalf("rollback without server authorization status=%+v err=%v", status, err)
	}
	opts.AllowDowngrade = true
	opts.PolicyRollbackReason = "production rollback approved"
	status, err := Check(opts)
	if err != nil || !status.UpdateAvailable || status.Status != "update_available" || status.Reason != "authorized_remote_rollback" {
		t.Fatalf("authorized rollback status=%+v err=%v", status, err)
	}
}

func TestReadSmallURLUsesConfiguredCA(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SecWeaver test update CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(caPath, pemData, 0600); err != nil {
		t.Fatal(err)
	}
	client, err := newHTTPClient(time.Second, false, caPath)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("configured CA was not attached to the update HTTP client")
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: transport.TLSClientConfig.RootCAs}); err != nil {
		t.Fatalf("configured update CA is not trusted: %v", err)
	}
}

func writeSignedManifest(t *testing.T, dir string, manifest Manifest, privateKey ed25519.PrivateKey) string {
	t.Helper()
	prepareSignedTestManifest(&manifest)
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope := ManifestEnvelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckUpdateFromLocalManifest(t *testing.T) {
	dir := t.TempDir()
	newPayload := []byte("new secweaver-agent")
	newBinary := filepath.Join(dir, "new-agent")
	if err := os.WriteFile(newBinary, newPayload, 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(newPayload)
	manifest := `{
  "schema_version": "1",
  "app": "secweaver-agent",
  "channel": "stable",
  "latest": {"version": "0.3.0"},
  "binaries": {
    "` + runtime.GOOS + `_` + runtime.GOARCH + `": {
      "url": "new-agent",
      "sha256": "` + hex.EncodeToString(sum[:]) + `",
      "size": ` + strconv.Itoa(len(newPayload)) + `
    }
  }
}`
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	status, err := Check(Options{ManifestURL: manifestPath, Channel: "stable", CurrentVersion: "0.2.0", DeviceID: "device-local-01", AllowUnsignedLocal: true})
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "update_available" || !status.UpdateAvailable || status.LatestVersion != "0.3.0" {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.BinaryURL != newBinary {
		t.Fatalf("binary url = %q, want %q", status.BinaryURL, newBinary)
	}
}

func TestInstallUpdateReplacesBinaryAndRollbackRestores(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows schedules replacement after process exit")
	}
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	selfPath := filepath.Join(dir, "secweaver-agent")
	newBinary := filepath.Join(dir, "new-agent")
	oldPayload := []byte("old secweaver-agent")
	newPayload := []byte("new secweaver-agent")
	if err := os.WriteFile(selfPath, oldPayload, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newBinary, newPayload, 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(newPayload)
	manifest := `{
  "schema_version": "1",
  "app": "secweaver-agent",
  "channel": "stable",
  "latest": {"version": "0.3.0"},
  "binaries": {
    "` + runtime.GOOS + `_` + runtime.GOARCH + `": {
      "url": "` + newBinary + `",
      "sha256": "` + hex.EncodeToString(sum[:]) + `"
    }
  }
}`
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	status, err := Install(Options{
		ManifestURL:        manifestPath,
		Channel:            "stable",
		CurrentVersion:     "0.2.0",
		StateDir:           stateDir,
		SelfPath:           selfPath,
		DeviceID:           "device-install-01",
		AllowUnsignedLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "installed" || status.BackupPath == "" || status.InstalledPath != selfPath {
		t.Fatalf("unexpected install status: %+v", status)
	}
	got, err := os.ReadFile(selfPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newPayload) {
		t.Fatalf("installed payload = %q", got)
	}
	stateBytes, err := os.ReadFile(filepath.Join(stateDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state State
	if err := json.Unmarshal(stateBytes, &state); err != nil {
		t.Fatal(err)
	}
	if state.LastUpdateStatus != "installed" || state.PreviousBinary == "" {
		t.Fatalf("unexpected state: %+v", state)
	}

	rollbackStatus, err := Rollback(Options{
		CurrentVersion: "0.3.0",
		StateDir:       stateDir,
		SelfPath:       selfPath,
		DeviceID:       "device-install-01",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rollbackStatus.Status != "rolled_back" {
		t.Fatalf("unexpected rollback status: %+v", rollbackStatus)
	}
	rolledBack, err := os.ReadFile(selfPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(rolledBack) != string(oldPayload) {
		t.Fatalf("rolled back payload = %q", rolledBack)
	}
}

func TestCheckRejectsWrongAppManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{
  "schema_version": "1",
  "app": "other-agent",
  "channel": "stable",
  "latest": {"version": "0.3.0"},
  "binaries": {}
}`), 0600); err != nil {
		t.Fatal(err)
	}
	status, err := Check(Options{ManifestURL: path, Channel: "stable", CurrentVersion: "0.2.0", AllowUnsignedLocal: true})
	if err == nil {
		t.Fatal("expected app mismatch error")
	}
	if status.Reason != "manifest_app_mismatch" {
		t.Fatalf("reason = %q", status.Reason)
	}
}

func TestCheckDefersWhenRolloutPercentageDoesNotMatch(t *testing.T) {
	path := writeRolloutManifest(t, `{"percentage": 0}`)
	status, err := Check(Options{
		ManifestURL:        path,
		Channel:            "stable",
		CurrentVersion:     "0.2.0",
		HostID:             "web-01",
		AllowUnsignedLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "rollout_deferred" || status.Reason != "rollout_percentage_not_matched" || !status.UpdateAvailable {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestManagedCheckUsesServerApprovalInsteadOfManifestRollout(t *testing.T) {
	path := writeRolloutManifest(t, `{"percentage": 0, "deny_device_ids": ["device-managed-01"]}`)
	status, err := Check(Options{
		ManifestURL:        path,
		Channel:            "stable",
		CurrentVersion:     "0.2.0",
		DesiredVersion:     "0.3.0",
		DeviceID:           "device-managed-01",
		ServerManaged:      true,
		AllowUnsignedLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "update_available" || status.RolloutBucket != nil || status.RolloutPercent != nil {
		t.Fatalf("managed update reapplied manifest rollout: %+v", status)
	}
}

func TestCheckAllowsExplicitRolloutHost(t *testing.T) {
	path := writeRolloutManifest(t, `{"percentage": 0, "allow_hosts": ["web-01"]}`)
	status, err := Check(Options{
		ManifestURL:        path,
		Channel:            "stable",
		CurrentVersion:     "0.2.0",
		HostID:             "web-01",
		AllowUnsignedLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "update_available" {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestCheckDeniesRolloutHost(t *testing.T) {
	path := writeRolloutManifest(t, `{"percentage": 100, "deny_hosts": ["web-*"]}`)
	status, err := Check(Options{
		ManifestURL:        path,
		Channel:            "stable",
		CurrentVersion:     "0.2.0",
		HostID:             "web-01",
		AllowUnsignedLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "rollout_deferred" || status.Reason != "rollout_device_denied" {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestCheckReportsDownloadSpreadDelay(t *testing.T) {
	path := writeRolloutManifest(t, `{"percentage": 100, "download_spread_seconds": 3600}`)
	status, err := Check(Options{
		ManifestURL:        path,
		Channel:            "stable",
		CurrentVersion:     "0.2.0",
		HostID:             "web-01",
		AllowUnsignedLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "update_available" {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.DownloadSpread == nil || *status.DownloadSpread != 3600 {
		t.Fatalf("download spread = %+v, want 3600", status.DownloadSpread)
	}
	if status.DownloadDelay == nil || *status.DownloadDelay < 0 || *status.DownloadDelay > 3600 {
		t.Fatalf("download delay = %+v, want 0..3600", status.DownloadDelay)
	}
}

func TestCheckDefersManifestThatDoesNotMatchDesiredVersion(t *testing.T) {
	path := writeRolloutManifest(t, `{"percentage": 100}`)
	status, err := Check(Options{
		ManifestURL:        path,
		Channel:            "stable",
		CurrentVersion:     "0.2.0",
		DesiredVersion:     "0.4.0",
		DeviceID:           "device-policy-01",
		AllowUnsignedLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "policy_deferred" || status.Reason != "manifest_version_does_not_match_server_policy" {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestFailedPostUpdateActivationAutomaticallyRollsBack(t *testing.T) {
	opts, selfPath := installUnsignedTestUpdate(t)
	if _, err := os.Stat(filepath.Join(opts.StateDir, "health.pending")); err != nil {
		t.Fatalf("missing external recovery marker: %v", err)
	}
	pending, status, err := PrepareHealthCheck(opts, time.Minute)
	if err != nil || !pending || status.Status != "health_check_pending" {
		t.Fatalf("first health check: pending=%v status=%+v err=%v", pending, status, err)
	}
	pending, status, err = PrepareHealthCheck(opts, time.Minute)
	if err != nil || pending || status.Status != "rolled_back" {
		t.Fatalf("second health check: pending=%v status=%+v err=%v", pending, status, err)
	}
	payload, err := os.ReadFile(selfPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "old secweaver-agent" {
		t.Fatalf("automatic rollback payload = %q", payload)
	}
	state, err := LoadState(opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.HealthPending || state.LastUpdateStatus != "rolled_back" || state.RollbackReason != "restarted_before_health_confirmation" {
		t.Fatalf("unexpected rollback state: %+v", state)
	}
}

func TestHealthyPostUpdateActivationIsCommitted(t *testing.T) {
	opts, _ := installUnsignedTestUpdate(t)
	pending, _, err := PrepareHealthCheck(opts, time.Minute)
	if err != nil || !pending {
		t.Fatalf("prepare health check: pending=%v err=%v", pending, err)
	}
	state, err := MarkHealthy(opts)
	if err != nil {
		t.Fatal(err)
	}
	if state.HealthPending || state.LastUpdateStatus != "healthy" || state.HealthConfirmedAt == "" {
		t.Fatalf("unexpected healthy state: %+v", state)
	}
	if _, err := os.Stat(filepath.Join(opts.StateDir, "health.pending")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery marker was not cleared: %v", err)
	}
}

func TestTargetVersionMismatchAutomaticallyRollsBack(t *testing.T) {
	opts, selfPath := installUnsignedTestUpdate(t)
	opts.CurrentVersion = "0.3.1"

	pending, status, err := PrepareHealthCheck(opts, time.Minute)
	if err != nil || pending || status.Status != "rolled_back" {
		t.Fatalf("target mismatch: pending=%v status=%+v err=%v", pending, status, err)
	}
	payload, err := os.ReadFile(selfPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "old secweaver-agent" {
		t.Fatalf("target mismatch did not restore the previous binary: %q", payload)
	}
	state, err := LoadState(opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.HealthPending || state.RollbackReason != "target_version_not_running" {
		t.Fatalf("unexpected mismatch rollback state: %+v", state)
	}
}

func TestSemverComparisonUsesPrereleasePrecedence(t *testing.T) {
	tests := []struct {
		left  string
		right string
		want  int
	}{
		{left: "1.0.0-rc.1", right: "1.0.0", want: -1},
		{left: "1.0.0-alpha.2", right: "1.0.0-alpha.10", want: -1},
		{left: "1.2.3+build.1", right: "1.2.3+build.9", want: 0},
		{left: "v2.0.0", right: "1.99.99", want: 1},
	}
	for _, test := range tests {
		got, err := compareVersions(test.left, test.right)
		if err != nil {
			t.Fatalf("compare %s and %s: %v", test.left, test.right, err)
		}
		if got != test.want {
			t.Fatalf("compare %s and %s = %d, want %d", test.left, test.right, got, test.want)
		}
	}
	if _, err := compareVersions("01.2.3", "1.2.3"); err == nil {
		t.Fatal("expected a leading-zero version to be rejected")
	}
}

func TestAcquireLockRemovesOnlyExpiredLock(t *testing.T) {
	stateDir := t.TempDir()
	lockPath := filepath.Join(stateDir, "update.lock")
	if err := os.WriteFile(lockPath, []byte("legacy-pid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireLock(stateDir, time.Hour); err == nil {
		t.Fatal("expected a fresh lock to remain active")
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}
	unlock, err := acquireLock(stateDir, time.Hour)
	if err != nil {
		t.Fatalf("replace expired lock: %v", err)
	}
	unlock()
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned lock was not removed: %v", err)
	}
}

func TestBackupRetentionRemovesOldestFiles(t *testing.T) {
	dir := t.TempDir()
	selfPath := filepath.Join(dir, "secweaver-agent")
	if err := os.WriteFile(selfPath, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	for index := 0; index < 5; index++ {
		if _, err := backupCurrentBinary(selfPath, stateDir, "0.3.0", 2); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(stateDir, "backups"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("retained backups = %d, want 2", len(entries))
	}
}

func TestDiskSpaceCheckFailsBeforeUpdate(t *testing.T) {
	dir := t.TempDir()
	selfPath := filepath.Join(dir, "secweaver-agent")
	if err := os.WriteFile(selfPath, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	original := availableDiskBytes
	availableDiskBytes = func(string) (uint64, error) { return 1, nil }
	t.Cleanup(func() { availableDiskBytes = original })
	err := ensureUpdateDiskSpace(Options{StateDir: filepath.Join(dir, "state"), MinFreeSpaceBytes: 1024}, selfPath, 1024)
	if err == nil {
		t.Fatal("expected insufficient disk space")
	}
}

func TestSigningKeyRotationAndRevocation(t *testing.T) {
	dir := t.TempDir()
	oldPublic, oldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newKeyID := PublicKeyID(newPublic)
	stateDir := filepath.Join(dir, "state")
	opts := Options{
		Channel:        "stable",
		CurrentVersion: "0.2.0",
		DeviceID:       "device-rotation-01",
		StateDir:       stateDir,
		PublicKey:      oldPublic,
	}

	firstDir := filepath.Join(dir, "first")
	if err := os.MkdirAll(firstDir, 0700); err != nil {
		t.Fatal(err)
	}
	firstManifest := signedArtifactManifest(t, firstDir, "0.3.0", oldPrivate)
	firstManifest.TrustUpdate = &TrustUpdate{AddKeys: map[string]string{
		newKeyID: base64.StdEncoding.EncodeToString(newPublic),
	}}
	opts.ManifestURL = writeSignedManifestWithKeyID(t, firstDir, firstManifest, oldPrivate, PublicKeyID(oldPublic))
	if status, err := Check(opts); err != nil || status.Status != "update_available" {
		t.Fatalf("add rotated key: status=%+v err=%v", status, err)
	}

	secondDir := filepath.Join(dir, "second")
	if err := os.MkdirAll(secondDir, 0700); err != nil {
		t.Fatal(err)
	}
	secondManifest := signedArtifactManifest(t, secondDir, "0.4.0", newPrivate)
	secondManifest.TrustUpdate = &TrustUpdate{RevokeKeyIDs: []string{PublicKeyID(oldPublic)}}
	opts.ManifestURL = writeSignedManifestWithKeyID(t, secondDir, secondManifest, newPrivate, newKeyID)
	if status, err := Check(opts); err != nil || status.SignerKeyID != newKeyID {
		t.Fatalf("use new key and revoke old: status=%+v err=%v", status, err)
	}

	thirdDir := filepath.Join(dir, "third")
	if err := os.MkdirAll(thirdDir, 0700); err != nil {
		t.Fatal(err)
	}
	oldManifest := signedArtifactManifest(t, thirdDir, "0.5.0", oldPrivate)
	opts.ManifestURL = writeSignedManifestWithKeyID(t, thirdDir, oldManifest, oldPrivate, PublicKeyID(oldPublic))
	if _, err := Check(opts); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revoked old signer to fail, got %v", err)
	}
}

func TestSignedEmergencyStopBlocksUpdate(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		SchemaVersion: "1",
		App:           appName,
		Channel:       "stable",
		EmergencyStop: &EmergencyStop{Enabled: true, Reason: "rollback release signing incident"},
	}
	path := writeSignedManifestWithKeyID(t, dir, manifest, privateKey, PublicKeyID(publicKey))
	status, err := Check(Options{
		ManifestURL:    path,
		Channel:        "stable",
		CurrentVersion: "0.3.0",
		StateDir:       filepath.Join(dir, "state"),
		PublicKey:      publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "emergency_stopped" || status.Reason != "manifest_emergency_stop" || status.EmergencyReason == "" {
		t.Fatalf("unexpected emergency stop status: %+v", status)
	}
}

func signedArtifactManifest(t *testing.T, dir, version string, privateKey ed25519.PrivateKey) Manifest {
	t.Helper()
	payload := []byte("agent-" + version)
	path := filepath.Join(dir, "secweaver-agent")
	if err := os.WriteFile(path, payload, 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	return Manifest{
		SchemaVersion: "1",
		App:           appName,
		Channel:       "stable",
		Latest:        ManifestLatest{Version: version},
		Binaries: map[string]Artifact{
			runtime.GOOS + "_" + runtime.GOARCH: {
				URL:       path,
				SHA256:    hex.EncodeToString(sum[:]),
				Size:      int64(len(payload)),
				Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
			},
		},
	}
}

func writeSignedManifestWithKeyID(t *testing.T, dir string, manifest Manifest, privateKey ed25519.PrivateKey, keyID string) string {
	t.Helper()
	prepareSignedTestManifest(&manifest)
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope := ManifestEnvelope{
		KeyID:     keyID,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func prepareSignedTestManifest(manifest *Manifest) {
	if manifest.GeneratedAt == "" {
		manifest.GeneratedAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	}
}

func installUnsignedTestUpdate(t *testing.T) (Options, string) {
	t.Helper()
	dir := t.TempDir()
	selfPath := filepath.Join(dir, "secweaver-agent")
	newBinary := filepath.Join(dir, "new-agent")
	oldPayload := []byte("old secweaver-agent")
	newPayload := []byte("new secweaver-agent")
	if err := os.WriteFile(selfPath, oldPayload, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newBinary, newPayload, 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(newPayload)
	manifest := `{"schema_version":"1","app":"secweaver-agent","channel":"stable","latest":{"version":"0.3.0"},"binaries":{"` + runtime.GOOS + `_` + runtime.GOARCH + `":{"url":"` + newBinary + `","sha256":"` + hex.EncodeToString(sum[:]) + `"}}}`
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		ManifestURL:        manifestPath,
		Channel:            "stable",
		CurrentVersion:     "0.3.0",
		StateDir:           filepath.Join(dir, "state"),
		SelfPath:           selfPath,
		DeviceID:           "device-health-01",
		AllowUnsignedLocal: true,
	}
	installOpts := opts
	installOpts.CurrentVersion = "0.2.0"
	status, err := Install(installOpts)
	if err != nil || status.Status != "installed" {
		t.Fatalf("install: status=%+v err=%v", status, err)
	}
	return opts, selfPath
}

func TestInstallKeepsDurableRecoveryJournalWhenFinalStateWriteFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows replacement is covered by the SCM integration test")
	}
	dir := t.TempDir()
	selfPath := filepath.Join(dir, "secweaver-agent")
	if err := os.WriteFile(selfPath, []byte("old-agent"), 0755); err != nil {
		t.Fatal(err)
	}
	manifestPath := writeRolloutManifest(t, `{"percentage": 100}`)
	originalWriter := writeInstallState
	writes := 0
	writeInstallState = func(path string, state State) error {
		writes++
		if writes == 2 {
			return errors.New("injected final state write failure")
		}
		return writeState(path, state)
	}
	t.Cleanup(func() { writeInstallState = originalWriter })

	opts := Options{
		ManifestURL:        manifestPath,
		Channel:            "stable",
		CurrentVersion:     "0.2.0",
		StateDir:           filepath.Join(dir, "state"),
		SelfPath:           selfPath,
		DeviceID:           "device-transaction-01",
		AllowUnsignedLocal: true,
	}
	status, err := Install(opts)
	if err == nil || status.Reason != "state_write_failed_after_install" || !status.CommitStarted {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	state, err := LoadState(opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.Phase != "commit_prepared" || !state.HealthPending || state.TargetVersion != "0.3.0" || state.PreviousBinary == "" {
		t.Fatalf("prepared recovery journal was not durable: %+v", state)
	}
	body, err := os.ReadFile(selfPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "new secweaver-agent" {
		t.Fatalf("replacement did not reach the explicit commit point: %q", body)
	}
}

func TestInstallCommitGuardPreventsBinaryReplacement(t *testing.T) {
	dir := t.TempDir()
	selfPath := filepath.Join(dir, "secweaver-agent")
	if err := os.WriteFile(selfPath, []byte("old-agent"), 0755); err != nil {
		t.Fatal(err)
	}
	guardErr := errors.New("server policy revoked before commit")
	status, err := Install(Options{
		ManifestURL:        writeRolloutManifest(t, `{"percentage": 100}`),
		Channel:            "stable",
		CurrentVersion:     "0.2.0",
		StateDir:           filepath.Join(dir, "state"),
		SelfPath:           selfPath,
		DeviceID:           "device-commit-guard-01",
		AllowUnsignedLocal: true,
		CommitGuard: func(context.Context) error {
			return guardErr
		},
	})
	if !errors.Is(err, guardErr) || status.CommitStarted || status.Reason != "update_cancelled_before_commit" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	payload, readErr := os.ReadFile(selfPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(payload) != "old-agent" {
		t.Fatalf("commit guard allowed binary replacement: %q", payload)
	}
}

func TestWriteBytesAtomicCreatesDirectoryAndReplacesExistingFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")
	path := filepath.Join(dir, "state.json")
	if err := writeBytesAtomic(path, []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeBytesAtomic(path, []byte("new\n"), 0600); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "new\n" {
		t.Fatalf("atomic replacement wrote %q", payload)
	}
	temporaryFiles, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temporaryFiles) != 0 {
		t.Fatalf("atomic replacement left temporary files: %v", temporaryFiles)
	}
}

func TestWindowsReplaceScriptUsesAtomicFileReplaceAndEncodedPaths(t *testing.T) {
	source := `C:\ProgramData\SecWeaver\pending\agent with spaces.new`
	destination := `C:\Program Files\SecWeaver\secweaver-agent.exe`
	script := windowsAtomicReplaceScript(source, destination)
	if strings.Contains(script, source) || strings.Contains(script, destination) {
		t.Fatal("Windows replacement script embeds an unescaped filesystem path")
	}
	for _, expected := range []string{
		"[IO.File]::Replace($Source, $Destination, $null, $true)",
		base64.StdEncoding.EncodeToString([]byte(source)),
		base64.StdEncoding.EncodeToString([]byte(destination)),
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("Windows replacement script is missing %q", expected)
		}
	}
	if strings.Contains(strings.ToLower(script), "move /y") {
		t.Fatal("Windows replacement script fell back to a non-atomic cmd move")
	}
}

func writeRolloutManifest(t *testing.T, rolloutJSON string) string {
	t.Helper()
	dir := t.TempDir()
	payload := []byte("new secweaver-agent")
	binaryPath := filepath.Join(dir, "new-agent")
	if err := os.WriteFile(binaryPath, payload, 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	manifest := `{
  "schema_version": "1",
  "app": "secweaver-agent",
  "channel": "stable",
  "latest": {"version": "0.3.0"},
  "rollout": ` + rolloutJSON + `,
  "binaries": {
    "` + runtime.GOOS + `_` + runtime.GOARCH + `": {
      "url": "` + binaryPath + `",
      "sha256": "` + hex.EncodeToString(sum[:]) + `"
    }
  }
}`
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
