package agentupdate

import (
	"strings"
	"testing"
)

// Explicit platform identities exercise both release families on every test
// host. A runtime.GOOS fixture hides Linux's update branch on macOS/Windows.
func TestPlatformManifestSelectsOperatingSystemTarget(t *testing.T) {
	for _, tc := range []struct {
		platform string
		latest   string
		update   bool
	}{
		{"linux_amd64", "0.3.2", true},
		{"linux_arm64", "0.3.2", true},
		{"linux_loong64", "0.3.2", true},
		{"windows_amd64", "0.3.1", false},
		{"windows_arm64", "0.3.1", false},
		{"darwin_arm64", "0.3.1", false},
	} {
		t.Run(tc.platform, func(t *testing.T) {
			manifest := platformManifestFixture(tc.platform)
			result, err := checkManifest(manifest, Options{
				CurrentVersion: "0.3.1", DeviceID: "platform-target-test", Channel: "stable",
			}, Status{Platform: tc.platform})
			if err != nil {
				t.Fatal(err)
			}
			if result.LatestVersion != tc.latest || result.UpdateAvailable != tc.update {
				t.Fatalf("target = %+v, want latest=%s update=%t", result, tc.latest, tc.update)
			}
			wantStatus := "up_to_date"
			if tc.update {
				wantStatus = "update_available"
			}
			if result.Status != wantStatus {
				t.Fatalf("status = %q, want %q", result.Status, wantStatus)
			}
		})
	}
}

// Family selection must not bypass artifact integrity or reinterpret a server
// policy for a different family. These checks never download a real artifact.
func TestPlatformManifestPreservesValidationAndLegacyFallback(t *testing.T) {
	for _, tc := range []struct {
		name           string
		platform       string
		legacy         bool
		missingHash    bool
		desiredVersion string
		wantLatest     string
		wantReason     string
		wantError      bool
	}{
		{"linux_missing_hash", "linux_amd64", false, true, "", "0.3.2", "missing_platform_binary_sha256", true},
		{"windows_missing_hash", "windows_amd64", false, true, "", "0.3.2", "missing_platform_binary_sha256", true},
		{"linux_policy_match", "linux_amd64", false, false, "0.3.2", "0.3.2", "", false},
		{"windows_policy_mismatch", "windows_amd64", false, false, "0.3.2", "0.3.1", "manifest_version_does_not_match_server_policy", false},
		{"linux_legacy", "linux_amd64", true, false, "", "0.3.1", "", false},
		{"windows_legacy", "windows_amd64", true, false, "", "0.3.1", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := platformManifestFixture(tc.platform)
			if tc.legacy {
				manifest.LatestByPlatform = nil
			}
			if tc.missingHash {
				manifest.LatestByPlatform[strings.SplitN(tc.platform, "_", 2)[0]] = ManifestLatest{Version: "0.3.2"}
				artifact := manifest.Binaries[tc.platform]
				artifact.SHA256 = ""
				manifest.Binaries[tc.platform] = artifact
			}
			result, err := checkManifest(manifest, Options{
				CurrentVersion: "0.3.1", DeviceID: "platform-target-test", Channel: "stable", DesiredVersion: tc.desiredVersion,
			}, Status{Platform: tc.platform})
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, want error=%t", err, tc.wantError)
			}
			if result.LatestVersion != tc.wantLatest || (tc.wantReason != "" && result.Reason != tc.wantReason) {
				t.Fatalf("target = %+v, want latest=%s reason=%s", result, tc.wantLatest, tc.wantReason)
			}
		})
	}
}

// The update-available branch requires a complete artifact even though checking
// a manifest does not fetch its bytes. Keep production SHA-256 checks enabled.
func platformManifestFixture(platform string) Manifest {
	return Manifest{
		SchemaVersion: "1", App: appName, Channel: "stable",
		Latest: ManifestLatest{Version: "0.3.1"},
		LatestByPlatform: map[string]ManifestLatest{
			"linux": {Version: "0.3.2"}, "windows": {Version: "0.3.1"},
		},
		Binaries: map[string]Artifact{platform: {
			URL: "https://updates.example.test/" + platform + "/agent", SHA256: strings.Repeat("a", 64),
		}},
	}
}
