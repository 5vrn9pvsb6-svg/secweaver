package main

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"secweaver-agent/pkg/agentlicense"
)

func TestEnrollmentTokenStdin(t *testing.T) {
	got, err := enrollmentTokenInput(strings.NewReader("synthetic-token\r\n"), "", true)
	if err != nil || got != "synthetic-token" {
		t.Fatal("stdin credential not accepted")
	}
	for _, input := range []string{"", "secret\nsecond", strings.Repeat("x", 513)} {
		if _, err := enrollmentTokenInput(strings.NewReader(input), "", true); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid input accepted or reflected")
		}
	}
	if _, err := enrollmentTokenInput(strings.NewReader("secret"), "argument", true); err == nil {
		t.Fatal("ambiguous credentials accepted")
	}
}

// A child process captures the real command's stdout without mutating the test
// runner's global streams. The TLS fixture echoes the cryptographically bound ID.
func TestEnrollInstallerOutput(t *testing.T) {
	if os.Getenv("SECWEAVER_ENROLL_OUTPUT_CHILD") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Exit(runEnrollCommand(os.Args[i+1:]))
			}
		}
		os.Exit(2)
	}
	var identities []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request agentlicense.EnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		identities = append(identities, request.DeviceID)
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": true, "device_id": request.DeviceID, "enterprise_id": "ABCD1234EFGH5678"})
	}))
	defer server.Close()
	root := t.TempDir()
	ca := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"installer", "installer", "enterprise-id"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestEnrollInstallerOutput$", "--", "-server-url", server.URL, "-enterprise-enrollment-token", "synthetic-token", "-state-path", filepath.Join(root, "state.json"), "-identity-key-path", filepath.Join(root, "device.key"), "-ca-file", ca, "-output", format)
		cmd.Env = append(os.Environ(), "SECWEAVER_ENROLL_OUTPUT_CHILD=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("enrollment failed: %v\n%s", err, output)
		}
		state, err := agentlicense.LoadState(filepath.Join(root, "state.json"))
		if err != nil {
			t.Fatal(err)
		}
		want := "ABCD1234EFGH5678\n"
		if format == "installer" {
			want = "ABCD1234EFGH5678\t" + state.DeviceID + "\n"
		}
		if string(output) != want {
			t.Fatalf("unexpected public identity output: %q", output)
		}
	}
	if len(identities) != 3 || identities[0] != identities[1] || identities[1] != identities[2] {
		t.Fatal("retry changed device identity")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestEnrollInstallerOutput$", "--", "-output", "invalid")
	cmd.Env = append(os.Environ(), "SECWEAVER_ENROLL_OUTPUT_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "invalid enrollment output format") {
		t.Fatalf("invalid format: %v %s", err, out)
	}
}

// Guidance must follow typed status, even through wrapping, without leaking
// supplied credentials or misdiagnosing transport/server failures as expiry.
func TestEnrollmentRecoveryHint(t *testing.T) {
	for _, status := range []int{401, 403, 404, 409, 429, 500} {
		err := fmt.Errorf("wrapped: %w", &agentlicense.HTTPStatusError{StatusCode: status, Reason: "secret-must-not-appear"})
		hint := enrollmentRecoveryHint(err)
		if (hint != "") != (status == 401 || status == 403 || status == 404) || strings.Contains(hint, "secret-must-not-appear") {
			t.Fatalf("status %d: %q", status, hint)
		}
	}
	if hint := enrollmentRecoveryHint(fmt.Errorf("network timeout")); hint != "" {
		t.Fatal(hint)
	}
}

// Exercise the actual CLI over TLS, including old/new Gateway JSON, WAF bodies
// and inconsistent status/code pairs. Failures must keep identity off stdout,
// suppress upstream prose and preserve the same device identity across retries.
func TestEnrollRejectionDiagnostics(t *testing.T) {
	const secret = "swenr_example.secret"
	for _, test := range []struct {
		name, code, body, description string
		status                        int
	}{
		{"identity", "DeviceIdentityConflict", `{"errorCode":"DeviceIdentityConflict","message":"UPSTREAM_SECRET swenr_example.secret"}`, "本机设备身份已被撤销", 403},
		{"quota", "DeviceQuotaExceeded", `{"errorCode":"DeviceQuotaExceeded","message":"UPSTREAM_SECRET swenr_example.secret"}`, "企业设备额度已满", 403},
		{"token-uses", "EnrollmentTokenExhausted", `{"errorCode":"EnrollmentTokenExhausted","message":"UPSTREAM_SECRET swenr_example.secret"}`, "安装令牌累计注册次数已用完", 403},
		{"disabled", "EnterpriseDisabled", `{"reason":"EnterpriseDisabled","message":"UPSTREAM_SECRET swenr_example.secret"}`, "企业被禁用", 403},
		{"expired", "SubscriptionExpired", `{"reason":"SubscriptionExpired"}`, "企业订阅已到期", 403},
		{"duplicates", "AmbiguousReinstall", `{"errorCode":"AmbiguousReinstall"}`, "多个有效设备身份", 409},
		{"legacy-denial", "DeviceQuotaExceeded", `{"allowed":false,"reason":"DeviceQuotaExceeded","message":"UPSTREAM_SECRET"}`, "企业设备额度已满", 200},
		{"waf", "UnknownRejection", `<html>UPSTREAM_SECRET swenr_example.secret</html>`, "响应没有可识别", 403},
		{"unknown-code", "UnknownRejection", `{"errorCode":"UPSTREAM_SECRET","reason":"DeviceQuotaExceeded","message":"swenr_example.secret"}`, "响应没有可识别", 403},
		{"wrong-status", "UnknownRejection", `{"errorCode":"DeviceQuotaExceeded","message":"UPSTREAM_SECRET"}`, "Internal Server Error", 500},
		{"malformed", "UnknownRejection", `{"errorCode":"DeviceQuotaExceeded","broken":`, "响应没有可识别", 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/secweaver/v2/agent/enroll" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			root := t.TempDir()
			ca := filepath.Join(root, "ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			statePath, keyPath := filepath.Join(root, "state.json"), filepath.Join(root, "device.key")
			previousID := ""
			for attempt := 0; attempt < 2; attempt++ {
				cmd := exec.Command(os.Args[0], "-test.run=^TestEnrollInstallerOutput$", "--", "-server-url", server.URL, "-enterprise-enrollment-token", secret, "-state-path", statePath, "-identity-key-path", keyPath, "-ca-file", ca, "-output", "installer")
				cmd.Env = append(os.Environ(), "SECWEAVER_ENROLL_OUTPUT_CHILD=1")
				var stdout, stderr strings.Builder
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 || stdout.Len() != 0 {
					t.Fatalf("rejected enrollment did not fail cleanly: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
				}
				message := stderr.String()
				if !strings.Contains(message, fmt.Sprintf("HTTP=%d reason=%s:", test.status, test.code)) || !strings.Contains(message, test.description) {
					t.Fatalf("missing specific diagnosis: %s", message)
				}
				if strings.Contains(message, secret) || strings.Contains(message, "UPSTREAM_SECRET") {
					t.Fatalf("upstream content leaked: %s", message)
				}
				state, err := agentlicense.LoadState(statePath)
				if err != nil || state.DeviceID == "" || state.RegisteredAt != "" {
					t.Fatalf("rejected identity was lost or registered: %v", err)
				}
				if previousID != "" && state.DeviceID != previousID {
					t.Fatal("retry replaced the rejected device identity")
				}
				previousID = state.DeviceID
			}
		})
	}
}

func TestEnrollmentFailureMessageRedactsCredentials(t *testing.T) {
	for _, err := range []error{
		&agentlicense.HTTPStatusError{StatusCode: 401, Reason: "swenr_example.secret"},
		fmt.Errorf(`Post "https://user:password@example.test/path?token=secret": timeout swenr_example.secret`),
	} {
		message := enrollmentFailureMessage(err, "https://user:password@example.test?token=secret", "swenr_example.secret")
		for _, secret := range []string{"password", "token=", "swenr_example.secret"} {
			if strings.Contains(message, secret) {
				t.Fatalf("leaked credential in %q", message)
			}
		}
		if !strings.Contains(message, "stage=device-enrollment") || !strings.Contains(message, "/api/secweaver/v2/agent/enroll") {
			t.Fatal(message)
		}
	}
}
