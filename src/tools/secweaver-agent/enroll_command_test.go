package main

import (
	"encoding/json"
	"encoding/pem"
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
		if (hint != "") != (status == 401 || status == 404) || strings.Contains(hint, "secret-must-not-appear") {
			t.Fatalf("status %d: %q", status, hint)
		}
	}
	if hint := enrollmentRecoveryHint(fmt.Errorf("network timeout")); hint != "" {
		t.Fatal(hint)
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
