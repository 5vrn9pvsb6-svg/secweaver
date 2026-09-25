package agentlicense

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// Gateways sometimes return an empty 200 or an HTML login page. Those must not
// be misreported as expired credentials or persist an authorized registration.
func TestEnrollmentRejectsInvalidSuccessfulResponses(t *testing.T) {
	for _, body := range []string{"", "  ", "null", "<html>swenr_example.secret</html>"} {
		t.Run(body, func(t *testing.T) {
			root := t.TempDir()
			client := Client{HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			result, err := client.Enroll(context.Background(), Config{Enabled: true, Protocol: "device_v2", ServerURL: "https://example.test", StatePath: filepath.Join(root, "state.json"), IdentityKeyPath: filepath.Join(root, "key")}, "synthetic-token", "test")
			var invalid *ResponseValidationError
			if !errors.As(err, &invalid) || invalid.StatusCode != 200 {
				t.Fatalf("unexpected response error: %v", err)
			}
			if result.State.RegisteredAt != "" || strings.Contains(err.Error(), "swenr_example.secret") {
				t.Fatal("invalid response was accepted or echoed")
			}
		})
	}
}
