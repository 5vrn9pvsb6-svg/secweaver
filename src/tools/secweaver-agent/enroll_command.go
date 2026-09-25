package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"secweaver-agent/pkg/agentlicense"
)

// runEnrollCommand defaults to the legacy enterprise-only output. Installers
// opt into a bounded two-field record after enrollment has durably succeeded;
// no private key, enrollment token, or raw server response is printed.
func runEnrollCommand(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverURL := ""
	token := ""
	tokenStdin := false
	statePath := agentlicense.DefaultStatePath()
	identityKeyPath := ""
	caFile := ""
	output := "enterprise-id"
	timeout := 30 * time.Second
	fs.StringVar(&serverURL, "server-url", "", "SecWeaver managed control-plane origin")
	fs.StringVar(&token, "enterprise-enrollment-token", "", "reusable enterprise installation credential")
	fs.BoolVar(&tokenStdin, "enterprise-enrollment-token-stdin", false, "read the installation credential from bounded stdin instead of the audited command line")
	fs.StringVar(&statePath, "state-path", statePath, "device identity state path")
	fs.StringVar(&identityKeyPath, "identity-key-path", "", "Ed25519 device private key path")
	fs.StringVar(&caFile, "ca-file", "", "optional PEM CA file for the control-plane HTTPS endpoint")
	fs.StringVar(&output, "output", output, "output: enterprise-id or installer (enterprise ID and device ID separated by a tab)")
	fs.DurationVar(&timeout, "timeout", timeout, "enrollment request timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if output != "enterprise-id" && output != "installer" {
		fmt.Fprintln(os.Stderr, "invalid enrollment output format")
		return 2
	}
	var tokenErr error
	token, tokenErr = enrollmentTokenInput(os.Stdin, token, tokenStdin)
	if tokenErr != nil {
		fmt.Fprintln(os.Stderr, tokenErr)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := (agentlicense.Client{}).Enroll(ctx, agentlicense.Config{
		Enabled:         true,
		Protocol:        "device_v2",
		ServerURL:       serverURL,
		StatePath:       statePath,
		IdentityKeyPath: identityKeyPath,
		CAFile:          caFile,
	}, token, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, enrollmentFailureMessage(err, serverURL, token))
		if hint := enrollmentRecoveryHint(err); hint != "" {
			fmt.Fprintln(os.Stderr, hint)
		}
		return 1
	}
	if output == "installer" {
		fmt.Fprintf(os.Stdout, "%s\t%s\n", result.State.EnterpriseID, result.State.DeviceID)
	} else {
		fmt.Fprintln(os.Stdout, result.State.EnterpriseID)
	}
	return 0
}

// enrollmentTokenInput keeps managed Windows enrollment out of Security 4688
// command-line records. The installer owns the pipe; bound input and reject
// ambiguous sources without including any credential bytes in error messages.
func enrollmentTokenInput(input io.Reader, argument string, fromStdin bool) (string, error) {
	if !fromStdin {
		return argument, nil
	}
	if argument != "" {
		return "", errors.New("choose exactly one enrollment token input")
	}
	body, err := io.ReadAll(io.LimitReader(input, 513))
	if err != nil || len(body) > 512 {
		return "", errors.New("enrollment token stdin is unreadable or oversized")
	}
	token := strings.TrimSpace(string(body))
	if token == "" || strings.ContainsAny(token, "\r\n\x00") {
		return "", errors.New("enrollment token stdin must contain one nonempty token")
	}
	return token, nil
}

// enrollmentFailureMessage keeps machine-readable identity on stdout and never
// reflects a server error body. HTTP status plus endpoint distinguish bad tokens
// from bad routes; transport errors remain useful without leaking credentials.
func enrollmentFailureMessage(err error, serverURL, token string) string {
	endpoint := "<invalid-url>"
	if parsed, parseErr := url.Parse(serverURL); parseErr == nil && parsed.Host != "" {
		parsed.User, parsed.RawQuery, parsed.Fragment = nil, "", ""
		if !strings.HasSuffix(parsed.Path, "/api/secweaver/v2/agent/enroll") {
			for _, suffix := range []string{"/api/secweaver/v1/agent/authorize", "/api/secweaver/v1/agent/heartbeat"} {
				parsed.Path = strings.TrimSuffix(parsed.Path, suffix)
			}
			parsed.Path = strings.TrimRight(parsed.Path, "/") + "/api/secweaver/v2/agent/enroll"
		}
		parsed.RawPath = ""
		endpoint = parsed.String()
	}
	statusCode := "unavailable"
	detail := err.Error()
	var status *agentlicense.HTTPStatusError
	if errors.As(err, &status) {
		statusCode = fmt.Sprint(status.StatusCode)
		detail = http.StatusText(status.StatusCode)
	}
	var invalid *agentlicense.ResponseValidationError
	if errors.As(err, &invalid) {
		statusCode = fmt.Sprint(invalid.StatusCode)
		detail = invalid.Error()
	}
	message := fmt.Sprintf("stage=device-enrollment check=authorization url=%s HTTP=%s: %s", endpoint, statusCode, detail)
	if token != "" {
		for _, secret := range []string{token, url.QueryEscape(token), url.PathEscape(token)} {
			message = strings.ReplaceAll(message, secret, "[REDACTED]")
		}
	}
	message = regexp.MustCompile(`swenr_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`).ReplaceAllString(message, "[REDACTED]")
	// URL errors can contain the original request URL, including query values.
	message = regexp.MustCompile(`https?://[^\s"<>]+`).ReplaceAllStringFunc(message, func(raw string) string {
		u, parseErr := url.Parse(raw)
		if parseErr != nil {
			return "<redacted-url>"
		}
		u.User, u.RawQuery, u.Fragment = nil, "", ""
		return u.String()
	})
	if len(message) > 2048 {
		message = message[:2048]
	}
	return message
}

// enrollmentRecoveryHint does not infer which credential check failed: the
// public endpoint intentionally conflates invalid, expired and revoked tokens.
// Keep guidance on stderr so installer identity output remains machine-readable.
func enrollmentRecoveryHint(err error) string {
	var status *agentlicense.HTTPStatusError
	if errors.As(err, &status) && status.StatusCode == http.StatusUnauthorized {
		return "Enrollment credential may be expired, revoked or invalid. Generate a new installation command in SecWeaver Data Cloud and retry. Preserve the existing device identity; do not delete state or disable TLS verification. / 安装令牌可能已过期、撤销或无效，请在 SecWeaver Data Cloud 生成新安装命令后重试；不要删除现有设备身份或关闭 TLS 校验。"
	}
	if errors.As(err, &status) && status.StatusCode == http.StatusNotFound {
		return "Check the Agent Gateway origin and /api/secweaver/v2/agent/enroll route, including reverse-proxy configuration. A 404 does not indicate an expired token. / 请核对 Agent Gateway 地址和注册路由；404 不代表令牌过期。"
	}
	return ""
}
