package agentupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxArtifactBytes int64 = 512 * 1024 * 1024

type downloadedArtifact struct {
	Path   string
	Size   int64
	SHA256 string
}

type HTTPStatusError struct {
	URL        string
	Status     string
	StatusCode int
	RetryDelay time.Duration
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("GET %s returned %s", e.URL, e.Status)
}

// RetryAfter returns the server-requested minimum retry delay carried by an
// HTTP update error. Callers may combine it with their own bounded backoff.
func RetryAfter(err error) time.Duration {
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) && statusErr.RetryDelay > 0 {
		return statusErr.RetryDelay
	}
	return 0
}

func verifySHA256(data []byte, expected string) bool {
	if expected == "" {
		return false
	}
	sum := sha256.Sum256(data)
	return strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(expected))
}

func verifyEd25519Signature(data []byte, encoded string, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must contain %d bytes", ed25519.PublicKeySize)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return fmt.Errorf("signature must be base64: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("signature must contain %d bytes", ed25519.SignatureSize)
	}
	if !ed25519.Verify(publicKey, data, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func decodeJSONStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.More() {
		return fmt.Errorf("unexpected trailing JSON value")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func isHTTPURL(location string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(location)), "http://") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(location)), "https://")
}

func validateRemoteLocation(location string, allowInsecureHTTP bool) error {
	trimmed := strings.ToLower(strings.TrimSpace(location))
	if strings.Contains(trimmed, "://") && !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		return fmt.Errorf("unsupported update URL scheme: %s", location)
	}
	if strings.HasPrefix(trimmed, "http://") && !allowInsecureHTTP {
		return fmt.Errorf("insecure HTTP update location is disabled: %s", location)
	}
	return nil
}

func readSmallURLOrFile(location string, maxBytes int64, allowInsecureHTTP bool, caFile string) ([]byte, error) {
	if err := validateRemoteLocation(location, allowInsecureHTTP); err != nil {
		return nil, err
	}
	location = strings.TrimSpace(location)
	if isHTTPURL(location) {
		client, err := newHTTPClient(15*time.Second, allowInsecureHTTP, caFile)
		if err != nil {
			return nil, err
		}
		resp, err := client.Get(location)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, responseStatusError(location, resp)
		}
		return readLimited(resp.Body, maxBytes)
	}
	f, err := os.Open(filepath.Clean(location))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLimited(f, maxBytes)
}

func readArtifact(location string, allowInsecureHTTP bool, caFile string) ([]byte, error) {
	if err := validateRemoteLocation(location, allowInsecureHTTP); err != nil {
		return nil, err
	}
	location = strings.TrimSpace(location)
	if isHTTPURL(location) {
		client, err := newHTTPClient(2*time.Minute, allowInsecureHTTP, caFile)
		if err != nil {
			return nil, err
		}
		resp, err := client.Get(location)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, responseStatusError(location, resp)
		}
		return readLimited(resp.Body, 512*1024*1024)
	}
	f, err := os.Open(filepath.Clean(location))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLimited(f, 512*1024*1024)
}

func downloadArtifact(
	ctx context.Context,
	location string,
	allowInsecureHTTP bool,
	caFile string,
	stateDir string,
) (downloadedArtifact, error) {
	if err := validateRemoteLocation(location, allowInsecureHTTP); err != nil {
		return downloadedArtifact{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	downloadDir := filepath.Join(stateDir, "downloads")
	if err := os.MkdirAll(downloadDir, 0700); err != nil {
		return downloadedArtifact{}, err
	}
	tmp, err := os.CreateTemp(downloadDir, "artifact-*.part")
	if err != nil {
		return downloadedArtifact{}, err
	}
	path := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()

	var source io.ReadCloser
	location = strings.TrimSpace(location)
	if isHTTPURL(location) {
		client, err := newHTTPClient(10*time.Minute, allowInsecureHTTP, caFile)
		if err != nil {
			return downloadedArtifact{}, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
		if err != nil {
			return downloadedArtifact{}, err
		}
		response, err := client.Do(request)
		if err != nil {
			return downloadedArtifact{}, err
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			_ = response.Body.Close()
			return downloadedArtifact{}, responseStatusError(location, response)
		}
		if response.ContentLength > maxArtifactBytes {
			_ = response.Body.Close()
			return downloadedArtifact{}, fmt.Errorf("artifact exceeds %d bytes", maxArtifactBytes)
		}
		source = response.Body
	} else {
		file, err := os.Open(filepath.Clean(location))
		if err != nil {
			return downloadedArtifact{}, err
		}
		source = file
	}
	defer source.Close()

	hash := sha256.New()
	written, err := copyWithContext(ctx, io.MultiWriter(tmp, hash), io.LimitReader(source, maxArtifactBytes+1))
	if err != nil {
		return downloadedArtifact{}, err
	}
	if written > maxArtifactBytes {
		return downloadedArtifact{}, fmt.Errorf("artifact exceeds %d bytes", maxArtifactBytes)
	}
	if err := tmp.Sync(); err != nil {
		return downloadedArtifact{}, err
	}
	if err := tmp.Close(); err != nil {
		return downloadedArtifact{}, err
	}
	keep = true
	return downloadedArtifact{Path: path, Size: written, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 128*1024)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		count, readErr := source.Read(buffer)
		if count > 0 {
			outputCount, writeErr := destination.Write(buffer[:count])
			written += int64(outputCount)
			if writeErr != nil {
				return written, writeErr
			}
			if outputCount != count {
				return written, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return written, nil
			}
			return written, readErr
		}
	}
}

func responseStatusError(location string, response *http.Response) error {
	return &HTTPStatusError{
		URL:        location,
		Status:     response.Status,
		StatusCode: response.StatusCode,
		RetryDelay: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
	}
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
		return 0
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return when.Sub(now)
}

func newHTTPClient(timeout time.Duration, allowInsecureHTTP bool, caFile string) (http.Client, error) {
	// P0-3 & P2-8: Safe type assertion with fallback and complete timeout settings
	var transport *http.Transport
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = defaultTransport.Clone()
		// P2-8: Ensure all timeouts are set even when cloning
		if transport.DialContext == nil {
			transport.DialContext = (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext
		}
		if transport.TLSHandshakeTimeout == 0 {
			transport.TLSHandshakeTimeout = 10 * time.Second
		}
		if transport.ResponseHeaderTimeout == 0 {
			transport.ResponseHeaderTimeout = 10 * time.Second
		}
		if transport.ExpectContinueTimeout == 0 {
			transport.ExpectContinueTimeout = 1 * time.Second
		}
		if transport.IdleConnTimeout == 0 {
			transport.IdleConnTimeout = 90 * time.Second
		}
	} else {
		// Fallback: create transport with safe defaults
		transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	if strings.TrimSpace(caFile) != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		pemData, err := os.ReadFile(filepath.Clean(strings.TrimSpace(caFile)))
		if err != nil {
			return http.Client{}, fmt.Errorf("read update CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return http.Client{}, fmt.Errorf("update CA file does not contain a valid PEM certificate")
		}
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		}
	}
	return http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			return validateRemoteLocation(request.URL.String(), allowInsecureHTTP)
		},
	}, nil
}

func readLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("payload exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func resolveArtifactLocation(manifestLocation, artifactLocation string) string {
	artifactLocation = strings.TrimSpace(artifactLocation)
	if artifactLocation == "" || strings.HasPrefix(artifactLocation, "http://") || strings.HasPrefix(artifactLocation, "https://") || filepath.IsAbs(artifactLocation) {
		return artifactLocation
	}
	if baseURL, err := url.Parse(manifestLocation); err == nil && baseURL.Scheme != "" && baseURL.Host != "" {
		ref, refErr := url.Parse(artifactLocation)
		if refErr == nil {
			return baseURL.ResolveReference(ref).String()
		}
	}
	if manifestLocation == "" {
		return artifactLocation
	}
	return filepath.Join(filepath.Dir(manifestLocation), artifactLocation)
}
