package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"secweaver-agent/pkg/agentupdate"
)

func main() {
	var addPublicKeyFiles stringListFlag
	var revokeKeyIDs stringListFlag
	var rollbackFromVersions stringListFlag
	manifestPath := flag.String("manifest", "", "unsigned update manifest JSON path")
	artifactDir := flag.String("artifact-dir", "", "directory containing manifest artifacts")
	privateKeyPath := flag.String("private-key-file", "", "Ed25519 private key file (base64 raw key or PKCS#8 PEM)")
	outputPath := flag.String("out", "", "signed envelope output path; defaults to replacing -manifest")
	publicKeyOutputPath := flag.String("public-key-out", "", "optional path for the base64 Ed25519 public key")
	verify := flag.Bool("verify", false, "verify a signed manifest and all local artifacts")
	publicKeyPath := flag.String("public-key-file", "", "base64 Ed25519 public key used with -verify")
	generateKeyPath := flag.String("generate-key", "", "generate a base64 private key and <path>.pub, then exit")
	emergencyStopReason := flag.String("emergency-stop-reason", "", "publish a signed emergency-stop manifest with this reason")
	rollbackReason := flag.String("rollback-reason", "", "authorize a controlled downgrade with this reason")
	rollbackExpiresAt := flag.String("rollback-expires-at", "", "RFC3339 expiry for controlled downgrade authorization")
	artifactSignatureFormat := flag.String(
		"artifact-signature-format",
		"ed25519",
		"artifact signature format: ed25519 (legacy-compatible) or ed25519-sha256",
	)
	flag.Var(&addPublicKeyFiles, "add-public-key-file", "add a public key to the signed trust update; repeatable")
	flag.Var(&revokeKeyIDs, "revoke-key-id", "revoke a trusted signing key ID; repeatable")
	flag.Var(&rollbackFromVersions, "rollback-from-version", "running version allowed to downgrade; repeatable")
	flag.Parse()

	if strings.TrimSpace(*generateKeyPath) != "" {
		if err := generateKey(*generateKeyPath); err != nil {
			fatal(err)
		}
		return
	}
	if *verify {
		if *manifestPath == "" || *artifactDir == "" || *publicKeyPath == "" {
			flag.Usage()
			os.Exit(2)
		}
		if err := verifyManifest(*manifestPath, *artifactDir, *publicKeyPath); err != nil {
			fatal(err)
		}
		return
	}
	if *manifestPath == "" || *artifactDir == "" || *privateKeyPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *outputPath == "" {
		*outputPath = *manifestPath
	}
	if err := signManifestWithOptions(*manifestPath, *artifactDir, *privateKeyPath, *outputPath, *publicKeyOutputPath, signOptions{
		AddPublicKeyFiles:       addPublicKeyFiles,
		RevokeKeyIDs:            revokeKeyIDs,
		EmergencyStopReason:     strings.TrimSpace(*emergencyStopReason),
		RollbackReason:          strings.TrimSpace(*rollbackReason),
		RollbackExpiresAt:       strings.TrimSpace(*rollbackExpiresAt),
		RollbackFromVersions:    rollbackFromVersions,
		ArtifactSignatureFormat: strings.TrimSpace(*artifactSignatureFormat),
	}); err != nil {
		fatal(err)
	}
}

type stringListFlag []string

func (values *stringListFlag) String() string { return strings.Join(*values, ",") }

func (values *stringListFlag) Set(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("value must not be empty")
	}
	*values = append(*values, trimmed)
	return nil
}

type signOptions struct {
	AddPublicKeyFiles       []string
	RevokeKeyIDs            []string
	EmergencyStopReason     string
	RollbackReason          string
	RollbackExpiresAt       string
	RollbackFromVersions    []string
	ArtifactSignatureFormat string
}

func verifyManifest(manifestPath, artifactDir, publicKeyPath string) error {
	keyBody, err := os.ReadFile(filepath.Clean(publicKeyPath))
	if err != nil {
		return err
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyBody)))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be a base64 Ed25519 public key")
	}
	keyID := agentupdate.PublicKeyID(ed25519.PublicKey(publicKey))
	body, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		return err
	}
	var envelope agentupdate.ManifestEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("parse signed manifest envelope: %w", err)
	}
	if envelope.KeyID != "" && envelope.KeyID != keyID {
		return fmt.Errorf("signed manifest key_id %q does not match public key %q", envelope.KeyID, keyID)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.Payload))
	if err != nil {
		return fmt.Errorf("decode signed manifest payload: %w", err)
	}
	manifestSignature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.Signature))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), payload, manifestSignature) {
		return fmt.Errorf("signed manifest signature is invalid")
	}
	var manifest agentupdate.Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return fmt.Errorf("parse signed manifest: %w", err)
	}
	if err := validateReleaseManifestMetadata(manifest); err != nil {
		return err
	}
	if len(manifest.Binaries) == 0 && (manifest.EmergencyStop == nil || !manifest.EmergencyStop.Enabled) {
		return fmt.Errorf("signed manifest contains no artifacts")
	}
	for platform, artifact := range manifest.Binaries {
		name, err := artifactFileName(artifact.URL)
		if err != nil {
			return fmt.Errorf("artifact %s: %w", platform, err)
		}
		artifactBody, err := os.ReadFile(filepath.Join(artifactDir, name))
		if err != nil {
			return fmt.Errorf("read artifact %s: %w", platform, err)
		}
		if artifact.Size != int64(len(artifactBody)) {
			return fmt.Errorf("artifact %s size mismatch", platform)
		}
		sum := sha256.Sum256(artifactBody)
		if !strings.EqualFold(artifact.SHA256, hex.EncodeToString(sum[:])) {
			return fmt.Errorf("artifact %s SHA-256 mismatch", platform)
		}
		signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(artifact.Signature))
		signedPayload := artifactBody
		if artifact.SignatureFormat == "ed25519-sha256" {
			signedPayload = sum[:]
		}
		if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), signedPayload, signature) {
			return fmt.Errorf("artifact %s signature is invalid", platform)
		}
	}
	fmt.Printf("verified %s (%d artifacts)\n", manifestPath, len(manifest.Binaries))
	return nil
}

func signManifest(manifestPath, artifactDir, privateKeyPath, outputPath, publicKeyOutputPath string) error {
	return signManifestWithOptions(manifestPath, artifactDir, privateKeyPath, outputPath, publicKeyOutputPath, signOptions{})
}

func signManifestWithOptions(manifestPath, artifactDir, privateKeyPath, outputPath, publicKeyOutputPath string, options signOptions) error {
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		return err
	}
	var manifest agentupdate.Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return fmt.Errorf("parse unsigned manifest: %w", err)
	}
	if err := validateReleaseManifestMetadata(manifest); err != nil {
		return err
	}
	if len(options.AddPublicKeyFiles) > 0 || len(options.RevokeKeyIDs) > 0 {
		if manifest.TrustUpdate == nil {
			manifest.TrustUpdate = &agentupdate.TrustUpdate{}
		}
		if manifest.TrustUpdate.AddKeys == nil {
			manifest.TrustUpdate.AddKeys = map[string]string{}
		}
		for _, path := range options.AddPublicKeyFiles {
			keyBody, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				return fmt.Errorf("read added public key %s: %w", path, err)
			}
			key, err := agentupdate.ParsePublicKey(string(keyBody))
			if err != nil {
				return fmt.Errorf("added public key %s: %w", path, err)
			}
			manifest.TrustUpdate.AddKeys[agentupdate.PublicKeyID(key)] = base64.StdEncoding.EncodeToString(key)
		}
		manifest.TrustUpdate.RevokeKeyIDs = append(manifest.TrustUpdate.RevokeKeyIDs, options.RevokeKeyIDs...)
	}
	if options.EmergencyStopReason != "" {
		manifest.EmergencyStop = &agentupdate.EmergencyStop{
			Enabled:  true,
			Reason:   options.EmergencyStopReason,
			IssuedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
	if options.RollbackReason != "" || len(options.RollbackFromVersions) > 0 || options.RollbackExpiresAt != "" {
		if options.RollbackReason == "" || len(options.RollbackFromVersions) == 0 || options.RollbackExpiresAt == "" {
			return fmt.Errorf("rollback signing requires -rollback-reason, -rollback-expires-at, and at least one -rollback-from-version")
		}
		expiresAt, err := time.Parse(time.RFC3339, options.RollbackExpiresAt)
		if err != nil || !expiresAt.After(time.Now().UTC()) {
			return fmt.Errorf("rollback expiry must be a future RFC3339 timestamp")
		}
		manifest.Rollback = &agentupdate.RollbackDirective{
			Enabled:       true,
			TargetVersion: manifest.Latest.Version,
			FromVersions:  append([]string(nil), options.RollbackFromVersions...),
			Reason:        options.RollbackReason,
			ExpiresAt:     expiresAt.UTC().Format(time.RFC3339),
		}
	}
	for platform, artifact := range manifest.Binaries {
		name, err := artifactFileName(artifact.URL)
		if err != nil {
			return fmt.Errorf("artifact %s: %w", platform, err)
		}
		payload, err := os.ReadFile(filepath.Join(artifactDir, name))
		if err != nil {
			return fmt.Errorf("read artifact %s: %w", platform, err)
		}
		sum := sha256.Sum256(payload)
		artifact.SHA256 = hex.EncodeToString(sum[:])
		artifact.Size = int64(len(payload))
		switch options.ArtifactSignatureFormat {
		case "", "ed25519":
			artifact.SignatureFormat = ""
			artifact.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
		case "ed25519-sha256":
			artifact.SignatureFormat = "ed25519-sha256"
			artifact.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, sum[:]))
		default:
			return fmt.Errorf("unsupported artifact signature format %q", options.ArtifactSignatureFormat)
		}
		manifest.Binaries[platform] = artifact
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID := agentupdate.PublicKeyID(publicKey)
	envelope := agentupdate.ManifestEnvelope{
		KeyID:     keyID,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Clean(outputPath), encoded, 0644); err != nil {
		return err
	}
	if strings.TrimSpace(publicKeyOutputPath) != "" {
		if err := os.WriteFile(
			filepath.Clean(publicKeyOutputPath),
			[]byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"),
			0644,
		); err != nil {
			return fmt.Errorf("write update public key: %w", err)
		}
	}
	fmt.Printf("signed %s (key_id=%s public_key=%s)\n", outputPath, keyID, base64.StdEncoding.EncodeToString(publicKey))
	return nil
}

func validateReleaseManifestMetadata(manifest agentupdate.Manifest) error {
	if manifest.SchemaVersion != "1" || manifest.App != "secweaver-agent" {
		return fmt.Errorf("manifest must use schema_version 1 and app secweaver-agent")
	}
	generatedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(manifest.GeneratedAt))
	if err != nil {
		return fmt.Errorf("manifest generated_at must use RFC3339")
	}
	expiresAt := generatedAt.Add(14 * 24 * time.Hour)
	if strings.TrimSpace(manifest.ExpiresAt) != "" {
		expiresAt, err = time.Parse(time.RFC3339, strings.TrimSpace(manifest.ExpiresAt))
	}
	if err != nil || !expiresAt.After(time.Now().UTC()) || !expiresAt.After(generatedAt) {
		return fmt.Errorf("manifest expires_at must be a future RFC3339 timestamp after generated_at")
	}
	return nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("private key permissions must not allow group or other access: %o", info.Mode().Perm())
	}
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(body))
	if block, _ := pem.Decode(body); block != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not Ed25519")
		}
		return privateKey, nil
	}
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("private key must be base64 or PKCS#8 PEM: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("private key must contain %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func artifactFileName(location string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return "", err
	}
	name := filepath.Base(parsed.Path)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "", fmt.Errorf("URL does not contain a file name")
	}
	return name, nil
}

func generateKey(path string) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Clean(path), []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Clean(path+".pub"), []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0644); err != nil {
		return err
	}
	fmt.Printf("generated %s and %s.pub (key_id=%s)\n", path, path, agentupdate.PublicKeyID(publicKey))
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
