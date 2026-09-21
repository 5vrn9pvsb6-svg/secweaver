package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"secweaver-agent/pkg/agentupdate"
)

func TestSignManifestSignsEnvelopeAndArtifact(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPath := filepath.Join(dir, "update.key")
	if err := os.WriteFile(privateKeyPath, []byte(base64.StdEncoding.EncodeToString(privateKey)), 0600); err != nil {
		t.Fatal(err)
	}
	artifactName := "secweaver-agent-test"
	artifact := []byte("signed artifact")
	if err := os.WriteFile(filepath.Join(dir, artifactName), artifact, 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(artifact)
	manifest := agentupdate.Manifest{
		SchemaVersion: "1",
		App:           "secweaver-agent",
		Channel:       "stable",
		Generation:    time.Now().UTC().UnixNano(),
		GeneratedAt:   time.Now().UTC().Add(-time.Second).Format(time.RFC3339),
		ExpiresAt:     time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Latest:        agentupdate.ManifestLatest{Version: "0.3.0"},
		Binaries: map[string]agentupdate.Artifact{
			runtime.GOOS + "_" + runtime.GOARCH: {
				URL:    "https://updates.example.com/releases/" + artifactName,
				SHA256: hex.EncodeToString(sum[:]),
				Size:   int64(len(artifact)),
			},
		},
	}
	unsignedPath := filepath.Join(dir, "unsigned.json")
	body, _ := json.Marshal(manifest)
	if err := os.WriteFile(unsignedPath, body, 0644); err != nil {
		t.Fatal(err)
	}
	signedPath := filepath.Join(dir, "signed.json")
	publicKeyPath := filepath.Join(dir, "update-signing-key.pub")
	nextPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nextPublicKeyPath := filepath.Join(dir, "next.pub")
	if err := os.WriteFile(nextPublicKeyPath, []byte(base64.StdEncoding.EncodeToString(nextPublicKey)), 0644); err != nil {
		t.Fatal(err)
	}
	if err := signManifestWithOptions(unsignedPath, dir, privateKeyPath, signedPath, publicKeyPath, signOptions{
		AddPublicKeyFiles:       []string{nextPublicKeyPath},
		RevokeKeyIDs:            []string{"ed25519-retired"},
		EmergencyStopReason:     "integration test stop",
		ArtifactSignatureFormat: "ed25519-sha256",
	}); err != nil {
		t.Fatal(err)
	}
	if err := verifyManifest(signedPath, dir, publicKeyPath); err != nil {
		t.Fatal(err)
	}

	signedBody, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	var envelope agentupdate.ManifestEnvelope
	if err := json.Unmarshal(signedBody, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.KeyID != agentupdate.PublicKeyID(publicKey) {
		t.Fatalf("envelope key ID = %q", envelope.KeyID)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	manifestSignature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, manifestSignature) {
		t.Fatal("manifest envelope signature is invalid")
	}
	var signedManifest agentupdate.Manifest
	if err := json.Unmarshal(payload, &signedManifest); err != nil {
		t.Fatal(err)
	}
	if signedManifest.TrustUpdate == nil || signedManifest.TrustUpdate.AddKeys[agentupdate.PublicKeyID(nextPublicKey)] == "" {
		t.Fatal("signed trust update did not include the next public key")
	}
	if signedManifest.EmergencyStop == nil || !signedManifest.EmergencyStop.Enabled {
		t.Fatal("signed emergency stop was not included")
	}
	signedArtifact := signedManifest.Binaries[runtime.GOOS+"_"+runtime.GOARCH]
	if signedArtifact.SignatureFormat != "ed25519-sha256" {
		t.Fatalf("artifact signature format = %q", signedArtifact.SignatureFormat)
	}
	artifactSignatureText := signedArtifact.Signature
	artifactSignature, err := base64.StdEncoding.DecodeString(artifactSignatureText)
	digest := sha256.Sum256(artifact)
	if err != nil || !ed25519.Verify(publicKey, digest[:], artifactSignature) {
		t.Fatal("artifact signature is invalid")
	}
}
