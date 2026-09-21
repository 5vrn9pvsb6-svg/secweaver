package agentupdate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const trustStoreSchemaVersion = "1"

type trustStore struct {
	SchemaVersion string            `json:"schema_version"`
	Keys          map[string]string `json:"keys"`
	RevokedKeyIDs []string          `json:"revoked_key_ids,omitempty"`
	UpdatedAt     string            `json:"updated_at"`
}

func PublicKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "ed25519-" + hex.EncodeToString(sum[:8])
}

func ParsePublicKey(text string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

func effectiveTrustedKeys(opts Options) (map[string]ed25519.PublicKey, map[string]bool, error) {
	keys := map[string]ed25519.PublicKey{}
	revoked := map[string]bool{}
	addKey := func(keyID string, key ed25519.PublicKey) error {
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("trusted update key %q must contain %d bytes", keyID, ed25519.PublicKeySize)
		}
		derived := PublicKeyID(key)
		if strings.TrimSpace(keyID) == "" {
			keyID = derived
		}
		if keyID != derived {
			return fmt.Errorf("trusted update key ID %q does not match derived ID %q", keyID, derived)
		}
		keys[keyID] = append(ed25519.PublicKey(nil), key...)
		return nil
	}
	if len(opts.PublicKey) > 0 {
		if err := addKey("", opts.PublicKey); err != nil {
			return nil, nil, err
		}
	}
	for keyID, key := range opts.TrustedPublicKeys {
		if err := addKey(keyID, key); err != nil {
			return nil, nil, err
		}
	}
	for _, keyID := range opts.RevokedKeyIDs {
		if trimmed := strings.TrimSpace(keyID); trimmed != "" {
			revoked[trimmed] = true
		}
	}
	path := filepath.Join(opts.StateDir, "trusted-update-keys.json")
	body, err := os.ReadFile(path)
	if err == nil {
		var persisted trustStore
		if err := decodeJSONStrict(body, &persisted); err != nil {
			return nil, nil, fmt.Errorf("parse update trust store: %w", err)
		}
		if persisted.SchemaVersion != trustStoreSchemaVersion {
			return nil, nil, fmt.Errorf("unsupported update trust store schema %q", persisted.SchemaVersion)
		}
		for keyID, encoded := range persisted.Keys {
			key, err := ParsePublicKey(encoded)
			if err != nil {
				return nil, nil, fmt.Errorf("persisted update key %q: %w", keyID, err)
			}
			if err := addKey(keyID, key); err != nil {
				return nil, nil, err
			}
		}
		for _, keyID := range persisted.RevokedKeyIDs {
			revoked[keyID] = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("read update trust store: %w", err)
	}
	return keys, revoked, nil
}

func persistTrustUpdate(opts Options, update *TrustUpdate) error {
	if update == nil || (len(update.AddKeys) == 0 && len(update.RevokeKeyIDs) == 0) {
		return nil
	}
	keys, revoked, err := effectiveTrustedKeys(opts)
	if err != nil {
		return err
	}
	for keyID, encoded := range update.AddKeys {
		key, err := ParsePublicKey(encoded)
		if err != nil {
			return fmt.Errorf("trust_update.add_keys[%s]: %w", keyID, err)
		}
		derived := PublicKeyID(key)
		if keyID != derived {
			return fmt.Errorf("trust_update key ID %q does not match derived ID %q", keyID, derived)
		}
		keys[keyID] = key
	}
	for _, keyID := range update.RevokeKeyIDs {
		keyID = strings.TrimSpace(keyID)
		if keyID == "" {
			return errors.New("trust_update contains an empty revoked key ID")
		}
		revoked[keyID] = true
	}
	active := 0
	for keyID := range keys {
		if !revoked[keyID] {
			active++
		}
	}
	if active == 0 {
		return errors.New("trust_update would revoke every trusted update key")
	}
	encodedKeys := make(map[string]string, len(keys))
	for keyID, key := range keys {
		encodedKeys[keyID] = base64.StdEncoding.EncodeToString(key)
	}
	revokedIDs := make([]string, 0, len(revoked))
	for keyID := range revoked {
		revokedIDs = append(revokedIDs, keyID)
	}
	sort.Strings(revokedIDs)
	payload, err := json.MarshalIndent(trustStore{
		SchemaVersion: trustStoreSchemaVersion,
		Keys:          encodedKeys,
		RevokedKeyIDs: revokedIDs,
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(opts.StateDir, 0700); err != nil {
		return err
	}
	return writeBytesAtomic(filepath.Join(opts.StateDir, "trusted-update-keys.json"), append(payload, '\n'), 0600)
}
