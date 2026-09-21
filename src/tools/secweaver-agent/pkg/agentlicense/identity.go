package agentlicense

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const fingerprintVersion = "hw-v1"

func ensureDeviceIdentity(cfg Config) (State, ed25519.PrivateKey, error) {
	state, err := LoadState(cfg.StatePath)
	if err != nil {
		return State{}, nil, fmt.Errorf("load device identity state: %w", err)
	}
	if strings.HasPrefix(state.DeviceID, "swd_") {
		privateKey, err := loadDevicePrivateKey(cfg.IdentityKeyPath)
		if err != nil {
			return State{}, nil, fmt.Errorf("load device identity key: %w", err)
		}
		publicKey := privateKey.Public().(ed25519.PublicKey)
		encodedPublicKey := base64.RawURLEncoding.EncodeToString(publicKey)
		if state.DevicePublicKey != encodedPublicKey {
			return State{}, nil, errors.New("device identity state does not match the local private key")
		}
		if state.FingerprintVersion != fingerprintVersion || state.HardwareFingerprint == "" {
			return State{}, nil, errors.New("device identity state has an invalid hardware fingerprint")
		}
		if computeDeviceID(state.HardwareFingerprint, publicKey) != state.DeviceID {
			return State{}, nil, errors.New("device identity state has an invalid device ID")
		}
		return state, privateKey, nil
	}
	if state.DeviceID != "" {
		return State{}, nil, errors.New(
			"legacy device identity found; keep protocol=legacy_v1 until the operator revokes the old device and starts the explicit v2 migration",
		)
	}

	components, err := collectHardwareComponentsFn()
	if err != nil {
		return State{}, nil, err
	}
	hardwareFingerprint := computeHardwareFingerprint(components)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return State{}, nil, fmt.Errorf("generate device key: %w", err)
	}
	installationID, err := NewDeviceID()
	if err != nil {
		return State{}, nil, fmt.Errorf("generate installation id: %w", err)
	}
	deviceID := computeDeviceID(hardwareFingerprint, publicKey)
	state = State{
		SchemaVersion:       "2",
		DeviceID:            deviceID,
		InstallationID:      installationID,
		DevicePublicKey:     base64.RawURLEncoding.EncodeToString(publicKey),
		HardwareFingerprint: hardwareFingerprint,
		FingerprintVersion:  fingerprintVersion,
		HardwareComponents:  components,
		KeyVersion:          1,
	}
	if err := saveDevicePrivateKey(cfg.IdentityKeyPath, privateKey); err != nil {
		return State{}, nil, fmt.Errorf("save device identity key: %w", err)
	}
	if err := SaveState(cfg.StatePath, state); err != nil {
		_ = os.Remove(cfg.IdentityKeyPath)
		return State{}, nil, fmt.Errorf("save device identity state: %w", err)
	}
	return state, privateKey, nil
}

func withCurrentHardwareObservation(state State) State {
	components, err := collectHardwareComponentsFn()
	if err != nil {
		return state
	}
	state.HardwareComponents = components
	state.HardwareFingerprint = computeHardwareFingerprint(components)
	state.FingerprintVersion = fingerprintVersion
	return state
}

func collectHardwareComponents() (map[string]string, error) {
	raw := make(map[string]string)
	switch runtime.GOOS {
	case "linux":
		readHardwareValue(raw, "machine_id", linuxMachineIDPath())
		readHardwareValue(raw, "dmi_product_uuid", "/sys/class/dmi/id/product_uuid")
		readHardwareValue(raw, "dmi_board_serial", "/sys/class/dmi/id/board_serial")
		readHardwareValue(raw, "cloud_instance_id", "/var/lib/cloud/data/instance-id")
	case "windows":
		raw["machine_guid"] = commandOutput(3*time.Second, "reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid")
		raw["smbios_uuid"] = commandOutput(3*time.Second, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID")
	case "darwin":
		raw["platform_uuid"] = commandOutput(3*time.Second, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	}

	components := make(map[string]string)
	for name, value := range raw {
		value = normalizeHardwareValue(value)
		if value == "" || isPlaceholderHardwareValue(value) {
			continue
		}
		digest := sha256.Sum256([]byte(name + "\x00" + value))
		components[name] = "sha256:" + fmt.Sprintf("%x", digest[:])
	}
	if len(components) == 0 {
		return nil, errors.New("no stable hardware identity signal is available")
	}
	return components, nil
}

// linuxMachineIDPath lets the container deployment bind-mount the host machine
// ID read-only at a distinct path. This avoids image-layer machine IDs becoming
// a fleet identity signal while preserving the normal host default. The
// persisted device key remains required, so recreating a container without its
// data volume intentionally registers a new Agent identity.
func linuxMachineIDPath() string {
	if path := strings.TrimSpace(os.Getenv("SECWEAVER_HOST_MACHINE_ID_PATH")); path != "" {
		return path
	}
	return "/etc/machine-id"
}

func readHardwareValue(values map[string]string, name, path string) {
	body, err := os.ReadFile(path)
	if err != nil || len(body) > 4096 {
		return
	}
	values[name] = string(body)
}

func normalizeHardwareValue(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(value)), " "))
}

func isPlaceholderHardwareValue(value string) bool {
	compact := strings.NewReplacer("-", "", " ", "", ":", "").Replace(value)
	return compact == "" || strings.Trim(compact, "0") == "" || compact == "unknown" || compact == "none"
}

func computeHardwareFingerprint(components map[string]string) string {
	names := make([]string, 0, len(components))
	for name := range components {
		names = append(names, name)
	}
	sort.Strings(names)
	hash := sha256.New()
	_, _ = hash.Write([]byte("secweaver-hw-v1\x00"))
	for _, name := range names {
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write([]byte("="))
		_, _ = hash.Write([]byte(components[name]))
		_, _ = hash.Write([]byte("\x00"))
	}
	return "sha256:" + fmt.Sprintf("%x", hash.Sum(nil))
}

func computeDeviceID(hardwareFingerprint string, publicKey ed25519.PublicKey) string {
	material := []byte("secweaver-device-v1\x00" + hardwareFingerprint + "\x00")
	material = append(material, publicKey...)
	digest := sha256.Sum256(material)
	return "swd_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]))
}

func saveDevicePrivateKey(path string, privateKey ed25519.PrivateKey) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("device identity key path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	body := []byte(base64.RawURLEncoding.EncodeToString(privateKey) + "\n")
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func loadDevicePrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("device identity key must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("device identity key permissions are too broad: %04o", info.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("device identity key is invalid")
	}
	return ed25519.PrivateKey(decoded), nil
}

func randomNonce() (string, error) {
	var body [16]byte
	if _, err := rand.Read(body[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(body[:]), nil
}

var collectHardwareComponentsFn = collectHardwareComponents
