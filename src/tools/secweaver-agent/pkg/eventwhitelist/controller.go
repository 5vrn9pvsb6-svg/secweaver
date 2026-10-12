package eventwhitelist

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"secweaver-agent/pkg/eventwhitelist/core"
	agentoutput "secweaver-agent/pkg/output"
	"sync"
	"time"
)

// DefaultPublicKey is the SaaS collection-policy trust root, independent of the
// update-manifest key. Private deployments may explicitly override this key.
const DefaultPublicKey = "RaGV5I8O7iUqXNBH7TxEbS2DqHCus987E3gPU+f32RI="

type Config struct {
	Enabled     *bool  `json:"enabled,omitempty"`
	PolicyFile  string `json:"policy_file,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	AlertOutput string `json:"alert_output,omitempty"`
}

type Controller struct {
	config                  Config
	eid, device, url, token string
	legacyPorts             []int
	mu                      sync.Mutex // parent policy writes are serialized, separate from alert I/O
}

// Start owns the sole rotating alert writer. Child module queues upload only to
// this random loopback endpoint with a per-process secret. Writer failure leaves
// event filtering available; alert rules are not advertised as ready.
func Start(cfg Config, stateDir, logsDir, eid, device string) (*Controller, func(), error) {
	if cfg.Enabled != nil && !*cfg.Enabled {
		return nil, func() {}, nil
	}
	if cfg.PolicyFile == "" {
		cfg.PolicyFile = filepath.Join(stateDir, "collection-rules", "current.json")
	}
	if cfg.PublicKey == "" {
		cfg.PublicKey = DefaultPublicKey
	}
	if cfg.AlertOutput == "" {
		cfg.AlertOutput = filepath.Join(logsDir, "custom-risk-alert.log")
	}
	if !filepath.IsAbs(cfg.PolicyFile) || !filepath.IsAbs(cfg.AlertOutput) {
		return nil, func() {}, fmt.Errorf("collection paths must be absolute")
	}
	c := &Controller{config: cfg, eid: eid, device: device}
	// Parent identity comes from verified configuration, not child-only env.
	out, closeOut, err := agentoutput.OpenEnterpriseEventAppend(agentoutput.AppendOptions{Path: cfg.AlertOutput, Perm: 0600, MaxSizeBytes: 100 << 20, MaxBackups: 5}, eid)
	if err != nil {
		return c, func() {}, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		closeOut()
		return c, func() {}, err
	}
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		listener.Close()
		closeOut()
		return c, func() {}, err
	}
	c.token = hex.EncodeToString(token)
	c.url = "http://" + listener.Addr().String() + "/alert"
	var writerMu sync.Mutex
	server := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/alert" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+c.token)) != 1 {
			http.Error(w, "denied", 403)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAlertBytes))
		if err != nil || !json.Valid(body) {
			http.Error(w, "invalid", 400)
			return
		}
		// The protected sink accepts only custom alerts; it cannot become another
		// raw-source writer or advance any module's audit/EventRecordID cursor.
		var record map[string]any
		if json.Unmarshal(body, &record) != nil || record["event_type"] != "custom_risk_alert" || record["device_id"] != device {
			http.Error(w, "invalid", 400)
			return
		}
		writerMu.Lock()
		_, err = out.Write(append(body, '\n'))
		if err == nil {
			err = agentoutput.Checkpoint(out)
		}
		writerMu.Unlock()
		if err != nil {
			http.Error(w, "write_failed", 503)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	return c, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = server.Close()
		<-done
		writerMu.Lock()
		closeOut()
		writerMu.Unlock()
	}, nil
}

// Env binds policy readers and local alert submission to this supervised run.
func (c *Controller) Env(module string) []string {
	if c == nil {
		return nil
	}
	return []string{PolicyEnv + "=" + c.config.PolicyFile, PublicKeyEnv + "=" + c.config.PublicKey, ModuleEnv + "=" + module, AlertURLEnv + "=" + c.url, AlertTokenEnv + "=" + c.token}
}
func (c *Controller) Capabilities() []string {
	if c == nil {
		return nil
	}
	caps := []string{core.Capability}
	if c.url != "" {
		caps = append(caps, core.AlertCapability)
	}
	return caps
}

// SetLegacyPorts records configuration metadata, never commands or events.
// It is called before module/heartbeat workers start, so no runtime lock is needed.
func (c *Controller) SetLegacyPorts(ports []int) {
	if c != nil {
		c.legacyPorts = append([]int{}, ports...)
	}
}

// Apply verifies device binding, freshness and monotonic revision before any
// file mutation. A renewal never changes the immutable content or learner state.
func (c *Controller) Apply(env *core.Envelope) error {
	if c == nil || env == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := env.Verify(c.config.PublicKey, c.eid, c.device, time.Now()); err != nil {
		return fmt.Errorf("collection verification failed")
	}
	previous, err := ReadBounded(c.config.PolicyFile, core.MaxPolicyBytes+8192)
	if err == nil {
		var old core.Envelope
		if json.Unmarshal(previous, &old) != nil {
			return fmt.Errorf("existing collection envelope invalid")
		}
		if env.Revision < old.Revision || env.Revision == old.Revision && env.Digest != old.Digest {
			return fmt.Errorf("collection revision replay rejected")
		}
		if env.Revision == old.Revision && env.ExpiresAt <= old.ExpiresAt {
			return nil
		}
		if err = AtomicFile(c.config.PolicyFile+".previous", previous); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return AtomicFile(c.config.PolicyFile, raw)
}

// Status accepts only fresh receipts from the actual live module PID. Download
// success cannot be promoted to applied, and a prior run's files are not proof.
func (c *Controller) Status(pids map[string]int) *core.Status {
	if c == nil {
		return nil
	}
	s := &core.Status{State: "unmanaged", UpdatedAt: time.Now().UTC().Format(time.RFC3339), Modules: map[string]core.ModuleStatus{}}
	s.LegacyPorts = c.legacyPorts
	s.LegacyPortsDigest = LegacyPortsDigest(c.legacyPorts)
	raw, err := ReadBounded(c.config.PolicyFile, core.MaxPolicyBytes+8192)
	if err != nil {
		return s
	}
	var env core.Envelope
	if json.Unmarshal(raw, &env) != nil {
		s.State = "apply_failed"
		s.Error = "policy_envelope_invalid"
		return s
	}
	s.Revision, s.Digest, s.State = env.Revision, env.Digest, "pending"
	s.EnvelopeExpiresAt = env.ExpiresAt
	end, _ := time.Parse(time.RFC3339, env.ExpiresAt)
	if !time.Now().Before(end) {
		s.State = "expired"
	}
	all, seen := true, 0
	for module, pid := range pids {
		if _, ok := core.Catalog[module]; !ok {
			continue
		}
		seen++
		if pid <= 0 {
			all = false
			s.Modules[module] = core.ModuleStatus{State: "pending", Error: "module_not_running", UpdatedAt: s.UpdatedAt}
			continue
		}
		receipt := core.ModuleStatus{State: "pending", ProcessID: pid, UpdatedAt: s.UpdatedAt}
		body, readErr := ReadBounded(StatusPath(c.config.PolicyFile, module), 128<<10)
		if readErr == nil {
			var m core.ModuleStatus
			if json.Unmarshal(body, &m) == nil {
				at, e := time.Parse(time.RFC3339, m.UpdatedAt)
				if e == nil && time.Since(at) >= -time.Minute && time.Since(at) < 45*time.Second && m.ProcessID == pid {
					receipt = m
				}
			}
		}
		s.Modules[module] = receipt
		if receipt.State != "applied" || receipt.Revision != s.Revision || receipt.Digest != s.Digest {
			all = false
		}
	}
	if all && seen > 0 && s.State != "expired" {
		s.State = "applied"
	}
	if _, e := os.Stat(c.config.PolicyFile + ".disabled"); e == nil {
		s.State = "local_disabled"
	}
	return s
}
