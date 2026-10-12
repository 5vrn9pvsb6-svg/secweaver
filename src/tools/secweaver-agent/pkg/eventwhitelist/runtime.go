// Package eventwhitelist loads immutable policies outside collector hot paths.
// Semantic adapters retain ownership of source cursors and process caches.
package eventwhitelist

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"secweaver-agent/pkg/eventwhitelist/core"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const PolicyEnv = "SECWEAVER_COLLECTION_POLICY_FILE"
const PublicKeyEnv = "SECWEAVER_COLLECTION_PUBLIC_KEY"
const ModuleEnv = "SECWEAVER_COLLECTION_MODULE"
const AlertURLEnv = "SECWEAVER_COLLECTION_ALERT_URL"
const AlertTokenEnv = "SECWEAVER_COLLECTION_ALERT_TOKEN"
const maxAlertBytes = 32 << 10

type counters struct{ matched, observed, suppressed, kept, passed, queued, failed atomic.Uint64 }

func (c *counters) read() core.Counts {
	return core.Counts{Matched: c.matched.Load(), Observed: c.observed.Load(), Suppressed: c.suppressed.Load(), Kept: c.kept.Load(), Passed: c.passed.Load(), AlertsQueued: c.queued.Load(), AlertFailures: c.failed.Load()}
}

type snapshot struct {
	engine   *core.Engine
	envelope core.Envelope
	policy   core.Policy
	counters map[string]*counters
}

// Decision pins its counter across publication races without retaining an old
// policy or pooled collector event in the asynchronous queue.
type Decision struct {
	core.Decision
	counter *counters
}
type alertJob struct {
	raw     []byte
	counter *counters
}
type moduleRuntime struct {
	current                                                 atomic.Pointer[snapshot]
	mu                                                      sync.Mutex // loader/status metadata only; Decide never acquires this lock
	status                                                  core.ModuleStatus
	file, public, eid, device, module, alertURL, alertToken string
	platform                                                string
	alerts                                                  chan alertJob
	pending                                                 atomic.Int64
	lastHash                                                [32]byte
	changed                                                 chan struct{}
}

var active atomic.Pointer[moduleRuntime]

// InitFromEnv starts one bounded loader/alert worker per child. Optional rule
// failures retain unexpired last-good rules and never terminate collection.
func InitFromEnv(ctx context.Context) (func(), error) {
	path, module := os.Getenv(PolicyEnv), os.Getenv(ModuleEnv)
	if path == "" || module == "" {
		return func() {}, nil
	}
	if !filepath.IsAbs(path) {
		return func() {}, fmt.Errorf("collection policy path must be absolute")
	}
	r := &moduleRuntime{file: path, public: os.Getenv(PublicKeyEnv), eid: os.Getenv("SECWEAVER_ENTERPRISE_ID"), device: os.Getenv("SECWEAVER_DEVICE_ID"), module: module, alertURL: os.Getenv(AlertURLEnv), alertToken: os.Getenv(AlertTokenEnv), alerts: make(chan alertJob, 64), changed: make(chan struct{}, 1)}
	r.status = core.ModuleStatus{State: "unmanaged", ProcessID: os.Getpid()}
	r.platform = runtime.GOOS
	active.Store(r)
	r.reload()
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); r.loop(workerCtx) }()
	return func() { active.CompareAndSwap(r, nil); cancel(); <-done; r.persistStatus() }, nil
}

// AtomicFile persists restrictive complete JSON before rename. The parent owns
// policy mutation; child readers see either complete generation.
func AtomicFile(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".collection-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}

// ReadBounded refuses symlinks, special files and oversized administrative input.
func ReadBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("invalid bounded collection file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("collection file too large")
	}
	return raw, err
}

func (r *moduleRuntime) reload() {
	if _, err := os.Stat(r.file + ".disabled"); err == nil {
		old := r.current.Swap(nil)
		if old != nil {
			select {
			case r.changed <- struct{}{}:
			default:
			}
		}
		r.lastHash = [32]byte{}
		r.setState("local_disabled", "")
		return
	}
	raw, err := ReadBounded(r.file, core.MaxPolicyBytes+8192)
	if os.IsNotExist(err) {
		if r.current.Load() == nil {
			r.setState("unmanaged", "")
		}
		return
	}
	if err != nil {
		r.setState("apply_failed", "policy_file_unreadable")
		return
	}
	hash := sha256.Sum256(raw)
	if hash == r.lastHash {
		return
	}
	var env core.Envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&env); err != nil {
		r.setState("apply_failed", "policy_envelope_invalid")
		return
	}
	p, err := env.Verify(r.public, r.eid, r.device, time.Now())
	if err != nil {
		r.setState("apply_failed", "policy_verification_failed")
		return
	}
	old := r.current.Load()
	if old != nil && (p.Revision < old.policy.Revision || p.Revision == old.policy.Revision && env.Digest != old.envelope.Digest) {
		r.setState("apply_failed", "policy_revision_replay")
		return
	}
	engine, err := core.Compile(p)
	if err != nil {
		r.setState("apply_failed", "policy_compile_failed")
		return
	}
	counts := make(map[string]*counters, len(p.Rules))
	for _, rule := range p.Rules {
		counts[rule.ID] = &counters{}
	}
	if old != nil && old.policy.Revision == p.Revision {
		counts = old.counters
	}
	r.current.Store(&snapshot{engine: engine, envelope: env, policy: p, counters: counts})
	r.lastHash = hash
	r.mu.Lock()
	r.status.Revision = p.Revision
	r.status.Digest = env.Digest
	r.status.State = "applied"
	for _, rule := range p.Rules {
		if rule.Enabled && rule.Kind == "listener_scope" && r.module == "audit-port-execmon" {
			r.status.State = "pending_listener"
			break
		}
	}
	r.status.Error = ""
	r.mu.Unlock()
	select {
	case r.changed <- struct{}{}:
	default:
	}
	r.persistStatus()
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func (r *moduleRuntime) setState(state, reason string) {
	r.mu.Lock()
	r.status.State = state
	r.status.Error = reason
	r.mu.Unlock()
}
func (r *moduleRuntime) persistStatus() {
	r.mu.Lock()
	status := r.status
	r.mu.Unlock()
	status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	status.Counts = map[string]core.Counts{}
	if s := r.current.Load(); s != nil {
		for id, c := range s.counters {
			status.Counts[id] = c.read()
		}
	}
	_ = AtomicFile(StatusPath(r.file, r.module), mustJSON(status))
}
func StatusPath(policy, module string) string { return policy + "." + module + ".status.json" }

// Changes coalesces publications for bounded listener reconciliation.
func Changes() <-chan struct{} {
	if r := active.Load(); r != nil {
		return r.changed
	}
	return nil
}

// loop owns loading and alert I/O. Shutdown gets a fresh bounded context, rather
// than draining with the already-cancelled collector context.
func (r *moduleRuntime) loop(ctx context.Context) {
	reload := time.NewTicker(2 * time.Second)
	defer reload.Stop()
	report := time.NewTicker(10 * time.Second)
	defer report.Stop()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for {
		select {
		case <-ctx.Done():
			drain, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			for {
				select {
				case job := <-r.alerts:
					r.send(drain, client, job)
				case <-drain.Done():
					// Count unsent jobs before dropping the bounded shutdown queue.
					for {
						select {
						case job := <-r.alerts:
							r.pending.Add(-int64(len(job.raw)))
							job.counter.failed.Add(1)
						default:
							return
						}
					}
				default:
					return
				}
			}
		case job := <-r.alerts:
			r.send(ctx, client, job)
		case <-reload.C:
			r.reload()
		case <-report.C:
			if s := r.current.Load(); s != nil {
				end, _ := time.Parse(time.RFC3339, s.envelope.ExpiresAt)
				if !time.Now().Before(end) {
					r.mu.Lock()
					wasExpired := r.status.State == "expired"
					r.mu.Unlock()
					r.setState("expired", "policy_expired")
					if !wasExpired {
						select {
						case r.changed <- struct{}{}:
						default:
						}
					}
				}
			}
			r.persistStatus()
		}
	}
}
func (r *moduleRuntime) send(ctx context.Context, client *http.Client, job alertJob) {
	defer r.pending.Add(-int64(len(job.raw)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.alertURL, bytes.NewReader(job.raw))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+r.alertToken)
		var resp *http.Response
		resp, err = client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			if resp.StatusCode != 202 {
				err = fmt.Errorf("alert sink rejected")
			}
		}
	}
	if err != nil {
		job.counter.failed.Add(1)
	}
}

// Decide performs no I/O, compilation or global locking. Keep/alert bypass
// learning exactly once; collectors continue their normal source bookkeeping.
func Decide(e core.Event) Decision {
	r := active.Load()
	if r == nil {
		return Decision{Decision: core.Decision{Action: "pass", Reason: "unmanaged"}}
	}
	s := r.current.Load()
	if s == nil {
		return Decision{Decision: core.Decision{Action: "pass", Reason: "unmanaged"}}
	}
	end, _ := time.Parse(time.RFC3339, s.envelope.ExpiresAt)
	if !time.Now().Before(end) {
		return Decision{Decision: core.Decision{Action: "keep", Revision: s.policy.Revision, Reason: "expired"}}
	}
	if e.Backfill {
		return Decision{Decision: core.Decision{Action: "pass", Revision: s.policy.Revision, Reason: "history_preserved"}}
	}
	e.Platform = r.platform
	e.DeviceID = r.device
	e.Module = r.module
	d := s.engine.Decide(e, time.Now())
	counter := s.counters[d.RuleID]
	if c := s.counters[d.PredictedRuleID]; c != nil {
		c.observed.Add(1)
	}
	if counter != nil {
		counter.matched.Add(1)
		switch d.Action {
		case "suppress":
			counter.suppressed.Add(1)
		case "keep", "alert":
			counter.kept.Add(1)
		case "pass":
			counter.passed.Add(1)
		}
	}
	return Decision{Decision: d, counter: counter}
}

// Alert redacts and copies registered fields before queue admission. Overflow or
// sink failure cannot change the caller's obligation to retain its original.
func Alert(d Decision, evidenceID, timestamp string, fields map[string]any) {
	r := active.Load()
	if r == nil || d.Action != "alert" || d.counter == nil {
		return
	}
	digest := sha256.Sum256([]byte(r.device + "\x00" + evidenceID + "\x00" + d.RuleID + "\x00" + fmt.Sprint(d.Revision)))
	record := map[string]any{"event_type": "custom_risk_alert", "asset_type": "custom_risk_alert", "evidence_id": "custom:" + hex.EncodeToString(digest[:]), "rule_id": d.RuleID, "policy_revision": d.Revision, "source_evidence_id": evidenceID, "timestamp": timestamp, "generated_at": time.Now().UTC().Format(time.RFC3339), "alert": d.Alert, "source_fields": RedactFields(fields), "module": r.module, "device_id": r.device}
	raw := mustJSON(record)
	// A custom rule can raise severity, but must not lower the source alert.
	levels := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	if native, ok := fields["/severity"].(string); ok && d.Alert != nil && levels[native] > levels[d.Alert.Severity] {
		alert := *d.Alert
		alert.Severity = native
		record["alert"] = &alert
		raw = mustJSON(record)
	}
	// Top-level risk fields reuse the established DataAsset risk adapter. They
	// express an administrator's alert verdict, not independent proof of attack.
	if alert, ok := record["alert"].(*core.Alert); ok && alert != nil {
		record["severity"], record["risk_level"] = alert.Severity, alert.Severity
		record["rule_name"], record["message"] = alert.Title, alert.Description
		raw = mustJSON(record)
	}
	if len(raw) > maxAlertBytes {
		delete(record, "source_fields")
		record["source_fields_omitted"] = true
		raw = mustJSON(record)
	}
	size := int64(len(raw))
	if r.alertURL == "" {
		d.counter.failed.Add(1)
		return
	}
	if r.pending.Add(size) > 1<<20 {
		r.pending.Add(-size)
		d.counter.failed.Add(1)
		return
	}
	select {
	case r.alerts <- alertJob{raw: raw, counter: d.counter}:
		d.counter.queued.Add(1)
	default:
		r.pending.Add(-size)
		d.counter.failed.Add(1)
	}
}

// SemanticFields omits unavailable strings. Windows explicitly restores empty
// listener_process because that value belongs to its evidence contract.
func SemanticFields(values map[string]any) map[string]any {
	for k, v := range values {
		if s, ok := v.(string); ok && strings.TrimSpace(s) == "" {
			delete(values, k)
		}
	}
	return values
}
