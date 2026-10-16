package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/eventwhitelist"
	op "secweaver-agent/pkg/learningoperation"
)

type relearningBinding struct{ Data, Public, Enterprise, Device, Installation string }
type relearningReceiptFile struct {
	Digest  string     `json:"digest"`
	Receipt op.Receipt `json:"receipt"`
}

// localRelearningBinding reads installation-owned configuration/identity only.
// A failed optional read withdraws this capability, never license supervision.
func localRelearningBinding(cfg agentlicense.Config, configPath string) (relearningBinding, error) {
	if !cfg.DeviceAuthEnabled() {
		return relearningBinding{}, fmt.Errorf("legacy identity")
	}
	state, err := agentlicense.LoadState(cfg.Normalize().StatePath)
	if err != nil {
		return relearningBinding{}, err
	}
	config, err := loadConfig(configPath)
	if err != nil {
		return relearningBinding{}, err
	}
	public := config.CollectionRules.PublicKey
	if public == "" {
		public = eventwhitelist.DefaultPublicKey
	}
	return relearningBinding{filepath.Dir(cfg.Normalize().StatePath), public, state.EnterpriseID, state.DeviceID, state.InstallationID}, nil
}

// relearningReport aggregates checkpoint facts; writing an inbox is never an
// acknowledgement of execution. Missing receipts stay pending even after the
// permit expires: a writer can be blocked in fsync, so absence proves nothing.
// Revision/contents are durably coupled before sending an authenticated report.
func relearningReport(binding relearningBinding, status *behaviorlearning.StatusSnapshot) (*op.Report, error) {
	if status == nil {
		return nil, fmt.Errorf("missing learning status")
	}
	report := &op.Report{Capability: op.Capability, Streams: map[string]op.Snapshot{}}
	for _, kind := range []string{"exec", "file", "network", "risk"} {
		s := status.Streams[kind]
		reason := s.FilteringReason
		if s.Mode != "enforcing" {
			reason = s.Mode
		}
		if reason == "" {
			reason = "status_unavailable"
		}
		report.Streams[kind] = op.Snapshot{BaselineToken: s.RelearningToken, Eligible: s.RelearningEligible, Reason: reason}
	}
	body, err := behaviorlearning.ReadOperationFile(binding.Data, "current.json")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return report, nil
		}
		return nil, err
	}
	grant, err := op.Decode(body)
	if err != nil {
		return report, err
	}
	if err := grant.VerifyIdentity(binding.Public, binding.Enterprise, binding.Device, binding.Installation); err != nil {
		return report, err
	}
	receipt := op.Receipt{OperationID: grant.OperationID, Sequence: grant.Sequence, Revision: "1", State: "reconciling", Streams: map[string]op.StreamResult{}}
	for _, target := range grant.Targets {
		result := op.StreamResult{State: "pending", Reason: "acceptance_unconfirmed", RemainingSeconds: 86400}
		if progress := status.Streams[target.Stream].Relearning; progress != nil && progress.OperationID == grant.OperationID && progress.Sequence == grant.Sequence {
			result = progress.Result
		} else if raw, e := behaviorlearning.ReadOperationFile(binding.Data, target.Stream+".json"); e == nil {
			var refusal behaviorlearning.RelearningRefusal
			if json.Unmarshal(raw, &refusal) == nil && refusal.OperationID == grant.OperationID && refusal.Sequence == grant.Sequence && refusal.Digest == grant.Digest && refusal.Result.State == "rejected" {
				result = refusal.Result
			}
		}
		receipt.Streams[target.Stream] = result
	}
	var prior relearningReceiptFile
	unchanged := false
	if raw, e := behaviorlearning.ReadOperationFile(binding.Data, "receipt.json"); e == nil {
		if json.Unmarshal(raw, &prior) != nil {
			return report, fmt.Errorf("invalid local relearning receipt")
		}
		decodedDigest, digestErr := hex.DecodeString(prior.Digest)
		if digestErr != nil || len(decodedDigest) != 32 || !op.ValidReport(&op.Report{Capability: op.Capability, Streams: report.Streams, Receipt: &prior.Receipt}) {
			return nil, fmt.Errorf("invalid durable relearning receipt")
		}
		if prior.Digest == grant.Digest && prior.Receipt.OperationID == grant.OperationID {
			if prior.Receipt.Sequence != grant.Sequence || !op.ValidReport(&op.Report{Capability: op.Capability, Streams: report.Streams, Receipt: &prior.Receipt}) {
				return nil, fmt.Errorf("invalid durable relearning receipt")
			}
			// A temporarily unreadable collector cannot retract an already durable
			// start/terminal fact. Re-send the original revision unchanged; Gateway
			// deliberately does not refresh its observation time for such a replay.
			for kind, old := range prior.Receipt.Streams {
				next := receipt.Streams[kind]
				terminal := old.State == "completed" || old.State == "rejected" || old.State == "expired" || old.State == "failed"
				if next.State == "pending" || terminal || next.HealthySeconds < old.HealthySeconds {
					receipt.Streams[kind] = old
				}
			}
			n, e := op.SequenceValue(prior.Receipt.Revision)
			if e != nil {
				return report, e
			}
			receipt.Revision = prior.Receipt.Revision
			a, _ := json.Marshal(prior.Receipt.Streams)
			b, _ := json.Marshal(receipt.Streams)
			if string(a) != string(b) {
				if n == 1<<63-1 {
					return report, fmt.Errorf("relearning revision exhausted")
				}
				receipt.Revision = fmt.Sprint(n + 1)
			} else {
				unchanged = true
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	report.Receipt = &receipt
	if !op.ValidReport(report) {
		return nil, fmt.Errorf("invalid checkpoint operation projection")
	}
	if !unchanged {
		raw, _ := json.Marshal(relearningReceiptFile{grant.Digest, receipt})
		if err := behaviorlearning.WriteOperationFile(binding.Data, "receipt.json", raw); err != nil {
			return nil, err
		}
	}
	return report, nil
}

// acceptRelearningDelivery shares the existing config/upgrade mutation fence.
// TryLock never queues behind an upgrade; unknown/in-flight upgrade state also
// defers claim. No service or evidence-reader restart is requested here.
func acceptRelearningDelivery(ctx context.Context, binding relearningBinding, cfg agentlicense.Config, report *op.Report, response agentlicense.Response, updater *scheduledUpdateConfig) error {
	var notice struct {
		OperationID string `json:"operation_id"`
	}
	if json.Unmarshal(response.RelearningDelivery, &notice) != nil || notice.OperationID == "" || report == nil {
		return nil
	}
	if raw, err := behaviorlearning.ReadOperationFile(binding.Data, "current.json"); err == nil {
		if g, e := op.Decode(raw); e == nil && g.OperationID == notice.OperationID && g.VerifyIdentity(binding.Public, binding.Enterprise, binding.Device, binding.Installation) == nil {
			return nil
		}
	}
	if !configMutationMu.TryLock() {
		return nil
	}
	defer configMutationMu.Unlock()
	if runtimeConfigRestartScheduled || !runtimePolicyRestartAllowed(updateHeartbeatReport(updater)) {
		return nil
	}
	claimCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	claim, err := (agentlicense.Client{}).ClaimRelearning(claimCtx, cfg, version, notice.OperationID, report)
	if err != nil {
		return err
	}
	g, err := op.Decode(claim.RelearningGrant)
	if err != nil {
		return err
	}
	if g.OperationID != notice.OperationID || !g.CanStart(time.Now()) {
		return fmt.Errorf("stale relearning permission")
	}
	if err := g.VerifyIdentity(binding.Public, binding.Enterprise, binding.Device, binding.Installation); err != nil {
		return err
	}
	return behaviorlearning.WriteOperationFile(binding.Data, "current.json", claim.RelearningGrant)
}
