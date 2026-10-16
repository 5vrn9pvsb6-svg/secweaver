package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
	op "secweaver-agent/pkg/learningoperation"
)

// An inbox is not execution. Revision and durable checkpoint facts survive
// missing status/restarts without fabricated progress or revision rewinds.
func TestRelearningCoordinatorDurableProjection(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := relearningBinding{Data: t.TempDir(), Public: base64.StdEncoding.EncodeToString(public), Enterprise: "enterprise", Device: "device", Installation: "install"}
	status := &behaviorlearning.StatusSnapshot{Streams: map[string]behaviorlearning.StatusSnapshot{}}
	for _, kind := range []string{"exec", "file", "network", "risk"} {
		status.Streams[kind] = behaviorlearning.StatusSnapshot{Mode: "disabled", FilteringReason: "disabled"}
	}
	exec := status.Streams["exec"]
	exec.Mode = "enforcing"
	exec.RelearningToken = strings.Repeat("a", 64)
	exec.RelearningEligible = true
	exec.FilteringReason = "active"
	status.Streams["exec"] = exec
	report, err := relearningReport(binding, status)
	if err != nil || report.Receipt != nil || !op.ValidReport(report) {
		t.Fatal(report, err)
	}
	now := time.Now().UTC()
	g, err := op.Sign(op.Grant{OperationID: "operation", Sequence: "1", EnterpriseID: binding.Enterprise, DeviceID: binding.Device, InstallationID: binding.Installation, IssuedAt: now, StartBefore: now.Add(30 * time.Second), RunNotAfter: now.Add(8 * 24 * time.Hour), DurationSeconds: 86400, Targets: []op.Target{{Stream: "exec", BaselineToken: exec.RelearningToken}}}, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(g)
	if err = behaviorlearning.WriteOperationFile(binding.Data, "current.json", raw); err != nil {
		t.Fatal(err)
	}
	report, err = relearningReport(binding, status)
	if err != nil || report.Receipt.Revision != "1" || report.Receipt.Streams["exec"].State != "pending" {
		t.Fatal(report, err)
	}
	exec.Relearning = &op.Progress{OperationID: g.OperationID, Sequence: g.Sequence, Result: op.StreamResult{State: "learning", StartedAt: now, HealthySeconds: 20, RemainingSeconds: 86380, RetainedEntries: 3, AddedEntries: 1}}
	status.Streams["exec"] = exec
	report, err = relearningReport(binding, status)
	if err != nil || report.Receipt.Revision != "2" {
		t.Fatal(report, err)
	}
	exec.Relearning = nil
	status.Streams["exec"] = exec
	report, err = relearningReport(binding, status)
	if err != nil || report.Receipt.Revision != "2" || report.Receipt.Streams["exec"].HealthySeconds != 20 {
		t.Fatal("missing collector erased fact", report, err)
	}
	// A corrupt revision file cannot be treated as an absent file and reset to1.
	if err = os.WriteFile(filepath.Join(binding.Data, "learning-operations", "receipt.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = relearningReport(binding, status); err == nil {
		t.Fatal("damaged durable receipt silently reset")
	}
}
