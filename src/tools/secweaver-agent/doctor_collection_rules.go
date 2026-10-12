package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/eventwhitelist"
	"secweaver-agent/pkg/eventwhitelist/core"
	"time"
)

// doctorCheckCollectionRules verifies local trust and expiry without starting
// the writer or treating downloaded bytes as proof of module/cloud delivery.
func doctorCheckCollectionRules(cfg agentConfig, add func(doctorLevel, string, string, string)) {
	path := cfg.CollectionRules.PolicyFile
	if path == "" {
		path = filepath.Join(filepath.Dir(cfg.License.Normalize().StatePath), "collection-rules", "current.json")
	}
	if _, err := os.Stat(path + ".disabled"); err == nil {
		add(doctorWarn, "collection_rules", "Collection rules locally disabled", path+".disabled")
		return
	}
	raw, err := eventwhitelist.ReadBounded(path, core.MaxPolicyBytes+8192)
	if os.IsNotExist(err) {
		add(doctorOK, "collection_rules", "No published custom collection policy", path)
		return
	}
	if err != nil {
		add(doctorWarn, "collection_rules", "Collection policy unreadable; originals retained", path)
		return
	}
	key := cfg.CollectionRules.PublicKey
	if key == "" {
		key = eventwhitelist.DefaultPublicKey
	}
	state, err := agentlicense.LoadState(cfg.License.Normalize().StatePath)
	if err != nil {
		add(doctorWarn, "collection_rules", "Device identity unavailable for policy verification", "")
		return
	}
	var env core.Envelope
	if json.Unmarshal(raw, &env) != nil {
		add(doctorWarn, "collection_rules", "Collection envelope invalid", "")
		return
	}
	if _, err = env.Verify(key, cfg.EnterpriseID, state.DeviceID, time.Now()); err != nil {
		add(doctorWarn, "collection_rules", "Collection signature/binding/expiry invalid", "")
		return
	}
	add(doctorOK, "collection_rules", "Collection envelope verified; check module heartbeat receipts for application", env.Digest)
}
