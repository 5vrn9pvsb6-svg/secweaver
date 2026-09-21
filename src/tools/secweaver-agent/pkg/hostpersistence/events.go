package hostpersistence

import (
	"crypto/sha256"
	"encoding/hex"

	"fmt"

	"sort"
	"strings"

	"time"
)

// This file converts state transitions into stable host_persistence evidence and attaches audit actor context when available.

func diffStates(previous, current map[string]fileState, emitBaseline bool, host, hostIP string, now time.Time, cfg runtimeConfig, tracker *auditTracker) []persistenceEvent {
	var events []persistenceEvent
	timestamp := now.Format(time.RFC3339)
	if previous == nil {
		previous = map[string]fileState{}
	}
	if emitBaseline {
		paths := sortedStateKeys(current)
		for _, path := range paths {
			events = append(events, eventForChange("observed", current[path], fileState{}, host, hostIP, timestamp, cfg, nil))
		}
		return events
	}

	for _, path := range sortedStateKeys(current) {
		cur := current[path]
		prev, ok := previous[path]
		if !ok {
			events = append(events, eventForChange("created", cur, fileState{}, host, hostIP, timestamp, cfg, tracker))
			continue
		}
		if stateChanged(prev, cur) {
			events = append(events, eventForChange("modified", cur, prev, host, hostIP, timestamp, cfg, tracker))
		}
	}
	for _, path := range sortedStateKeys(previous) {
		if _, ok := current[path]; !ok {
			events = append(events, eventForChange("deleted", previous[path], previous[path], host, hostIP, timestamp, cfg, tracker))
		}
	}
	return events
}

func stateChanged(prev, cur fileState) bool {
	return prev.Mode != cur.Mode ||
		prev.Size != cur.Size ||
		prev.ModTime != cur.ModTime ||
		prev.Hash != cur.Hash ||
		(prev.ContentCaptured && cur.ContentCaptured && prev.Content != cur.Content) ||
		prev.SymlinkTarget != cur.SymlinkTarget ||
		prev.Category != cur.Category ||
		prev.PersistenceType != cur.PersistenceType ||
		prev.FileType != cur.FileType
}

func sortedStateKeys(items map[string]fileState) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func eventForChange(action string, cur, prev fileState, host, hostIP, timestamp string, cfg runtimeConfig, tracker *auditTracker) persistenceEvent {
	message := fmt.Sprintf("host persistence %s: %s", action, cur.Path)
	if action == "deleted" {
		message = fmt.Sprintf("host persistence deleted: %s", prev.Path)
	}
	diff, truncated := buildContentDiff(action, cur, prev, cfg.MaxDiffLines)
	event := persistenceEvent{
		EvidenceID:           persistenceEvidenceID(host, timestamp, action, cur, prev),
		AssetType:            "host_persistence",
		Time:                 timestamp,
		Timestamp:            timestamp,
		Host:                 host,
		HostName:             host,
		HostIP:               hostIP,
		EventType:            defaultPersistenceEvt,
		Action:               action,
		Category:             cur.Category,
		PersistenceType:      cur.PersistenceType,
		Path:                 cur.Path,
		FileType:             cur.FileType,
		Mode:                 cur.Mode,
		Size:                 cur.Size,
		ModTime:              cur.ModTime,
		Hash:                 cur.Hash,
		PreviousHash:         prev.Hash,
		PreviousMode:         prev.Mode,
		PreviousSize:         prev.Size,
		PreviousModTime:      prev.ModTime,
		SymlinkTarget:        cur.SymlinkTarget,
		ContentDiff:          diff,
		ContentDiffTruncated: truncated,
		Message:              message,
		Fields: map[string]string{
			"parser": "host-persistence",
		},
		ParserVersion: parserVersion,
	}
	if action == "deleted" {
		event.Category = prev.Category
		event.PersistenceType = prev.PersistenceType
		event.Path = prev.Path
		event.FileType = prev.FileType
		event.Mode = ""
		event.Size = 0
		event.ModTime = ""
		event.Hash = ""
		event.SymlinkTarget = ""
	}
	if tracker != nil {
		if change, ok := tracker.Find(event.Path, timestamp); ok {
			enrichWithAudit(&event, change)
		}
	}
	return event
}

func persistenceEvidenceID(host, timestamp, action string, cur, prev fileState) string {
	h := sha256.New()
	parts := []string{
		host,
		timestamp,
		action,
		cur.Path,
		cur.Hash,
		cur.Mode,
		cur.ModTime,
		prev.Hash,
		prev.Mode,
		prev.ModTime,
	}
	_, _ = h.Write([]byte(strings.Join(parts, "|")))
	return "host-persistence-" + hex.EncodeToString(h.Sum(nil))
}
