package hoststatesnapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secweaver-agent/internal/agentactivity"
)

func TestCollectionEventsBaselineAndDiff(t *testing.T) {
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	initial := []entity{
		{Key: "account:alice", EntityType: "identity_account", AssetType: "host_identity", Fields: map[string]any{"user": "alice", "enabled": true}},
		{Key: "session:alice", EntityType: "login_session", AssetType: "host_identity", Fields: map[string]any{"user": "alice"}},
	}
	events, state := collectionEvents("identity", initial, persistedCollection{}, false, 24*time.Hour, "host-a", "10.0.0.1", now)
	if len(events) != 2 || events[0]["action"] != "observed" {
		t.Fatalf("unexpected baseline events: %#v", events)
	}
	current := []entity{
		{Key: "account:alice", EntityType: "identity_account", AssetType: "host_identity", Fields: map[string]any{"user": "alice", "enabled": false}},
		{Key: "account:bob", EntityType: "identity_account", AssetType: "host_identity", Fields: map[string]any{"user": "bob", "enabled": true}},
	}
	events, _ = collectionEvents("identity", current, state, false, 24*time.Hour, "host-a", "10.0.0.1", now.Add(time.Minute))
	actions := map[string]string{}
	for _, event := range events {
		actions[event["entity_key"].(string)] = event["event_type"].(string)
	}
	if actions["account:alice"] != "identity_change" || actions["account:bob"] != "identity_change" || actions["session:alice"] != "login_session_ended" {
		t.Fatalf("unexpected diff event types: %#v", actions)
	}
}

func TestDefaultSocketInterval(t *testing.T) {
	if defaultSocketInterval != 5*time.Minute {
		t.Fatalf("default socket interval = %v, want 5m", defaultSocketInterval)
	}
}

func TestContainerWorkloadCollectorsOmitHostServiceState(t *testing.T) {
	collectors := platformCollectors(time.Minute, time.Minute, time.Minute, time.Minute, 100, true)
	names := make([]string, 0, len(collectors))
	for _, collector := range collectors {
		names = append(names, collector.Name)
	}
	if got := strings.Join(names, ","); got != "socket,identity,kernel" {
		t.Fatalf("container collectors = %q", got)
	}
}

func TestSocketSnapshotAlwaysEmitsObserved(t *testing.T) {
	item := entity{Key: "tcp|0.0.0.0|22", EntityType: "listening_socket", AssetType: "host_socket", Fields: map[string]any{"protocol": "tcp", "listen_port": 22}}
	events, _ := collectionEvents("socket", []entity{item}, persistedCollection{}, false, 24*time.Hour, "host", "", time.Now().UTC())
	if len(events) != 1 || events[0]["event_type"] != "listening_socket_snapshot" || events[0]["action"] != "observed" {
		t.Fatalf("unexpected socket snapshot: %#v", events)
	}
}

func TestCollectionEventsDeduplicatesEntityKeys(t *testing.T) {
	item := entity{Key: "same", EntityType: "listening_socket", AssetType: "host_socket"}
	events, _ := collectionEvents("socket", []entity{item, item}, persistedCollection{}, false, time.Hour, "host", "", time.Now().UTC())
	if len(events) != 1 || events[0]["snapshot_entity_count"] != 1 {
		t.Fatalf("duplicate entities were emitted: %#v", events)
	}
}

func TestPersistedCollectionEqualIgnoresMapOrder(t *testing.T) {
	left := persistedCollection{Initialized: true, LastFullSnapshot: "2026-07-16T08:00:00Z", Entities: map[string]entity{
		"a": {Key: "a", Fields: map[string]any{"port": 22, "process": "sshd"}},
		"b": {Key: "b", Fields: map[string]any{"port": 443, "process": "nginx"}},
	}}
	right := persistedCollection{Initialized: true, LastFullSnapshot: left.LastFullSnapshot, Entities: map[string]entity{
		"b": left.Entities["b"],
		"a": left.Entities["a"],
	}}
	if !persistedCollectionEqual(left, right) {
		t.Fatal("equivalent collections should not trigger a state rewrite")
	}
	right.Entities["a"] = entity{Key: "a", Fields: map[string]any{"port": 23, "process": "sshd"}}
	if persistedCollectionEqual(left, right) {
		t.Fatal("changed collection must be persisted")
	}
}

func TestDecodeProcEndpoint(t *testing.T) {
	address, port, ok := decodeProcEndpoint("0100007F:0016", false)
	if !ok || address != "127.0.0.1" || port != 22 {
		t.Fatalf("got %q:%d ok=%v", address, port, ok)
	}
}

func TestParseLinuxIdentityDoesNotExposePasswordHash(t *testing.T) {
	shadow := parseLinuxShadow("alice:$6$salt$hash:20000:0:99999:7:::\n")
	items := parseLinuxPasswd("alice:x:1000:1000:Alice:/home/alice:/bin/bash\n", map[string][]string{"alice": {"sudo"}}, shadow)
	if len(items) != 1 {
		t.Fatalf("got %d identities", len(items))
	}
	body, _ := json.Marshal(items[0])
	if bytes.Contains(body, []byte("$6$")) || bytes.Contains(body, []byte("hash")) {
		t.Fatalf("password hash leaked: %s", body)
	}
}

func TestCollectLinuxContainerIdentityDoesNotRequireShadow(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "passwd"), []byte("app:x:1000:1000:Application:/app:/sbin/nologin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "group"), []byte("app:x:1000:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	items, err := collectLinuxContainerIdentity(root, time.Now())
	if err != nil || len(items) != 1 || items[0].Key != "account:app" {
		t.Fatalf("container identity = %#v err=%v", items, err)
	}
}

func TestDecodeWindowsEntitiesObjectAndArray(t *testing.T) {
	for _, body := range [][]byte{
		[]byte(`{"key":"service:sshd","entity_type":"service","service_name":"sshd"}`),
		[]byte(`[{"key":"service:sshd","entity_type":"service","service_name":"sshd"}]`),
	} {
		items, err := decodeWindowsEntities(body, "host_service")
		if err != nil || len(items) != 1 || items[0].Key != "service:sshd" || items[0].AssetType != "host_service" {
			t.Fatalf("decode result=%#v err=%v", items, err)
		}
	}
}

func TestRecognizesOnlyExactInternalWindowsScript(t *testing.T) {
	known := agentactivity.MarkPowerShellScript(windowsSocketScriptV2)
	if !agentactivity.IsInternalPowerShellScript(known) {
		t.Fatal("fixed collector script should be recognized")
	}
	if agentactivity.IsInternalPowerShellScript(known + "; Invoke-Expression 'malicious'") {
		t.Fatal("modified script must not be recognized as an internal collector")
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := persistedState{Version: parserVersion, Collections: map[string]persistedCollection{"identity": {LastFullSnapshot: time.Now().UTC().Format(time.RFC3339Nano), Entities: map[string]entity{"account:a": {Key: "account:a"}}}}}
	if err := saveState(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadState(path)
	if err != nil || got.Version != parserVersion || got.Collections["identity"].Entities["account:a"].Key != "account:a" {
		t.Fatalf("round trip got=%#v err=%v", got, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state mode is %o", info.Mode().Perm())
	}
}

func TestCorruptStateIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := loadState(path)
	if err != nil || len(state.Collections) != 0 {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	matches, err := filepath.Glob(path + ".corrupt-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("quarantined states=%v err=%v", matches, err)
	}
}

func TestContainerDigestIgnoresVolatileProcessList(t *testing.T) {
	a := entity{Key: "container:a", EntityType: "container_context", Fields: map[string]any{"container_id": "a", "process_count": 1, "pids": []int{1}}}
	b := entity{Key: "container:a", EntityType: "container_context", Fields: map[string]any{"container_id": "a", "process_count": 2, "pids": []int{2, 3}}}
	if entityDigest(a) != entityDigest(b) {
		t.Fatal("volatile container process membership should not create a context-change event")
	}
}

func TestContainerProcessCountDeduplicatesControllersBeforeLimit(t *testing.T) {
	// Model both cgroup v1 repeated controllers and v2, using synthetic procfs.
	for _, count := range []int{1, 100, 103} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			root := t.TempDir()
			id := strings.Repeat("a", 64)
			for pid := 1; pid <= count; pid++ {
				dir := filepath.Join(root, fmt.Sprint(pid))
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				body := fmt.Sprintf("1:cpu:/docker/%s\n2:memory:/docker/%s\n0::/docker/%s\n", id, id, id)
				if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			items := linuxContainerEntities(root)
			if len(items) != 1 || items[0].Fields["process_count"] != count {
				t.Fatalf("entities: %#v", items)
			}
			pids := items[0].Fields["pids"].([]int)
			want := count
			if want > 100 {
				want = 100
			}
			if len(pids) != want {
				t.Fatalf("pids len=%d want=%d", len(pids), want)
			}
			for i, pid := range pids {
				if pid != i+1 {
					t.Fatalf("unstable or duplicate pids: %v", pids)
				}
			}
		})
	}
}
