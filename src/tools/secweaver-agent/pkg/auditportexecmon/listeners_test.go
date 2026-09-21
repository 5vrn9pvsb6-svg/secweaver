package auditportexecmon

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNetstatCommandEnvForcesCLocale(t *testing.T) {
	input := []string{
		"PATH=/usr/local/bin:/usr/bin",
		"LANG=zh_CN.UTF-8",
		"LC_ALL=en_US.UTF-8",
		"HOME=/root",
	}
	want := []string{
		"PATH=/usr/local/bin:/usr/bin",
		"HOME=/root",
		"LC_ALL=C",
		"LANG=C",
	}
	if got := netstatCommandEnv(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("netstat environment = %#v, want %#v", got, want)
	}
}

func TestListenerDiscoverySkipsProcWhenNetstatHasPID(t *testing.T) {
	procCalls := 0
	listeners, err := findExternalListenersWithSources(0, nil, listenerDiscoverySources{
		netstatCandidates: func() (netstatListenerScan, error) {
			return netstatListenerScan{TCPListenLines: 1, Candidates: []listenerInfo{{PID: os.Getpid(), Process: "test", Address: "0.0.0.0", Port: 8080}}}, nil
		},
		socketOwners: func() (map[string]int, socketInodeScanStats) {
			procCalls++
			return nil, socketInodeScanStats{}
		},
		procListeners: func(map[string]int) []listenerInfo {
			procCalls++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("find listeners: %v", err)
	}
	if len(listeners) != 1 || listeners[0].Port != 8080 {
		t.Fatalf("listeners = %#v, want one port 8080 listener", listeners)
	}
	if procCalls != 0 {
		t.Fatalf("proc fallback calls = %d, want 0", procCalls)
	}
}

func TestListenerDiscoveryFallsBackWhenNetstatFails(t *testing.T) {
	ownerCalls := 0
	listeners, err := findExternalListenersWithSources(0, nil, listenerDiscoverySources{
		netstatCandidates: func() (netstatListenerScan, error) { return netstatListenerScan{}, errors.New("netstat unavailable") },
		socketOwners: func() (map[string]int, socketInodeScanStats) {
			ownerCalls++
			return map[string]int{"123": os.Getpid()}, socketInodeScanStats{}
		},
		procListeners: func(map[string]int) []listenerInfo {
			return []listenerInfo{{PID: os.Getpid(), Process: "test", Address: "0.0.0.0", Port: 8443}}
		},
	})
	if err != nil {
		t.Fatalf("find listeners: %v", err)
	}
	if ownerCalls != 1 || len(listeners) != 1 || listeners[0].Port != 8443 {
		t.Fatalf("owner calls/listeners = %d/%#v", ownerCalls, listeners)
	}
}

func TestListenerDiscoveryFallsBackWhenRelevantNetstatPIDIsMissing(t *testing.T) {
	ownerCalls := 0
	listeners, err := findExternalListenersWithSources(8080, nil, listenerDiscoverySources{
		netstatCandidates: func() (netstatListenerScan, error) {
			return netstatListenerScan{TCPListenLines: 1, Candidates: []listenerInfo{{Address: "0.0.0.0", Port: 8080, Raw: "missing pid"}}}, nil
		},
		socketOwners: func() (map[string]int, socketInodeScanStats) {
			ownerCalls++
			return map[string]int{}, socketInodeScanStats{}
		},
		procListeners: func(map[string]int) []listenerInfo {
			return []listenerInfo{{PID: os.Getpid(), Process: "test", Address: "0.0.0.0", Port: 8080}}
		},
	})
	if err != nil {
		t.Fatalf("find listeners: %v", err)
	}
	if ownerCalls != 1 || len(listeners) != 1 {
		t.Fatalf("owner calls/listeners = %d/%#v, want one fallback result", ownerCalls, listeners)
	}
}

func TestParseNetstatListenerOutputVariants(t *testing.T) {
	input := `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name
tcp 0 0 0.0.0.0:443 0.0.0.0:* LISTEN 31843/nginx: master
tcp 0 0 127.0.0.1:5066 0.0.0.0:* LISTEN 9496/filebeat
tcp6 0 0 :::22 :::* LISTEN 1286/sshd: /usr/sbi
tcp 0 0 0.0.0.0:2049 0.0.0.0:* LISTEN -
tcp 0 0 0.0.0.0:9443 0.0.0.0:* LISTEN root 3205/docker-proxy
tcp 0 0 0.0.0.0:8080 0.0.0.0:* listen
tcp6 0 0 [::]:8443 [::]:* LISTEN 88/vendor-tls
tcp 0 0 *:3000 *:* LISTEN 77/busyboxd
udp 0 0 0.0.0.0:68 0.0.0.0:* 123/dhclient
`
	scan, err := parseNetstatListenerOutput([]byte(input))
	if err != nil {
		t.Fatalf("parse output: %v", err)
	}
	if scan.TCPListenLines != 8 || scan.RejectedListenLines != 0 || len(scan.Candidates) != 8 {
		t.Fatalf("scan = %#v, want 8 parsed TCP listeners", scan)
	}
	want := []listenerInfo{
		{Address: "0.0.0.0", Port: 443, PID: 31843, Process: "nginx"},
		{Address: "127.0.0.1", Port: 5066, PID: 9496, Process: "filebeat"},
		{Address: "::", Port: 22, PID: 1286, Process: "sshd"},
		{Address: "0.0.0.0", Port: 2049, PID: 0, Process: ""},
		{Address: "0.0.0.0", Port: 9443, PID: 3205, Process: "docker-proxy"},
		{Address: "0.0.0.0", Port: 8080, PID: 0, Process: ""},
		{Address: "::", Port: 8443, PID: 88, Process: "vendor-tls"},
		{Address: "*", Port: 3000, PID: 77, Process: "busyboxd"},
	}
	for i, candidate := range scan.Candidates {
		candidate.Raw = ""
		if !reflect.DeepEqual(candidate, want[i]) {
			t.Fatalf("candidate[%d] = %#v, want %#v", i, candidate, want[i])
		}
	}
}

func TestListenerDiscoveryFallsBackOnPartiallyRejectedOutput(t *testing.T) {
	ownerCalls := 0
	listeners, err := findExternalListenersWithSources(0, nil, listenerDiscoverySources{
		netstatCandidates: func() (netstatListenerScan, error) {
			return netstatListenerScan{
				TCPListenLines:      2,
				RejectedListenLines: 1,
				Candidates:          []listenerInfo{{PID: os.Getpid(), Process: "test", Address: "0.0.0.0", Port: 8080}},
			}, nil
		},
		socketOwners: func() (map[string]int, socketInodeScanStats) {
			ownerCalls++
			return map[string]int{}, socketInodeScanStats{}
		},
		procListeners: func(map[string]int) []listenerInfo {
			return []listenerInfo{{PID: os.Getpid() + 1, Process: "fallback", Address: "0.0.0.0", Port: 9090}}
		},
	})
	if err != nil {
		t.Fatalf("find listeners: %v", err)
	}
	if ownerCalls != 1 || len(listeners) != 2 {
		t.Fatalf("owner calls/listeners = %d/%#v, want fallback plus parsed listener", ownerCalls, listeners)
	}
}

func TestParseNetstatListenerOutputCountsMalformedTCPListenRows(t *testing.T) {
	input := "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 123/sshd\n" +
		"tcp malformed row LISTEN 456/vendor-daemon\n"
	scan, err := parseNetstatListenerOutput([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if scan.TCPListenLines != 2 || scan.RejectedListenLines != 1 || len(scan.Candidates) != 1 {
		t.Fatalf("scan = %#v, want one parsed and one rejected listener", scan)
	}
}

func TestScanSocketInodeMapHonorsFDBudget(t *testing.T) {
	procRoot := t.TempDir()
	fdDir := filepath.Join(procRoot, "100", "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := os.Symlink("socket:["+string(rune('1'+i))+"]", filepath.Join(fdDir, string(rune('0'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	owners, stats := scanSocketInodeMap(procRoot, 2)
	if !stats.BudgetExhausted || stats.FDsScanned != 2 {
		t.Fatalf("stats = %#v, want exhausted after 2 FDs", stats)
	}
	if len(owners) > 2 {
		t.Fatalf("owners = %#v, want at most 2 entries", owners)
	}
}
