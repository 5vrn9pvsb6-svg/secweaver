package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"secweaver-agent/pkg/windowscollection"
)

// runLogtailCheckCommand is shared by the installer and diagnostics. Manifest
// validation precedes host mutation; cache validation only proves local rule
// delivery, never a successful SLS PutLogs or cloud query.
func runLogtailCheckCommand(args []string) int {
	fs := flag.NewFlagSet("logtail-check", flag.ContinueOnError)
	manifest := fs.String("manifest", "", "signed Windows collection envelope")
	key := fs.String("public-key", "", "trusted base64 Ed25519 key")
	cache := fs.String("cache", "", "vendor user_log_config.json; omitted validates manifest only")
	logPath := fs.String("log-path", "", "expected Agent log directory")
	uid := fs.String("aliuid", "", "expected SLS account")
	group := fs.String("machine-group", "", "expected Windows group identifier")
	region := fs.String("region", "", "expected region without network selector")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	body, err := windowscollection.ReadBounded(*manifest, 65536)
	var m windowscollection.Manifest
	if err == nil {
		m, err = windowscollection.Verify(body, *key)
	}
	if err == nil && ((*logPath != "" && windowscollection.NormalizePath(m.LogPath) != windowscollection.NormalizePath(*logPath)) || (*uid != "" && m.AliUID != *uid) || (*group != "" && m.MachineGroup != *group) || (*region != "" && m.Region != *region)) {
		err = fmt.Errorf("collection manifest does not match installation identity/path/region")
	}
	var missing []string
	if err == nil && *cache != "" {
		body, err = windowscollection.ReadBounded(*cache, 4<<20)
		if err == nil {
			missing, err = windowscollection.CheckCache(body, m)
		}
		if err == nil && len(missing) > 0 {
			err = fmt.Errorf("collection rules missing, conflicting or wrong destination")
		}
	}
	result := map[string]any{"ok": err == nil, "cloud_delivery": "unverified", "missing_files": missing}
	if err != nil {
		result["error"] = err.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
	if err != nil {
		return 1
	}
	return 0
}
