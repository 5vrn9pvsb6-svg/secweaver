package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"secweaver-agent/pkg/eventwhitelist"
	"secweaver-agent/pkg/eventwhitelist/core"
	"time"
)

// runWhitelistCommand inspects administrative input without starting collectors
// or alert writers. Emergency disable is a local sentinel cloud renewals cannot
// remove; enable only removes that sentinel, not a tenant's policy switch.
func runWhitelistCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "whitelist validate|test|status|disable|enable -config <config.json> -policy <policy.json> -event <event.json>")
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("whitelist "+action, flag.ContinueOnError)
	config := fs.String("config", defaultAgentConfigPath(), "Agent configuration")
	policy := fs.String("policy", "", "unsigned policy for validation/sample only")
	event := fs.String("event", "", "normalized semantic sample")
	if fs.Parse(args[1:]) != nil {
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(os.Stderr, "whitelist:", err); return 1 }
	if action == "validate" || action == "test" {
		raw, err := eventwhitelist.ReadBounded(*policy, core.MaxPolicyBytes)
		if err != nil {
			return fail(err)
		}
		p, err := core.Decode(raw)
		if err != nil {
			return fail(err)
		}
		engine, err := core.Compile(p)
		if err != nil {
			return fail(err)
		}
		if action == "validate" {
			fmt.Println("policy valid")
			return 0
		}
		f, err := os.Open(*event)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		e, err := core.DecodeEvent(f)
		if err != nil {
			return fail(err)
		}
		if e.Backfill {
			return jsonWhitelist(core.Decision{Action: "pass", Reason: "history_preserved", Revision: p.Revision})
		}
		return jsonWhitelist(engine.Decide(e, time.Now()))
	}
	cfg, err := loadConfig(*config)
	if err != nil {
		return fail(err)
	}
	path := cfg.CollectionRules.PolicyFile
	if path == "" {
		path = filepath.Join(filepath.Dir(cfg.License.Normalize().StatePath), "collection-rules", "current.json")
	}
	if !filepath.IsAbs(path) {
		return fail(fmt.Errorf("policy path must be absolute"))
	}
	switch action {
	case "disable":
		returnCode := eventwhitelist.AtomicFile(path+".disabled", []byte("local emergency disable\n"))
		if returnCode != nil {
			return fail(returnCode)
		}
		fmt.Println("local collection rules disabled; learning configuration preserved")
		return 0
	case "enable":
		if err = os.Remove(path + ".disabled"); err != nil && !os.IsNotExist(err) {
			return fail(err)
		}
		fmt.Println("local disable removed; published policy still controls activation")
		return 0
	case "status":
		raw, err := eventwhitelist.ReadBounded(path, core.MaxPolicyBytes+8192)
		if os.IsNotExist(err) {
			return jsonWhitelist(map[string]string{"state": "unmanaged"})
		}
		if err != nil {
			return fail(err)
		}
		var env core.Envelope
		if err = json.Unmarshal(raw, &env); err != nil {
			return fail(err)
		}
		state := "downloaded"
		if _, err = os.Stat(path + ".disabled"); err == nil {
			state = "local_disabled"
		}
		// Expose metadata only; a downloaded envelope does not prove child application.
		return jsonWhitelist(map[string]any{"state": state, "revision": env.Revision, "digest": env.Digest, "expires_at": env.ExpiresAt})
	default:
		return fail(fmt.Errorf("unknown whitelist command %q", action))
	}
}

func jsonWhitelist(value any) int {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		return 1
	}
	return 0
}
