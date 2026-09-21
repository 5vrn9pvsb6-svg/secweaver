package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"secweaver-agent/pkg/agentlicense"
)

// runEnrollCommand defaults to the legacy enterprise-only output. Installers
// opt into a bounded two-field record after enrollment has durably succeeded;
// no private key, enrollment token, or raw server response is printed.
func runEnrollCommand(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverURL := ""
	token := ""
	statePath := agentlicense.DefaultStatePath()
	identityKeyPath := ""
	caFile := ""
	output := "enterprise-id"
	timeout := 30 * time.Second
	fs.StringVar(&serverURL, "server-url", "", "SecWeaver managed control-plane origin")
	fs.StringVar(&token, "enterprise-enrollment-token", "", "reusable enterprise installation credential")
	fs.StringVar(&statePath, "state-path", statePath, "device identity state path")
	fs.StringVar(&identityKeyPath, "identity-key-path", "", "Ed25519 device private key path")
	fs.StringVar(&caFile, "ca-file", "", "optional PEM CA file for the control-plane HTTPS endpoint")
	fs.StringVar(&output, "output", output, "output: enterprise-id or installer (enterprise ID and device ID separated by a tab)")
	fs.DurationVar(&timeout, "timeout", timeout, "enrollment request timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if output != "enterprise-id" && output != "installer" {
		fmt.Fprintln(os.Stderr, "invalid enrollment output format")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := (agentlicense.Client{}).Enroll(ctx, agentlicense.Config{
		Enabled:         true,
		Protocol:        "device_v2",
		ServerURL:       serverURL,
		StatePath:       statePath,
		IdentityKeyPath: identityKeyPath,
		CAFile:          caFile,
	}, token, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "device enrollment failed: %v\n", err)
		return 1
	}
	if output == "installer" {
		fmt.Fprintf(os.Stdout, "%s\t%s\n", result.State.EnterpriseID, result.State.DeviceID)
	} else {
		fmt.Fprintln(os.Stdout, result.State.EnterpriseID)
	}
	return 0
}
