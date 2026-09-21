package main

import "secweaver-agent/internal/modulecontract"

// stringFlag is retained for generic config generation and preflight checks.
// Module-private interpretation belongs in each module's descriptor.
func stringFlag(args []string, name string) (string, bool) {
	return modulecontract.StringFlag(args, name)
}
