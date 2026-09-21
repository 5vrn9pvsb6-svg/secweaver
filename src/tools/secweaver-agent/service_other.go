//go:build !windows

package main

import (
	"fmt"
	"os"
)

func runServiceCommand(args []string) int {
	_ = args
	fmt.Fprintln(os.Stderr, "service command is only supported on Windows")
	return 2
}
