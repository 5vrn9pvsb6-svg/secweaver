//go:build !windows

package agentupdate

import (
	"context"
	"fmt"
)

func verifyWindowsAuthenticode(_ context.Context, _ string, _ []string) error {
	return fmt.Errorf("Windows Authenticode verification is unavailable on this platform")
}
