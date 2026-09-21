// Package modulecontrol combines operating-system signals with the supervisor's
// process control channel. The channel is enabled only for supervised children,
// so standalone collector commands retain their normal stdin behavior.
package modulecontrol

import (
	"bufio"
	"context"
	"os"
	"os/signal"
	"strings"
)

const (
	Environment = "SECWEAVER_MODULE_CONTROL"
	StdinV1     = "stdin-v1"
	StopCommand = "shutdown"
)

// NotifyContext mirrors signal.NotifyContext and additionally cancels when a
// supervised child receives the exact shutdown command or loses its parent-held
// control pipe. EOF is a stop request because the pipe has no other writer.
func NotifyContext(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
	signalCtx, stopSignals := signal.NotifyContext(parent, signals...)
	ctx, cancel := context.WithCancel(signalCtx)
	if strings.EqualFold(strings.TrimSpace(os.Getenv(Environment)), StdinV1) {
		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				if strings.TrimSpace(scanner.Text()) == StopCommand {
					cancel()
					return
				}
			}
			// A closed control pipe means the supervisor exited or deliberately
			// released ownership; either case requires a graceful child stop.
			cancel()
		}()
	}
	return ctx, func() {
		cancel()
		stopSignals()
	}
}
