// learning-recovery is offline maintenance tooling, never a remotely callable
// Agent action. It stages a new verified directory without replacing the source.
package main

import (
	"flag"
	"fmt"
	"os"

	"secweaver-agent/pkg/behaviorlearning"
)

func main() {
	source := flag.String("source", "", "stopped collector's absolute learning-state directory")
	destination := flag.String("destination", "", "new absolute recovery directory (must not exist)")
	budget := flag.Int("state-mb", 64, "original configured per-stream state budget in MiB")
	flag.Parse()
	if err := behaviorlearning.RestoreRelearningBackup(*source, *destination, *budget); err != nil {
		fmt.Fprintln(os.Stderr, "recovery staging failed:", err)
		os.Exit(1)
	}
	fmt.Println("Verified pre-window state staged; original directory retained. No live directory was switched.")
}
