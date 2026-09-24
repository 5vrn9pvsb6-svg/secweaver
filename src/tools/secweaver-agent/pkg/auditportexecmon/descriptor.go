package auditportexecmon

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/pkg/behaviorlearning"
)

// Descriptor is the sole supervisor-facing contract for audit-port-execmon.
// Private JSON and flag precedence stays here so the parent cannot drift from
// the command-line behavior implemented by Main.
func Descriptor() modulecontract.Descriptor {
	return modulecontract.Descriptor{
		Name:        "audit-port-execmon",
		Description: "auditd-based external listener exec/connect/file evidence collector",
		Platforms:   []string{"linux"},
		Flags: modulecontract.Flags(
			[]string{"config", "port", "audit-log", "output-log", "key"},
			[]string{"version", "learning-status", "include-ppid", "keep-rule", "from-start", "raw", "dry-run"},
		),
		OutputPaths:       descriptorOutputPaths,
		AuditSubscription: descriptorAuditSubscription,
		Run:               Main,
	}
}

func descriptorOutputPaths(args []string) []string {
	path := defaultOutputLog
	var learning behaviorlearning.Config
	if configPath, ok := modulecontract.StringFlag(args, "config"); ok {
		var cfg struct {
			OutputLog        string          `json:"output_log"`
			BehaviorLearning json.RawMessage `json:"behavior_learning"`
		}
		if body, err := os.ReadFile(strings.TrimSpace(configPath)); err == nil && json.Unmarshal(body, &cfg) == nil {
			if strings.TrimSpace(cfg.OutputLog) != "" {
				path = strings.TrimSpace(cfg.OutputLog)
			}
			learning, _ = behaviorlearning.Decode(cfg.BehaviorLearning)
		}
	}
	if value, ok := modulecontract.StringFlag(args, "output-log"); ok {
		path = value
	}
	// Include summaries in supervisor rotation, disk budgets and diagnostics.
	if learning.Enabled {
		return []string{path, learningPaths(learning, path).OutputLog}
	}
	return []string{path}
}

// descriptorAuditSubscription returns only transport-level settings. Rule
// ownership remains in this module; the parent uses the result solely to share
// one audit.log reader when another module requests the same stream.
func descriptorAuditSubscription(args []string) (modulecontract.AuditSubscription, bool, error) {
	if dryRun, ok, err := modulecontract.BoolFlag(args, "dry-run"); err != nil {
		return modulecontract.AuditSubscription{}, false, err
	} else if ok && dryRun {
		return modulecontract.AuditSubscription{}, false, nil
	}
	path := "/var/log/audit/audit.log"
	if value, ok := modulecontract.StringFlag(args, "audit-log"); ok && strings.TrimSpace(value) != "" {
		path = strings.TrimSpace(value)
	}
	fromStart, _, err := modulecontract.BoolFlag(args, "from-start")
	if err != nil {
		return modulecontract.AuditSubscription{}, false, err
	}
	baseKey := "tb_external_listener"
	if value, ok := modulecontract.StringFlag(args, "key"); ok && strings.TrimSpace(value) != "" {
		baseKey = strings.TrimSpace(value)
	} else if value, ok := modulecontract.StringFlag(args, "port"); ok && strings.TrimSpace(value) != "" {
		if port, parseErr := strconv.Atoi(strings.TrimSpace(value)); parseErr == nil && port > 0 {
			baseKey = fmt.Sprintf("tb_port_%d", port)
		}
	}
	return modulecontract.AuditSubscription{Path: path, FromStart: fromStart, Keys: []string{
		baseKey + "_exec",
		baseKey + "_connect",
		baseKey + "_file",
		baseKey + "_sensitive",
		baseKey + "_clone",
	}}, true, nil
}
