package auditportexecmon

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	agentoutput "secweaver-agent/pkg/output"
)

func openOutputLog(path string) (io.Writer, func(), error) {
	if path != "-" {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, nil, fmt.Errorf("创建日志目录 %s：%w", dir, err)
		}
	}
	return agentoutput.OpenEventAppend(agentoutput.AppendOptions{
		Path:          path,
		Fallback:      os.Stdout,
		Perm:          agentoutput.DefaultFilePerm,
		FlushInterval: agentoutput.DefaultFlushInterval,
	})
}
