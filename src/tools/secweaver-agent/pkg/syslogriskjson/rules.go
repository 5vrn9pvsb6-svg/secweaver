package syslogriskjson

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

type rulesDocument struct {
	SchemaVersion string            `json:"schema_version"`
	RulesVersion  string            `json:"rules_version"`
	Rules         []json.RawMessage `json:"rules"`
}

type versionInfo struct {
	App           string `json:"app"`
	Version       string `json:"version"`
	ParserVersion string `json:"parser_version"`
	RulesVersion  string `json:"rules_version"`
	Platform      string `json:"platform"`
}

func loadRulesVersion(path string) (string, error) {
	if path == "" {
		return "builtin", nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	var doc rulesDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("解析规则 JSON 失败: %w", err)
	}
	if doc.SchemaVersion == "" {
		return "", fmt.Errorf("规则文件缺少 schema_version")
	}
	if doc.RulesVersion == "" {
		return "", fmt.Errorf("规则文件缺少 rules_version")
	}
	if doc.Rules == nil {
		return "", fmt.Errorf("规则文件缺少 rules 数组")
	}
	return doc.RulesVersion, nil
}

func printVersion(w io.Writer, rulesVersion string) {
	info := versionInfo{
		App:           "syslog-risk-json",
		Version:       version,
		ParserVersion: parserVersion,
		RulesVersion:  rulesVersion,
		Platform:      runtime.GOOS + "_" + runtime.GOARCH,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(info)
}
