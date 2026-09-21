package hostpersistence

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

func readTextContent(path string, maxBytes int64) (string, bool, bool, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxContentBytes
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false, false, err
	}
	defer f.Close()

	var buf bytes.Buffer
	limited := io.LimitReader(f, maxBytes+1)
	if _, err := io.Copy(&buf, limited); err != nil {
		return "", false, false, err
	}
	data := buf.Bytes()
	truncated := int64(len(data)) > maxBytes
	if truncated {
		data = data[:maxBytes]
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return "", truncated, false, nil
	}
	return string(data), truncated, true, nil
}

func buildContentDiff(action string, cur, prev fileState, maxLines int) (string, bool) {
	if maxLines <= 0 {
		maxLines = defaultMaxDiffLines
	}
	oldCaptured := prev.ContentCaptured
	newCaptured := cur.ContentCaptured
	oldText := prev.Content
	newText := cur.Content
	switch action {
	case "created", "observed":
		oldCaptured = true
		oldText = ""
	case "deleted":
		newCaptured = true
		newText = ""
	}
	if !oldCaptured && !newCaptured {
		if prev.Hash != "" && cur.Hash != "" && prev.Hash != cur.Hash {
			return fmt.Sprintf("content changed; diff unavailable because content was not captured; previous_hash=%s hash=%s", prev.Hash, cur.Hash), false
		}
		return "", false
	}
	if oldText == newText {
		return "", false
	}
	diff, truncated := unifiedLineDiff(oldText, newText, maxLines)
	if prev.ContentTruncated || cur.ContentTruncated {
		truncated = true
	}
	return diff, truncated
}

func unifiedLineDiff(oldText, newText string, maxLines int) (string, bool) {
	oldLines := splitLines(oldText)
	newLines := splitLines(newText)
	if len(oldLines)*len(newLines) > 200000 {
		return fmt.Sprintf("content changed; full diff omitted because line count is too large (old_lines=%d new_lines=%d)", len(oldLines), len(newLines)), true
	}
	lcs := make([][]int, len(oldLines)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(newLines)+1)
	}
	for i := len(oldLines) - 1; i >= 0; i-- {
		for j := len(newLines) - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	out := make([]string, 0)
	truncated := false
	appendLine := func(prefix, line string) bool {
		if len(out) >= maxLines {
			truncated = true
			return false
		}
		out = append(out, prefix+line)
		return true
	}

	i, j := 0, 0
	for i < len(oldLines) && j < len(newLines) {
		if oldLines[i] == newLines[j] {
			if !appendLine(" ", oldLines[i]) {
				break
			}
			i++
			j++
		} else if lcs[i+1][j] >= lcs[i][j+1] {
			if !appendLine("-", oldLines[i]) {
				break
			}
			i++
		} else {
			if !appendLine("+", newLines[j]) {
				break
			}
			j++
		}
	}
	for i < len(oldLines) && !truncated {
		if !appendLine("-", oldLines[i]) {
			break
		}
		i++
	}
	for j < len(newLines) && !truncated {
		if !appendLine("+", newLines[j]) {
			break
		}
		j++
	}
	if truncated {
		out = append(out, "... diff truncated ...")
	}
	return strings.Join(out, "\n"), truncated
}

func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return []string{""}
	}
	return strings.Split(text, "\n")
}
