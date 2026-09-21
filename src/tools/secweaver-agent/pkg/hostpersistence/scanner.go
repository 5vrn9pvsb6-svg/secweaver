package hostpersistence

import (
	"crypto/sha256"
	"encoding/hex"

	"fmt"
	"io"
	"os"

	"path/filepath"

	"sort"
	"strings"

	"time"
)

// This file owns bounded filesystem traversal and metadata/content reuse; unchanged mtime and size avoid repeated hashing and reads.

func scanTargets(cfg runtimeConfig) (map[string]fileState, int) {
	return scanTargetsWithPrevious(cfg, nil)
}

func scanTargetsWithPrevious(cfg runtimeConfig, previous map[string]fileState) (map[string]fileState, int) {
	out := map[string]fileState{}
	errors := 0
	for _, target := range cfg.Watch {
		paths, err := expandTargetPaths(target.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: expand watch path %s failed: %v\n", target.Path, err)
			errors++
			continue
		}
		for _, path := range paths {
			items, err := scanPath(path, target, cfg, previous)
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARN: scan %s failed: %v\n", path, err)
				errors++
				continue
			}
			for _, item := range items {
				if _, exists := out[item.Path]; exists {
					continue
				}
				out[item.Path] = item
			}
		}
	}
	return out, errors
}

func expandTargetPaths(pattern string) ([]string, error) {
	if strings.ContainsAny(pattern, "*?[") {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		sort.Strings(matches)
		return matches, nil
	}
	return []string{pattern}, nil
}

func scanPath(path string, target watchTarget, cfg runtimeConfig, previous map[string]fileState) ([]fileState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return nil, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		item, err := stateForPath(path, info, target, cfg, previous)
		if err != nil {
			return nil, err
		}
		return []fileState{item}, nil
	}

	var items []fileState
	rootDepth := pathDepth(path)
	walkErr := filepath.WalkDir(path, func(current string, entry os.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		if current == path {
			return nil
		}
		depth := pathDepth(current) - rootDepth
		if target.MaxDepth > 0 && depth > target.MaxDepth {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if target.Recursive {
				return nil
			}
			return filepath.SkipDir
		}
		info, err := entry.Info()
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		item, err := stateForPath(current, info, target, cfg, previous)
		if err != nil {
			return err
		}
		items = append(items, item)
		if !target.Recursive {
			return nil
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items, nil
}

func pathDepth(path string) int {
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) {
		return 0
	}
	parts := strings.Split(strings.Trim(clean, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) == 1 && parts[0] == "" {
		return 0
	}
	return len(parts)
}

func stateForPath(path string, info os.FileInfo, target watchTarget, cfg runtimeConfig, previous map[string]fileState) (fileState, error) {
	item := fileState{
		Path:            filepath.Clean(path),
		Category:        target.Category,
		PersistenceType: target.PersistenceType,
		FileType:        fileType(info),
		Mode:            info.Mode().String(),
		Size:            info.Size(),
		ModTime:         info.ModTime().UTC().Format(time.RFC3339Nano),
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err == nil {
			item.SymlinkTarget = target
		}
		return item, nil
	}
	if reused, ok := reusePreviousContentState(item, previous, cfg); ok {
		return reused, nil
	}
	if cfg.IncludeHash && info.Mode().IsRegular() && info.Size() <= cfg.MaxHashBytes {
		hash, err := sha256File(path)
		if err != nil {
			if os.IsPermission(err) {
				return item, nil
			}
			return item, err
		}
		item.Hash = hash
	}
	if cfg.IncludeContentDiff && info.Mode().IsRegular() && info.Size() <= cfg.MaxContentBytes {
		content, truncated, ok, err := readTextContent(path, cfg.MaxContentBytes)
		if err != nil {
			if os.IsPermission(err) {
				return item, nil
			}
			return item, err
		}
		if ok {
			item.ContentCaptured = true
			item.Content = content
			item.ContentTruncated = truncated
		}
	}
	return item, nil
}

func reusePreviousContentState(item fileState, previous map[string]fileState, cfg runtimeConfig) (fileState, bool) {
	if len(previous) == 0 {
		return item, false
	}
	prev, ok := previous[item.Path]
	if !ok ||
		prev.Mode != item.Mode ||
		prev.Size != item.Size ||
		prev.ModTime != item.ModTime ||
		prev.SymlinkTarget != item.SymlinkTarget ||
		prev.Category != item.Category ||
		prev.PersistenceType != item.PersistenceType ||
		prev.FileType != item.FileType {
		return item, false
	}
	needsHash := cfg.IncludeHash && item.FileType == "file" && item.Size <= cfg.MaxHashBytes
	needsContent := cfg.IncludeContentDiff && item.FileType == "file" && item.Size <= cfg.MaxContentBytes
	if needsHash && prev.Hash == "" {
		return item, false
	}
	if needsContent && !prev.ContentCaptured {
		return item, false
	}
	if needsHash {
		item.Hash = prev.Hash
	}
	if needsContent {
		item.ContentCaptured = prev.ContentCaptured
		item.Content = prev.Content
		item.ContentTruncated = prev.ContentTruncated
	}
	return item, true
}

func fileType(info os.FileInfo) string {
	mode := info.Mode()
	switch {
	case mode&os.ModeSymlink != 0:
		return "symlink"
	case mode.IsRegular():
		return "file"
	case mode.IsDir():
		return "dir"
	default:
		return "other"
	}
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
