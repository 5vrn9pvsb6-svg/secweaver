package auditportexecmon

import (
	"encoding/hex"
	"strconv"
	"strings"

	"time"
)

// This file contains allocation-conscious parsing helpers for audit record fields, message IDs, paths, and argv.

func pruneOld(accs map[string]*auditAccumulator, maxAge time.Duration) {
	// Malformed or incomplete kernel events must not keep accumulator state
	// forever. Normal records are emitted before this retention bound.
	now := time.Now()
	for id, acc := range accs {
		if now.Sub(acc.firstSeen) > maxAge {
			delete(accs, id)
			// P1 Optimization: Return accumulator to pool
			putAccumulator(acc)
		}
	}
}

func extractMsgID(line string) string {
	m := msgIDPattern.FindStringSubmatch(line)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

func parseFields(line string) map[string]string {
	// P0 Optimization: Use fast state-machine parser instead of regex
	// This provides 3-5x performance improvement over regex-based parsing
	return parseFieldsFast(line)
}

// parseFieldsFast implements a state-machine based parser that avoids regex overhead.
// It handles audit field format: key=value or key="quoted value"
// EXECVE arguments (a0=, a1=, etc.) are detected and handled inline.
func parseFieldsFast(line string) map[string]string {
	fields := make(map[string]string, 32) // Pre-allocate for typical field count

	i := 0
	length := len(line)

	for i < length {
		// Skip whitespace
		for i < length && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= length {
			break
		}

		// Read key
		keyStart := i
		for i < length && line[i] != '=' && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		if i >= length || line[i] != '=' {
			// No '=' found, skip to next space
			for i < length && line[i] != ' ' && line[i] != '\t' {
				i++
			}
			continue
		}

		key := line[keyStart:i]
		i++ // Skip '='

		if i >= length {
			break
		}

		// Read value
		var value string
		quoted := line[i] == '"'
		if quoted {
			// Quoted value
			i++ // Skip opening quote
			valueStart := i
			escaped := false

			for i < length {
				if escaped {
					escaped = false
					i++
					continue
				}
				if line[i] == '\\' {
					escaped = true
					i++
					continue
				}
				if line[i] == '"' {
					value = line[valueStart:i]
					i++ // Skip closing quote
					break
				}
				i++
			}

			// Unescape the value if needed
			if strings.Contains(value, "\\") {
				if unquoted, err := strconv.Unquote("\"" + value + "\""); err == nil {
					value = unquoted
				}
			}
		} else {
			// Unquoted value - read until space
			valueStart := i
			for i < length && line[i] != ' ' && line[i] != '\t' {
				i++
			}
			value = line[valueStart:i]
		}
		// Linux audit hex-encodes unquoted EXECVE strings containing whitespace
		// or non-ASCII bytes. Quoted hex-looking arguments are literal strings;
		// SYSCALL a0/a1 values are pointers and must never be decoded as argv.
		if !quoted && fields["type"] == "EXECVE" && len(key) > 1 && key[0] == 'a' {
			if _, err := strconv.Atoi(key[1:]); err == nil {
				if decoded, err := hexStringToBytes(value); err == nil {
					value = string(decoded)
				}
			}
		}

		// Store the field
		// Normalize quoted PROCTITLE to the existing hex decoder, and decode
		// encoded PATH names before exact file matching. Never decode SYSCALL
		// pointers or quoted hex-looking filenames as byte strings.
		if quoted && fields["type"] == "PROCTITLE" && key == "proctitle" {
			value = hex.EncodeToString([]byte(value))
		}
		if !quoted && fields["type"] == "PATH" && key == "name" {
			if decoded, err := hexStringToBytes(value); err == nil {
				value = string(decoded)
			}
		}
		// For EXECVE args like a0, a1, etc., preserve the key format
		fields[key] = value
	}

	return fields
}

// parseFieldsRegex is the original regex-based parser, kept for fallback/comparison
func parseFieldsRegex(line string) map[string]string {
	// EXECVE arguments use a0/a1/... tokens that overlap generic field parsing.
	// The second pass intentionally overwrites them with the argument-aware regex.
	fields := map[string]string{}
	for _, m := range fieldPattern.FindAllStringSubmatch(line, -1) {
		if len(m) != 3 {
			continue
		}
		value := unquoteAuditValue(m[2])
		// Keep the reference parser's file/title contract aligned with the
		// production parser so compatibility checks compare decoded evidence.
		quoted := strings.HasPrefix(m[2], "\"")
		if quoted && fields["type"] == "PROCTITLE" && m[1] == "proctitle" {
			value = hex.EncodeToString([]byte(value))
		}
		if !quoted && fields["type"] == "PATH" && m[1] == "name" {
			if decoded, err := hexStringToBytes(value); err == nil {
				value = string(decoded)
			}
		}
		fields[m[1]] = value
	}
	for _, m := range execArgPattern.FindAllStringSubmatch(line, -1) {
		if len(m) != 3 {
			continue
		}
		fields["a"+m[1]] = unquoteAuditValue(m[2])
	}
	return fields
}

func unquoteAuditValue(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		if s, err := strconv.Unquote(v); err == nil {
			return s
		}
		return strings.Trim(v, "\"")
	}
	return v
}

func orderedArgs(argv map[int]string) []string {
	if len(argv) == 0 {
		return nil
	}
	max := 0
	for i := range argv {
		if i > max {
			max = i
		}
	}
	args := make([]string, 0, len(argv))
	for i := 0; i <= max; i++ {
		if v, ok := argv[i]; ok {
			args = append(args, v)
		}
	}
	return args
}
