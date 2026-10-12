package eventwhitelist

import (
	"net/url"
	"regexp"
	"strings"
)

// RE2 expressions compile once. Matching uses originals; only alert copies are
// redacted, including URL-encoded command arguments.
var secretArgument = regexp.MustCompile(`(?i)(sshpass\s+-p\s+)(?:"[^"]*"|'[^']*'|\S+)|((?:password|passwd|token|access[_-]?key[_-]?secret|authorization)\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s&;]+)`)

func redactText(s string) string {
	if len(s) > 32<<10 {
		return "[OMITTED: oversized field]"
	}
	redact := func(value string) string {
		return secretArgument.ReplaceAllStringFunc(value, func(match string) string {
			groups := secretArgument.FindStringSubmatch(match)
			prefix := groups[1]
			if prefix == "" {
				prefix = groups[2]
			}
			return prefix + "[REDACTED]"
		})
	}
	result := redact(s)
	decoded := s
	for i := 0; i < 2; i++ {
		next, err := url.QueryUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}
	if safe := redact(decoded); safe != decoded {
		return safe
	}
	return result
}

// RedactFields makes an owned bounded copy; unknown nested objects are omitted.
func RedactFields(fields map[string]any) map[string]any {
	out := make(map[string]any)
	// Charge worst-case JSON escaping before allocating owned alert copies.
	remaining := 24 << 10
	for key, value := range fields {
		if len(out) >= 64 || len(key) > 128 {
			continue
		}
		cost := len(key)*6 + 32
		switch v := value.(type) {
		case string:
			cost += len(v) * 6
		case []string:
			for _, s := range v {
				cost += len(s)*6 + 8
			}
		default:
			cost += 64
		}
		if cost > remaining {
			out[key] = "[OMITTED: alert budget]"
			continue
		}
		remaining -= cost
		lower := strings.ToLower(key)
		if strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "authorization") {
			out[key] = "[REDACTED]"
			continue
		}
		switch v := value.(type) {
		case string:
			out[key] = redactText(v)
		case []string:
			if len(v) > 256 {
				out[key] = "[OMITTED]"
				continue
			}
			copy := make([]string, len(v))
			for i, s := range v {
				copy[i] = redactText(s)
			}
			out[key] = copy
		case bool, int, int64, uint64, float64:
			out[key] = v
		default:
			out[key] = "[OMITTED]"
		}
	}
	return out
}
