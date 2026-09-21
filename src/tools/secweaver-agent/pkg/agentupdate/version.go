package agentupdate

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

var strictSemverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func normalizeSemver(value string) (string, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(value), "v")
	if !strictSemverPattern.MatchString(trimmed) {
		return "", fmt.Errorf("%q is not a valid SemVer 2.0.0 version", value)
	}
	normalized := "v" + trimmed
	if !semver.IsValid(normalized) {
		return "", fmt.Errorf("%q is not a valid SemVer 2.0.0 version", value)
	}
	return normalized, nil
}

func compareVersions(a, b string) (int, error) {
	left, err := normalizeSemver(a)
	if err != nil {
		return 0, err
	}
	right, err := normalizeSemver(b)
	if err != nil {
		return 0, err
	}
	return semver.Compare(left, right), nil
}
