// Package goversion interprets the Go assembler's source SDK version.
package goversion

import (
	"regexp"
	"strconv"
	"strings"
)

var release = regexp.MustCompile(`^go1\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)|(beta|rc)(0|[1-9][0-9]*))?(-[^[:space:]]+)?( X:[a-zA-Z0-9_]+(,[a-zA-Z0-9_]+)*)?$`)

// ParseMinor recognizes releases and versioned development toolchains. A devel
// identifier can include the commit date and build metadata after the version.
func ParseMinor(version string) (int, bool) {
	if strings.HasPrefix(version, "devel ") {
		version, _, _ = strings.Cut(strings.TrimPrefix(version, "devel "), " ")
	}
	parts := release.FindStringSubmatch(version)
	if parts == nil {
		return 0, false
	}
	minor, err := strconv.Atoi(parts[1])
	return minor, err == nil
}
