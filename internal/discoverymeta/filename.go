// Package discoverymeta interprets the build-selection information that can be
// recovered from assembly file names without downloading a module again.
package discoverymeta

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

var knownGOOS = []string{
	"aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "js",
	"linux", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows",
}

var knownGOARCH = []string{
	"386", "amd64", "arm", "arm64", "loong64", "mips", "mips64", "mips64le",
	"mipsle", "ppc64", "ppc64le", "riscv64", "s390x", "wasm",
}

// InferArchitecture returns the GOARCH suffix encoded by a Go assembly file
// name. Unknown includes portable names and custom suffixes such as amd64x.
func InferArchitecture(name string) string {
	stem := strings.TrimSuffix(path.Base(name), path.Ext(name))
	if architecture, ok := filenameSuffix(stem, knownGOARCH); ok {
		return architecture
	}
	return "unknown"
}

// ArchitectureHints returns deterministic module-level hints derived from all
// recorded assembly paths. The hints include Go ports plan9asm does not yet
// support so a future platform can be selected from the existing ledger.
func ArchitectureHints(files []string) []string {
	set := make(map[string]bool)
	for _, name := range files {
		set[InferArchitecture(name)] = true
	}
	return sortedSet(set)
}

// FilterAssemblyFiles returns paths that may be selected by at least one
// target according to Go's filename suffix convention. It only rejects a file
// when the suffix conclusively names another GOOS or GOARCH. Unknown/custom
// names remain eligible so source build constraints can be checked after the
// recorded exact module version is fetched.
func FilterAssemblyFiles(files, targets []string) ([]string, error) {
	type targetPair struct{ goos, goarch string }
	pairs := make([]targetPair, 0, len(targets))
	allOS := append([]string(nil), knownGOOS...)
	allArch := append([]string(nil), knownGOARCH...)
	for _, target := range targets {
		parts := strings.Split(target, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid discovery target %q", target)
		}
		pairs = append(pairs, targetPair{goos: parts[0], goarch: parts[1]})
		allOS = append(allOS, parts[0])
		allArch = append(allArch, parts[1])
	}
	allOS = uniqueSorted(allOS)
	allArch = uniqueSorted(allArch)

	set := make(map[string]bool)
	for _, name := range files {
		for _, target := range pairs {
			if filenameMayMatch(name, target.goos, target.goarch, allOS, allArch) {
				set[name] = true
				break
			}
		}
	}
	return sortedSet(set), nil
}

func filenameMayMatch(name, goos, goarch string, allOS, allArch []string) bool {
	stem := strings.TrimSuffix(path.Base(name), path.Ext(name))
	if suffix, ok := filenameSuffix(stem, allArch); ok {
		if suffix != goarch {
			return false
		}
		stem = strings.TrimSuffix(stem, "_"+suffix)
	}
	if suffix, ok := filenameSuffix(stem, allOS); ok && suffix != goos {
		return false
	}
	return true
}

func filenameSuffix(stem string, values []string) (string, bool) {
	for _, value := range values {
		if strings.HasSuffix(stem, "_"+value) {
			return value, true
		}
	}
	return "", false
}

func uniqueSorted(values []string) []string {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return sortedSet(set)
}

func sortedSet(set map[string]bool) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}
