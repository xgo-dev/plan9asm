package gotoolprofile

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Runner keeps bounded stdout/stderr and child-process lifetime ownership at
// the application boundary. Capture does not execute package initialization.
type Runner func(context.Context, string, []string, string, ...string) ([]byte, []byte, error)

var discoverySHA256Pattern = regexp.MustCompile("^[0-9a-f]{64}$")

func replaceEnv(base []string, replacements map[string]string) []string {
	var result []string
	for _, item := range base {
		key, _, _ := strings.Cut(item, "=")
		if _, replace := replacements[key]; !replace {
			result = append(result, item)
		}
	}
	var keys []string
	for key := range replacements {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result = append(result, key+"="+replacements[key])
	}
	return result
}

func uniqueSortedDiscoveryStrings(values []string) []string {
	set := make(map[string]bool)
	for _, value := range values {
		set[value] = true
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func equalDiscoveryStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func validateTarget(target string) error {
	parts := strings.Split(target, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid target %q", target)
	}
	switch parts[1] {
	case "386", "amd64", "arm", "arm64", "wasm":
		return nil
	default:
		return fmt.Errorf("target %q uses unsupported Plan 9 architecture", target)
	}
}

func discoveryModeledCPUFeatures(tags []string, arch, value string, minor int) []string {
	var modeled []string
	for _, tag := range tags {
		if !strings.HasPrefix(tag, arch+".") {
			modeled = append(modeled, tag)
		}
	}
	level := strings.Split(value, ",")[0]
	for _, candidate := range discoveryCPUFeatureCandidates() {
		if !strings.HasPrefix(candidate, arch+".") {
			continue
		}
		selected := candidate == arch+"."+level
		switch arch {
		case "amd64", "arm":
			selected = candidate <= arch+"."+level
		case "arm64":
			selected = value != "" && (candidate <= "arm64."+level && strings.HasPrefix(candidate, "arm64."+level[:2]))
			if strings.HasPrefix(level, "v9.") && strings.HasPrefix(candidate, "arm64.v8.") {
				selected = int(candidate[len(candidate)-1]-'0') <= int(level[len(level)-1]-'0')+5
			}
		case "wasm":
			// Go 1.26's gogoarchTags registers both unconditionally, even
			// when go env GOWASM is empty. The source/actual-marker proof
			// remains independent of this versioned expectation.
			selected = minor >= 26 || containsTargetFeature(strings.Split(value, ","), strings.TrimPrefix(candidate, "wasm."))
		}
		if selected {
			modeled = append(modeled, candidate)
		}
	}
	return uniqueSortedDiscoveryStrings(modeled)
}
