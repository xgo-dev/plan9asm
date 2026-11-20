package gotoolprofile

import (
	"fmt"
	"strings"
)

// FeatureCommandEnvironment constructs a fresh target's actual command
// environment. It does not normalize a returned observation or an already
// authenticated consumer environment. Capture and cache inspection must use
// this same construction before querying the real Go driver.
func FeatureCommandEnvironment(base []string, target string, overrides map[string]string) ([]string, error) {
	parts := strings.Split(target, "/")
	if len(parts) != 2 || parts[0] == "" {
		return nil, fmt.Errorf("invalid feature target %q", target)
	}
	cpuKeys := map[string]string{
		"386": "GO386", "amd64": "GOAMD64", "arm": "GOARM", "arm64": "GOARM64", "wasm": "GOWASM",
	}
	cpuKey, supported := cpuKeys[parts[1]]
	if !supported {
		return nil, fmt.Errorf("unsupported feature target %q", target)
	}
	replacements := map[string]string{
		"GOOS": parts[0], "GOARCH": parts[1], "CGO_ENABLED": "0",
		"GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "",
	}
	for _, key := range []string{"GO386", "GOAMD64", "GOARM", "GOARM64", "GOWASM"} {
		if key != cpuKey {
			replacements[key] = ""
		}
	}
	for key, value := range overrides {
		if key != cpuKey && key != "GOEXPERIMENT" {
			return nil, fmt.Errorf("feature profile cannot override %s for %s", key, target)
		}
		replacements[key] = value
	}
	// Empty inactive process values can still be supplied by Go's configuration
	// files. Preserve GOENV and the real query output: unchanged strict replay
	// rejects any resulting foreign CPU field rather than erasing evidence.
	return replaceEnv(base, replacements), nil
}
