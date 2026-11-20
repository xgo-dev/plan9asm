package gotoolprofile

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Offline replay verifies a source/tool-provenance-validated observation. It
// does not authenticate the Go binary or source bytes without the producer's
// actual-driver and actual-source checks.
func validateDiscoveryTargetFeatures(features *discoveryTargetFeatures) error {
	if features == nil || features.Protocol != "go_driver_builtin_features_v2" {
		return fmt.Errorf("missing actual Go driver builtin-feature protocol")
	}
	parts := strings.Split(features.Target, "/")
	minor, err := goMinor(features.GoVersion)
	if len(parts) != 2 || err != nil || minor < 20 || minor > 27 || features.GoVersion != features.Environment["GOVERSION"] ||
		features.Environment["GOOS"] != parts[0] || features.Environment["GOARCH"] != parts[1] || features.Environment["CGO_ENABLED"] != "0" {
		return fmt.Errorf("actual feature environment/version does not match its target")
	}
	if err := validateTarget(features.Target); err != nil {
		return err
	}
	if len(features.Environment) != len(discoveryFeatureEnvKeys)-3 {
		return fmt.Errorf("incomplete or nonportable actual feature environment")
	}
	for _, key := range discoveryFeatureEnvKeys {
		if key != "GOROOT" && key != "GOTOOLDIR" && key != "GOCACHE" {
			if _, present := features.Environment[key]; !present {
				return fmt.Errorf("missing actual feature environment key %s", key)
			}
		}
	}
	if !validDiscoveryFeatureToolDirectory(features.ToolDirectory) ||
		len(features.ToolBinarySHA256) != len(discoveryFeatureSubtools) ||
		len(features.ToolBinaryOrigins) != len(discoveryFeatureSubtools) ||
		!discoverySHA256Pattern.MatchString(features.ToolRoutingSHA256) ||
		!discoverySHA256Pattern.MatchString(features.ToolDispatcherSHA256) {
		return fmt.Errorf("missing actual Go subtool identity")
	}
	for _, name := range discoveryFeatureSubtools {
		if !discoverySHA256Pattern.MatchString(features.ToolBinarySHA256[name]) {
			return fmt.Errorf("missing actual Go %s tool identity", name)
		}
		suffix := ""
		if strings.HasPrefix(strings.TrimPrefix(features.ToolDirectory, "pkg/tool/"), "windows_") {
			suffix = ".exe"
		}
		origin := features.ToolBinaryOrigins[name]
		if origin != "goroot/"+features.ToolDirectory+"/"+name+suffix &&
			!(minor >= 25 && (name == "nm" || name == "vet") && origin == "gocache/builtin/cmd/"+name) {
			return fmt.Errorf("unrecognized actual Go %s tool origin", name)
		}
	}
	for _, digest := range []string{features.DriverSHA256, features.MarkerSourceSHA256, features.DriverSelectionSHA256, features.EnvStderrSHA256, features.EnvRecheckStderrSHA256, features.ListStderrSHA256} {
		if !discoverySHA256Pattern.MatchString(digest) {
			return fmt.Errorf("missing actual driver/marker/command identity")
		}
	}
	if len(features.ToolSourceSHA256) != 3 {
		return fmt.Errorf("incomplete actual Go feature-registration source identity")
	}
	for _, file := range []string{"VERSION", "src/internal/buildcfg/cfg.go", "src/internal/goexperiment/flags.go"} {
		if !discoverySHA256Pattern.MatchString(features.ToolSourceSHA256[file]) {
			return fmt.Errorf("missing actual feature-registration source %s", file)
		}
	}
	cpuKey := map[string]string{"386": "GO386", "amd64": "GOAMD64", "arm": "GOARM", "arm64": "GOARM64", "wasm": "GOWASM"}[parts[1]]
	if cpuKey == "" || validateDiscoveryCPUEnvironment(parts[1], features.Environment[cpuKey], minor) != nil {
		return fmt.Errorf("invalid actual target CPU profile")
	}
	for _, key := range []string{"GO386", "GOAMD64", "GOARM", "GOARM64", "GOWASM"} {
		if key != cpuKey && features.Environment[key] != "" {
			return fmt.Errorf("foreign target CPU environment leaked into observation")
		}
	}
	cpuNames := make(map[string]bool)
	for _, tag := range discoveryCPUFeatureCandidates() {
		cpuNames[tag] = true
		if _, present := features.MarkerSelection[tag]; !present {
			return fmt.Errorf("missing builtin CPU namespace member %s", tag)
		}
	}
	var experiments []string
	var allNames, selected []string
	for name, enabled := range features.MarkerSelection {
		allNames = append(allNames, name)
		if enabled {
			selected = append(selected, name)
		}
	}
	allNames, selected = uniqueSortedDiscoveryStrings(allNames), uniqueSortedDiscoveryStrings(selected)
	for _, tag := range allNames {
		if strings.HasPrefix(tag, "goexperiment.") {
			experiments = append(experiments, tag)
		} else if !cpuNames[tag] {
			return fmt.Errorf("unknown builtin namespace member %s", tag)
		}
	}
	encoded, err := json.Marshal(experiments)
	if err != nil || discoveryFeatureBytesSHA256(encoded) != discoveryVersionedExperimentFingerprints[minor] {
		return fmt.Errorf("incomplete or foreign actual Go experiment namespace")
	}
	selectedCPU := discoveryModeledCPUFeatures(nil, parts[1], features.Environment[cpuKey], minor)
	for tag := range cpuNames {
		if features.MarkerSelection[tag] != containsTargetFeature(selectedCPU, tag) {
			return fmt.Errorf("actual CPU marker selection disagrees with observed environment: %s", tag)
		}
	}
	if !equalDiscoveryStrings(features.ToolTags, selected) || features.MarkerSourceSHA256 != discoveryFeatureMarkerSHA256(discoveryFeatureMarkerFiles(allNames)) {
		return fmt.Errorf("feature tags do not match the complete actual marker observation")
	}
	encoded, err = json.Marshal(features.MarkerSelection)
	if err != nil || features.DriverSelectionSHA256 != discoveryFeatureBytesSHA256(encoded) {
		return fmt.Errorf("actual driver selection digest does not match its complete marker observation")
	}
	return nil
}
