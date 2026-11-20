package gotoolprofile

import (
	"context"
	"fmt"
)

// Capture and Validate share the complete actual-driver marker protocol.
// Observe the same environment/cache/routing before and after consuming it;
// a caller-provided ID is never sufficient on its own.
func Capture(ctx context.Context, binary, ownedDir string, env []string, target string, overrides map[string]string, run Runner) (*Observation, error) {
	if ctx == nil || run == nil {
		return nil, fmt.Errorf("feature capture requires a live context and bounded command runner")
	}
	return captureDiscoveryTargetFeatures(ctx, binary, ownedDir, env, target, overrides, run)
}

func Validate(observed *Observation) error { return validateDiscoveryTargetFeatures(observed) }
func CPUEnvironment(arch, value string, minor int) error {
	return validateDiscoveryCPUEnvironment(arch, value, minor)
}
func CPUCandidates() []string { return discoveryCPUFeatureCandidates() }
func BuiltinCandidates(root string, versions ...string) ([]string, map[string]string, error) {
	return discoveryBuiltinFeatureCandidates(root, versions...)
}
func ValidateRegistration(data []byte, minors ...int) error {
	return validateDiscoveryFeatureRegistration(data, minors...)
}
func ExperimentCandidates(data []byte) ([]string, error) {
	return discoveryExperimentFeatureCandidates(data)
}
func MarkerFiles(tags []string) map[string][]byte { return discoveryFeatureMarkerFiles(tags) }
func DecodeMarkers(data []byte, dir string, tags []string) (map[string]bool, error) {
	return decodeDiscoveryFeatureMarkers(data, dir, tags)
}
func TagNamespace(tag string) bool { return discoveryFeatureTagNamespace(tag) }

// ReservedTag covers the frontend's target/compiler namespace in addition to
// CPU, experiment and instrumentation tags. These cannot be user CPU profiles.
func ReservedTag(tag string) bool {
	if TagNamespace(tag) {
		return true
	}
	for _, reserved := range []string{
		"ignore", "cgo", "gc", "gccgo", "unix",
		"aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios", "js", "linux", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows", "zos",
		"386", "amd64", "amd64p32", "arm", "armbe", "arm64", "arm64be", "loong64", "mips", "mipsle", "mips64", "mips64le", "mips64p32", "mips64p32le", "ppc", "ppc64", "ppc64le", "riscv", "riscv64", "s390", "s390x", "sparc", "sparc64", "wasm",
	} {
		if tag == reserved {
			return true
		}
	}
	return false
}
func FileSHA256(name string) (string, error)      { return discoveryFeatureFileSHA256(name) }
func MarkerSHA256(files map[string][]byte) string { return discoveryFeatureMarkerSHA256(files) }
func EnvironmentKeys() []string                   { return append([]string(nil), discoveryFeatureEnvKeys...) }
func CPUFeatures(tags []string, arch, value string, minor int) []string {
	return discoveryModeledCPUFeatures(tags, arch, value, minor)
}

type ToolState struct {
	Directory  string
	Digests    map[string]string
	Origins    map[string]string
	Routing    string
	Dispatcher string
}

func CaptureSubtools(ctx context.Context, binary string, env []string, actual map[string]string, run Runner) (*ToolState, error) {
	state, err := captureDiscoveryFeatureSubtools(ctx, binary, env, actual, run)
	if err != nil {
		return nil, err
	}
	return &ToolState{Directory: state.directory, Digests: state.digests, Origins: state.origins, Routing: state.routing, Dispatcher: state.dispatcher}, nil
}

func ValidToolDirectory(directory string) bool { return validDiscoveryFeatureToolDirectory(directory) }
