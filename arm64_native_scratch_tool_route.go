package plan9asm

import (
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// Only paths actually returned by the stock driver for its builtin tools or
// selected exports use this route. Original source/SDK paths still go through
// the strict physical-file reader. Retain both names so redirecting a cache
// alias cannot substitute bytes during a later command or verification.
func (source *GoARM64ScratchSource) readObservedCacheFile(name string) ([]byte, error) {
	cache := source.settings["GOCACHE"]
	if !filepath.IsAbs(name) || strings.ContainsAny(name, "\r\n") ||
		!filepath.IsAbs(cache) || !goAssemblyPathWithinRoot(cache, name) {
		return nil, arm64ScratchContext("unrecognized driver-generated cache input")
	}
	physicalCache, err := sourcepath.Resolve(cache)
	if err != nil {
		return nil, err
	}
	physical, err := sourcepath.Resolve(name)
	if err != nil || !goAssemblyPathWithinRoot(physicalCache, physical) {
		return nil, arm64ScratchContext("driver-generated input escaped its actual cache")
	}
	if previous, present := source.generatedPaths[name]; present && previous != physical {
		return nil, arm64ScratchContext("driver-generated cache route changed")
	}
	data, err := source.read(physical)
	if err != nil {
		return nil, err
	}
	if source.generatedPaths == nil {
		source.generatedPaths = make(map[string]string)
	}
	source.generatedPaths[name] = physical
	return data, nil
}

func (source *GoARM64ScratchSource) readObservedTool(tool, name string) error {
	if !filepath.IsAbs(name) || strings.ContainsAny(name, "\r\n") {
		return arm64ScratchContext("unknown actual %s tool identity", tool)
	}
	executable := tool
	if strings.HasSuffix(source.request.GoBinary, ".exe") {
		executable += ".exe"
	}
	if name == filepath.Join(source.settings["GOTOOLDIR"], executable) {
		_, err := source.read(name)
		return err
	}
	// Go1.27's builtin-tool frontend builds these two tools for the host in
	// GOCACHE even for cross targets. asm/compile must retain their SDK route.
	if (tool != "objdump" && tool != "pack") || filepath.Base(name) != executable {
		return arm64ScratchContext("unknown builtin %s tool origin", tool)
	}
	_, err := source.readObservedCacheFile(name)
	return err
}

func (source *GoARM64ScratchSource) readObservedExport(pkg arm64ScratchPackage) ([]byte, error) {
	// Older SDKs may still ship precompiled standard-library archives. Their
	// exact selected SDK role remains physical, not an arbitrary export path.
	if pkg.Standard && pkg.Goroot &&
		goAssemblyPathWithinRoot(filepath.Join(source.settings["GOROOT"], "pkg"), pkg.Export) {
		return source.read(pkg.Export)
	}
	return source.readObservedCacheFile(pkg.Export)
}

func (source *GoARM64ScratchSource) verifyGeneratedPaths() error {
	for original, expected := range source.generatedPaths {
		actual, err := sourcepath.Resolve(original)
		if err != nil || actual != expected {
			return arm64ScratchContext("driver-generated cache input was redirected")
		}
	}
	return nil
}
