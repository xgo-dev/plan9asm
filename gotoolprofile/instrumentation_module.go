package gotoolprofile

import (
	"fmt"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// InstrumentationOriginalModulePath derives a namespace from complete original
// ZIP go.mod bytes, not a requested path or a caller-supplied namespace override.
// Its caller must independently authenticate the archive/member and guard the
// original bytes before and after every actual source/export/object phase.
func InstrumentationOriginalModulePath(contents, expectedSHA256 string) (string, error) {
	if len(contents) == 0 || len(contents) > instrumentationOriginalFileLimit ||
		!discoverySHA256Pattern.MatchString(expectedSHA256) || bytesSHA256([]byte(contents)) != expectedSHA256 {
		return "", fmt.Errorf("original module namespace lacks bounded unchanged ZIP metadata")
	}
	parsed, err := modfile.Parse("go.mod", []byte(contents), nil)
	if err != nil || parsed.Module == nil || module.CheckPath(parsed.Module.Mod.Path) != nil {
		return "", fmt.Errorf("original module namespace has invalid or missing module metadata: %v", err)
	}
	return parsed.Module.Mod.Path, nil
}

func validateInstrumentationModuleNamespace(input *ConsumerInput, contents string) error {
	if input == nil || input.SourceModule == "" && input.Version != "" || input.SourceModule != "" &&
		(module.Check(input.SourceModule, input.Version) != nil || module.Check(input.Module, input.Version) != nil) {
		return fmt.Errorf("original source role lacks an exact external identity or genuine versionless main module")
	}
	alias := input.SourceModule != "" && input.SourceModule != input.Module
	if !alias {
		if contents != "" {
			return fmt.Errorf("unaliasable module carries unexplained namespace metadata")
		}
		return nil
	}
	// A legacy proxy directive is a separate authenticated origin and cannot
	// supply a fictitious ZIP member or authorize another namespace here.
	if input.ProxyGoMod != nil {
		return fmt.Errorf("proxy go.mod cannot supply an original ZIP namespace alias")
	}
	members := 0
	for _, name := range input.Directories["."] {
		if name == "go.mod" {
			members++
		}
	}
	if members != 1 {
		return fmt.Errorf("original alias lacks its unique complete root-directory go.mod member")
	}
	declared, err := InstrumentationOriginalModulePath(contents, input.Sources["go.mod"])
	if err != nil || declared != input.Module {
		return fmt.Errorf("original namespace differs from the exact ZIP module declaration: %v", err)
	}
	return nil
}
