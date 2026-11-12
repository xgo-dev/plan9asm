package gotoolprofile

import (
	"context"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/mod/module"
)

// These are source resources within the independent instrumentation v2 role.
// Reusing the ZIP/directory verifier does not create a TestDependencyProof,
// supplemental declaration, embed permission, or candidate assembly scope.
type instrumentationTypeModuleBinding struct {
	source                       TestModuleSource
	root, archive, downloadedMod string
	metadata                     map[string]string
}

type InstrumentationTypeModuleGuard struct {
	bindings map[string]*instrumentationTypeModuleBinding
}

func validateInstrumentationTypeModuleResources(sources []TestModuleSource) error {
	if sources == nil || len(sources) > 4096 {
		return fmt.Errorf("instrumentation v2 requires its bounded explicit source-only module inventory")
	}
	entries, directories, headers, textBytes := 0, 0, 0, 0
	for i, source := range sources {
		if source.SourceModule == "" || i > 0 && sources[i-1].ID() >= source.ID() {
			return fmt.Errorf("instrumentation foreign modules lack unique canonical exact identities")
		}
		if err := ValidateTestModuleSource(source); err != nil {
			return fmt.Errorf("instrumentation source-only resource: %w", err)
		}
		directories += len(source.Directories)
		headers += len(source.Headers)
		for _, members := range source.Directories {
			entries += len(members)
		}
		for _, contents := range source.Headers {
			textBytes += len(contents)
		}
		if directories > 4096 || entries > 65536 || headers > 32768 || textBytes > instrumentationOriginalInventoryLimit {
			return fmt.Errorf("instrumentation foreign source inventory exceeds its shared resource budget")
		}
	}
	return nil
}

// BindInstrumentationTypeModuleSources obtains live paths only from the actual
// bounded Go download. Recorded paths or matching export hashes cannot bind a
// foreign source. The production producer separately authenticates the exact
// download with the unchanged stock-Go/SumDB/ZIP/go.mod machinery.
func BindInstrumentationTypeModuleSources(ctx context.Context, binary, directory string, env []string,
	sources []TestModuleSource, run Runner,
) (*InstrumentationTypeModuleGuard, error) {
	if ctx == nil || ctx.Err() != nil || run == nil || !filepath.IsAbs(binary) || !filepath.IsAbs(directory) {
		return nil, fmt.Errorf("instrumentation source modules require a live actual Go invocation")
	}
	if err := validateInstrumentationTypeModuleResources(sources); err != nil {
		return nil, err
	}
	// A caller may not mutate the portable input to rewrite an already live guard.
	data, err := json.Marshal(sources)
	if err != nil {
		return nil, err
	}
	var snapshot []TestModuleSource
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	guard := &InstrumentationTypeModuleGuard{bindings: make(map[string]*instrumentationTypeModuleBinding)}
	for _, source := range snapshot {
		stdout, stderr, err := run(ctx, directory, env, binary, "mod", "download", "-json", source.ID())
		if err != nil || len(stderr) != 0 || len(stdout) == 0 || len(stdout) > commandOutputLimit {
			return nil, fmt.Errorf("instrumentation exact foreign source download failed: %v; %s", err, stderr)
		}
		var download struct{ Path, Version, Dir, Zip, GoMod, Sum, GoModSum, Error string }
		if err := json.Unmarshal(stdout, &download); err != nil || download.Error != "" ||
			download.Path != source.SourceModule || download.Version != source.SourceVersion ||
			download.Sum != source.ModuleSum || download.GoModSum != source.GoModSum {
			return nil, fmt.Errorf("instrumentation source download differs from its exact ZIP/mod identity: %v", err)
		}
		root, err := sourcepath.Resolve(download.Dir)
		if err != nil || !filepath.IsAbs(root) {
			return nil, fmt.Errorf("instrumentation foreign source lacks an actual canonical root")
		}
		binding := &instrumentationTypeModuleBinding{source: source, root: root, archive: download.Zip,
			downloadedMod: download.GoMod, metadata: make(map[string]string)}
		guard.bindings[source.ID()] = binding
		if err := guard.bindMetadata(binding, download.GoMod); err != nil {
			return nil, err
		}
	}
	return guard, guard.Verify(ctx)
}

func (guard *InstrumentationTypeModuleGuard) bindMetadata(binding *instrumentationTypeModuleBinding, filename string) error {
	if err := VerifyTestModuleGoModMetadata(binding.source, binding.root, filename, binding.downloadedMod); err != nil {
		return err
	}
	resolved, err := sourcepath.Resolve(filename)
	if err != nil {
		return err
	}
	if old, found := binding.metadata[filename]; found && old != resolved {
		return fmt.Errorf("instrumentation foreign metadata changed its physical path")
	}
	binding.metadata[filename] = resolved
	return nil
}

func (guard *InstrumentationTypeModuleGuard) bindPackage(pkg instrumentationTypeListPackage) (*instrumentationTypeModuleBinding, ImportExport, error) {
	source := ImportExport{ImportPath: pkg.ImportPath, PackagePath: pkg.ImportPath, GoSHA256: make(map[string]string)}
	actual := pkg.Module
	if guard == nil || actual == nil || actual.Main || module.Check(actual.Path, actual.Version) != nil ||
		pkg.ImportPath != actual.Path && !strings.HasPrefix(pkg.ImportPath, actual.Path+"/") {
		return nil, source, fmt.Errorf("instrumentation foreign package lacks actual exact Module ownership")
	}
	source.ModulePath, source.Version = actual.Path, actual.Version
	source.SourceModule, source.SourceVersion, source.SourceRole = actual.Path, actual.Version, "module"
	metadata := actual.GoMod
	root, err := sourcepath.Resolve(actual.Dir)
	if err != nil {
		return nil, source, err
	}
	if replacement := actual.Replace; replacement != nil {
		if replacement.Main || replacement.Replace != nil || module.Check(replacement.Path, replacement.Version) != nil {
			return nil, source, fmt.Errorf("instrumentation foreign source has unknown/local/nested replacement")
		}
		replaced, err := sourcepath.Resolve(replacement.Dir)
		if err != nil || root != replaced {
			return nil, source, fmt.Errorf("instrumentation replacement changed its actual source root")
		}
		source.SourceModule, source.SourceVersion, source.SourceRole = replacement.Path, replacement.Version, "version_replace"
		metadata = replacement.GoMod
	}
	binding := guard.bindings[source.SourceModule+"@"+source.SourceVersion]
	if binding == nil || binding.root != root {
		return nil, source, fmt.Errorf("original type graph needs an authenticated foreign module source closure")
	}
	if err := guard.bindMetadata(binding, metadata); err != nil {
		return nil, source, err
	}
	return binding, source, nil
}

// Verify rechecks original membership, ZIP/h1/mod origin and every observed
// physical metadata path at the final metadata/CPP/LLVM consumer boundary.
func (guard *InstrumentationTypeModuleGuard) Verify(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || guard == nil || guard.bindings == nil {
		return fmt.Errorf("missing live instrumentation foreign source guard")
	}
	for _, binding := range guard.bindings {
		if err := VerifyTestModuleSource(ctx, binding.source, binding.root, binding.archive); err != nil {
			return err
		}
		for name, wanted := range binding.metadata {
			actual, err := sourcepath.Resolve(name)
			if err != nil || actual != wanted {
				return fmt.Errorf("instrumentation foreign metadata path changed after loading")
			}
			if err := VerifyTestModuleGoModMetadata(binding.source, binding.root, name, binding.downloadedMod); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateInstrumentationTypeModuleCoverage(input *InstrumentationConsumerInput, proof *InstrumentationTypeSourceProof) error {
	if err := validateInstrumentationTypeModuleResources(proof.SourceModules); err != nil {
		return err
	}
	resources := make(map[string]TestModuleSource)
	needed := make(map[string]map[string]bool)
	for _, source := range proof.SourceModules {
		resources[source.ID()] = source
	}
	for _, pkg := range proof.Dependencies {
		source := pkg.Dependency.Source
		foreign := source.ModulePath != "" && source.ModulePath != input.Original.Module
		if !foreign {
			if pkg.SourceRootID != "" || pkg.SFiles != nil {
				return fmt.Errorf("ordinary/SDK type package acquired a foreign source-only role")
			}
			continue
		}
		id := source.SourceModule + "@" + source.SourceVersion
		resource, found := resources[id]
		if !found || pkg.SourceRootID != id || module.Check(source.ModulePath, source.Version) != nil ||
			source.SourceRole != "module" && source.SourceRole != "version_replace" ||
			source.SourceRole == "module" && (source.SourceModule != source.ModulePath || source.SourceVersion != source.Version) || pkg.SFiles == nil {
			return fmt.Errorf("foreign type package lacks its actual independent module/source selection")
		}
		directory := strings.TrimPrefix(strings.TrimPrefix(source.PackagePath, source.ModulePath), "/")
		if directory == "" {
			directory = "."
		}
		if source.PackagePath != source.ModulePath && !strings.HasPrefix(source.PackagePath, source.ModulePath+"/") {
			return fmt.Errorf("foreign package has a different declared module owner")
		}
		if needed[id] == nil {
			needed[id] = make(map[string]bool)
		}
		if err := validateInstrumentationForeignSelection(input, pkg, resource, directory); err != nil {
			return err
		}
		for dir := directory; ; dir = path.Dir(dir) {
			needed[id][dir] = true
			if dir == "." {
				break
			}
		}
		for file, hash := range source.GoSHA256 {
			if path.Dir(file) != directory || resource.Sources[file] != hash {
				return fmt.Errorf("foreign selected Go source differs from its original ZIP resource")
			}
		}
		if !sort.StringsAreSorted(pkg.SFiles) {
			return fmt.Errorf("foreign selected assembly is not canonical")
		}
		for i, file := range pkg.SFiles {
			if path.Ext(file) != ".s" || path.Dir(file) != directory || resource.Sources[file] == "" || i > 0 && pkg.SFiles[i-1] == file {
				return fmt.Errorf("foreign selected assembly has an unbound original source role")
			}
		}
	}
	if len(needed) != len(resources) {
		return fmt.Errorf("instrumentation source-only inventory contains an unconsumed module")
	}
	for id, source := range resources {
		if len(source.Directories) != len(needed[id]) {
			return fmt.Errorf("instrumentation foreign source directories lost exact consumed coverage")
		}
		for directory := range source.Directories {
			if !needed[id][directory] {
				return fmt.Errorf("unconsumed instrumentation foreign directory")
			}
		}
	}
	return nil
}

func validateInstrumentationForeignSelection(input *InstrumentationConsumerInput, pkg InstrumentationTypeSourcePackage,
	resource TestModuleSource, directory string,
) error {
	if input.Observation.Early.SourceRules == nil ||
		input.Observation.Early.SourceRules.GoVersion != input.Observation.Early.BaselineFeatures.GoVersion {
		return fmt.Errorf("foreign original selection lacks its same-SDK source-rule identity")
	}
	context, err := instrumentationOriginalBuildContext(&InstrumentationOriginalSourceInventory{Contents: resource.Headers},
		input.Observation.Early, input.Plan.CustomTags, true)
	if err != nil {
		return err
	}
	goFiles, assembly := []string{}, []string{}
	for _, member := range resource.Directories[directory] {
		if member.Kind != "file" || path.Ext(member.Name) != ".go" && path.Ext(member.Name) != ".s" {
			continue
		}
		file := path.Join(directory, member.Name)
		selected, err := context.MatchFile(directory, member.Name)
		if err != nil {
			return fmt.Errorf("foreign ordinary source selection: %w", err)
		}
		if !selected || strings.HasSuffix(member.Name, "_test.go") {
			continue
		}
		if path.Ext(member.Name) == ".s" {
			assembly = append(assembly, file)
			continue
		}
		syntax, err := parser.ParseFile(token.NewFileSet(), file, resource.Headers[file], parser.ImportsOnly)
		if err != nil || syntax.Name.Name != pkg.Name {
			return fmt.Errorf("foreign selected source lost its actual ordinary package clause")
		}
		for _, imported := range syntax.Imports {
			spelling, err := strconv.Unquote(imported.Path.Value)
			if err != nil || spelling == "C" {
				return fmt.Errorf("foreign source-only type selection cannot grant a generated cgo role")
			}
		}
		goFiles = append(goFiles, file)
	}
	claimed := make([]string, 0, len(pkg.Dependency.Source.GoSHA256))
	for file := range pkg.Dependency.Source.GoSHA256 {
		claimed = append(claimed, file)
	}
	sort.Strings(claimed)
	if !reflect.DeepEqual(goFiles, claimed) || !reflect.DeepEqual(assembly, pkg.SFiles) {
		return fmt.Errorf("foreign source-only selection differs from complete original directory/profile/tags")
	}
	// Body-only dependencies deliberately have no declaration-AST Contents.
	// Their complete original selection headers still bind every import spelling.
	return validateInstrumentationOriginalImportSpellings(goFiles, resource.Headers, pkg.Dependency.ImportMap)
}

func instrumentationForeignDependencyBound(input *InstrumentationConsumerInput, source ImportExport) bool {
	if input.TypeSources == nil || input.TypeSources.Protocol != instrumentationTypeSourcesProtocol {
		return false
	}
	for _, pkg := range input.TypeSources.Dependencies {
		if pkg.SourceRootID != "" && reflect.DeepEqual(pkg.Dependency.Source, source) {
			return true
		}
	}
	return false
}
