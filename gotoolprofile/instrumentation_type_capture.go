package gotoolprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// This is an original-input capture, separate from the metadata query. The
// caller must already authenticate the module ZIP/go.mod and stock SDK. Actual
// Go selects the whole graph twice under the registered mode, before and after
// export compilation; source roots, bytes, exports and tool routing are checked
// again at the end. No import prefix, export digest or portable JSON authorizes
// a physical root. Foreign modules require their independent v2 source resource;
// generated/native/embed roles stay closed.
func CaptureInstrumentationTypeSources(ctx context.Context, binary, directory string, env []string, input *InstrumentationConsumerInput, run Runner) (*InstrumentationTypeSourceProof, error) {
	modules := []TestModuleSource{}
	if input != nil && input.TypeSources != nil {
		modules = input.TypeSources.SourceModules
	}
	return CaptureInstrumentationTypeSourcesWithModules(ctx, binary, directory, env, input, modules, run)
}

func CaptureInstrumentationTypeSourcesWithModules(ctx context.Context, binary, directory string, env []string,
	input *InstrumentationConsumerInput, modules []TestModuleSource, run Runner,
) (*InstrumentationTypeSourceProof, error) {
	return captureInstrumentationTypeSources(ctx, binary, directory, env, input, modules, run, retainInstrumentationRequiredTypeSources)
}

func captureInstrumentationTypeSources(ctx context.Context, binary, directory string, env []string,
	input *InstrumentationConsumerInput, modules []TestModuleSource, run Runner,
	retain func(*InstrumentationConsumerInput, *InstrumentationTypeSourceProof, *instrumentationTypeGraph) error,
) (*InstrumentationTypeSourceProof, error) {
	env = replaceEnv(env, map[string]string{"GOENV": "off"})
	if ctx == nil || ctx.Err() != nil || run == nil || !filepath.IsAbs(binary) || !filepath.IsAbs(directory) || input == nil || input.Plan == nil {
		return nil, fmt.Errorf("original type source capture needs a live bounded actual Go invocation")
	}
	// The consumer also compiles from the physical invocation directory.
	// Windows short/long spellings can change compiler-recorded source names
	// and export bytes even when both routes select the same original files.
	directory, err := sourcepath.Resolve(directory)
	if err != nil {
		return nil, err
	}
	if err := ValidateInstrumentationConsumerInput(input, input.Plan.PackageDirectory, input.Plan.CustomTags); err != nil {
		return nil, err
	}
	if err := recheckInstrumentationOriginalSources(input.Original); err != nil {
		return nil, err
	}
	moduleGuard, err := BindInstrumentationTypeModuleSources(ctx, binary, directory, env, modules, run)
	if err != nil {
		return nil, err
	}
	configuration, err := captureInstrumentationInvocationConfig(directory)
	if err != nil {
		return nil, err
	}
	actual, commandContext, err := instrumentationObserverEnvironment(ctx, binary, directory, env, run)
	if err != nil {
		return nil, err
	}
	early := input.Observation.Early
	if err := recheckInstrumentationExportEnvironment(actual, commandContext, early); err != nil {
		return nil, err
	}
	tools, err := captureDiscoveryFeatureSubtools(ctx, binary, env, actual, run)
	if err != nil || !instrumentationExportToolsMatch(tools, early.ModeTools) {
		return nil, fmt.Errorf("original type capture tool routing differs from the registered mode: %v", err)
	}
	before, err := captureInstrumentationTypeGraph(ctx, binary, directory, env, input, actual, false, moduleGuard, run)
	if err != nil {
		return nil, err
	}
	after, err := captureInstrumentationTypeGraph(ctx, binary, directory, env, input, actual, true, moduleGuard, run)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(before.selection, after.selection) {
		return nil, fmt.Errorf("original type source selection/origin/ImportMap/bytes changed during export")
	}
	for file, expected := range before.hashes {
		if after.hashes[file] != expected || after.paths[file] != before.paths[file] {
			return nil, fmt.Errorf("original imported source/metadata physical path changed during export")
		}
	}
	for file, expected := range after.hashes {
		resolved, err := sourcepath.Resolve(file)
		if err != nil || resolved != after.paths[file] {
			return nil, fmt.Errorf("actual imported source/export path changed during capture")
		}
		if digest, err := FileSHA256(file); err != nil || digest != expected {
			return nil, fmt.Errorf("actual imported source/export bytes changed during capture")
		}
	}
	if err := recheckInstrumentationOriginalSources(input.Original); err != nil {
		return nil, err
	}
	configs, err := captureInstrumentationInvocationConfig(directory)
	if err != nil || !reflect.DeepEqual(configuration, configs) {
		return nil, fmt.Errorf("original type capture invocation metadata changed")
	}
	now, nowContext, err := instrumentationObserverEnvironment(ctx, binary, directory, env, run)
	if err != nil || !reflect.DeepEqual(now, actual) || !reflect.DeepEqual(nowContext, commandContext) {
		return nil, fmt.Errorf("original type capture environment changed")
	}
	nowTools, err := captureDiscoveryFeatureSubtools(ctx, binary, env, actual, run)
	if err != nil || !equalDiscoveryFeatureToolStates(tools, nowTools) {
		return nil, fmt.Errorf("original type capture tool bytes/routing changed")
	}
	sources, err := CaptureInstrumentationSourceProof(actual["GOROOT"], actual["GOVERSION"])
	if err != nil || !reflect.DeepEqual(sources, early.SourceRules) {
		return nil, fmt.Errorf("original type capture SDK source rules changed")
	}
	if digest, err := FileSHA256(binary); err != nil || digest != early.BaselineFeatures.DriverSHA256 {
		return nil, fmt.Errorf("original type capture Go driver changed")
	}
	for name, expected := range early.BaselineFeatures.ToolSourceSHA256 {
		if digest, err := FileSHA256(filepath.Join(actual["GOROOT"], filepath.FromSlash(name))); err != nil || digest != expected {
			return nil, fmt.Errorf("original type capture registered SDK source changed: %s", name)
		}
	}
	proof := after.proof
	if err := retain(input, proof, after); err != nil {
		return nil, err
	}
	for file, expected := range after.hashes {
		resolved, err := sourcepath.Resolve(file)
		if err != nil || resolved != after.paths[file] {
			return nil, fmt.Errorf("actual original type source path changed during AST capture")
		}
		if digest, err := FileSHA256(file); err != nil || digest != expected {
			return nil, fmt.Errorf("actual original type source/export changed during AST capture")
		}
	}
	if err := moduleGuard.Verify(ctx); err != nil {
		return nil, err
	}
	return proof, ValidateInstrumentationTypeSources(input, proof)
}

type instrumentationTypeListModule struct {
	Path, Version, Dir, GoMod string
	Main                      bool
	Replace                   *instrumentationTypeListModule
}

type instrumentationTypeListPackage struct {
	Dir, ImportPath, Name, Export, ForTest                      string
	GoFiles, CompiledGoFiles, SFiles, Imports                   []string
	CgoFiles, CFiles, CXXFiles, FFiles, SwigFiles, SwigCXXFiles []string
	EmbedFiles, EmbedPatterns                                   []string
	ImportMap                                                   map[string]string
	Module                                                      *instrumentationTypeListModule
	Incomplete                                                  bool
	Error                                                       json.RawMessage
	DepsErrors                                                  []json.RawMessage
}

type instrumentationTypeGraph struct {
	proof       *InstrumentationTypeSourceProof
	selection   map[string]string
	hashes      map[string]string
	paths       map[string]string
	files       map[string]map[string]string
	moduleFiles map[string]string
	bytes       int
	modules     *InstrumentationTypeModuleGuard
}

// This is only an index of metadata already retained by the original/foreign
// source guards. Private graph constructors used for those guards need not
// initialize the separate native-header query index.
func (graph *instrumentationTypeGraph) recordModuleMetadataPath(id, filename string) {
	if graph.moduleFiles == nil {
		graph.moduleFiles = make(map[string]string)
	}
	graph.moduleFiles[id] = filename
}

func captureInstrumentationTypeGraph(ctx context.Context, binary, directory string, env []string, input *InstrumentationConsumerInput, actual map[string]string, export bool, modules *InstrumentationTypeModuleGuard, run Runner) (*instrumentationTypeGraph, error) {
	flags, err := InstrumentationPackageLoadFlags(input)
	if err != nil {
		return nil, err
	}
	args := append([]string{"list", "-deps", "-compiled", "-json"}, flags...)
	if export {
		args = append(args, "-export")
	}
	args = append(args, input.Plan.PackagePath)
	stdout, stderr, err := run(ctx, directory, env, binary, args...)
	if err != nil || len(stderr) != 0 || len(stdout) == 0 || len(stdout) > commandOutputLimit {
		return nil, fmt.Errorf("actual same-mode original type graph failed (not source N/A): %v; %s", err, stderr)
	}
	graph := &instrumentationTypeGraph{
		proof:     &InstrumentationTypeSourceProof{Protocol: instrumentationTypeSourcesProtocol, InputSHA256: instrumentationTypeSourceInputSHA(input), Dependencies: []InstrumentationTypeSourcePackage{}, SourceModules: []TestModuleSource{}},
		selection: make(map[string]string), hashes: make(map[string]string), paths: make(map[string]string), files: make(map[string]map[string]string),
		modules: modules, moduleFiles: make(map[string]string),
	}
	for _, binding := range modules.bindings {
		graph.proof.SourceModules = append(graph.proof.SourceModules, binding.source)
	}
	SortTestModuleSources(graph.proof.SourceModules)
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	seen, rootSeen := make(map[string]bool), false
	for {
		var pkg instrumentationTypeListPackage
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if len(seen) >= 4096 || pkg.ImportPath == "" || seen[pkg.ImportPath] || !token.IsIdentifier(pkg.Name) || pkg.Name == "_" ||
			pkg.Incomplete || len(pkg.Error) != 0 || len(pkg.DepsErrors) != 0 || pkg.ForTest != "" ||
			len(pkg.CgoFiles)+len(pkg.CFiles)+len(pkg.CXXFiles)+len(pkg.FFiles)+len(pkg.SwigFiles)+len(pkg.SwigCXXFiles)+len(pkg.EmbedFiles)+len(pkg.EmbedPatterns) != 0 {
			return nil, fmt.Errorf("original type graph has unknown/generated/native/test/embed package roles")
		}
		seen[pkg.ImportPath] = true
		if pkg.ImportPath == "unsafe" {
			actualRoot, rootErr := sourcepath.Resolve(filepath.Join(actual["GOROOT"], "src", "unsafe"))
			actualDir, dirErr := sourcepath.Resolve(pkg.Dir)
			if pkg.Module != nil || pkg.Name != "unsafe" || rootErr != nil || dirErr != nil || actualDir != actualRoot {
				return nil, fmt.Errorf("builtin unsafe package acquired an external role")
			}
			file := filepath.Join(actualRoot, "unsafe.go")
			if err := graph.retain(file); err != nil {
				return nil, err
			}
			graph.proof.UnsafeSHA256 = graph.hashes[file]
			continue
		}
		entry, err := captureInstrumentationTypePackage(input, actual, pkg, graph, export)
		if err != nil {
			return nil, err
		}
		// Export bytes are intentionally absent from the pre/post source key:
		// compilation creates them between the two independently selected graphs.
		key := entry
		key.Dependency.Source.ExportSHA256 = ""
		graph.selection[pkg.ImportPath] = instrumentationObjectSHA(struct {
			Package InstrumentationTypeSourcePackage
			Origin  *instrumentationTypeListModule
			Dir     string
			SFiles  []string
		}{Package: key, Origin: pkg.Module, Dir: pkg.Dir, SFiles: pkg.SFiles})
		if pkg.ImportPath == input.Plan.PackagePath {
			goFiles := instrumentationTypeNames(pkg.GoFiles, pkg.Dir, input.Original.SourceRoot)
			compiledGoFiles := instrumentationTypeNames(pkg.CompiledGoFiles, pkg.Dir, input.Original.SourceRoot)
			asmFiles := instrumentationTypeNames(pkg.SFiles, pkg.Dir, input.Original.SourceRoot)
			if rootSeen || pkg.Name != input.Plan.PackageName || goFiles == nil || compiledGoFiles == nil || asmFiles == nil ||
				!equalDiscoveryStrings(goFiles, input.Plan.GoFiles) || !equalDiscoveryStrings(compiledGoFiles, input.Plan.GoFiles) ||
				!equalDiscoveryStrings(asmFiles, input.Plan.SFiles) {
				return nil, fmt.Errorf("actual original type graph changed the planned root selection")
			}
			rootSeen, graph.proof.RootImportMap = true, entry.Dependency.ImportMap
		} else {
			graph.proof.Dependencies = append(graph.proof.Dependencies, entry)
		}
	}
	if !rootSeen {
		return nil, fmt.Errorf("original type graph omitted the root package")
	}
	sort.Slice(graph.proof.Dependencies, func(i, j int) bool {
		return graph.proof.Dependencies[i].Dependency.Source.PackagePath < graph.proof.Dependencies[j].Dependency.Source.PackagePath
	})
	return graph, nil
}

func instrumentationTypeNames(names []string, directory, root string) []string {
	if !filepath.IsAbs(root) || !filepath.IsAbs(directory) {
		return nil
	}
	root, err := sourcepath.Resolve(root)
	if err != nil {
		return nil
	}
	directory, err = sourcepath.Resolve(directory)
	if err != nil {
		return nil
	}
	info, err := os.Stat(directory)
	relative, relErr := filepath.Rel(root, directory)
	if err != nil || !info.IsDir() || relErr != nil || !filepath.IsLocal(relative) {
		return nil
	}
	// A valid empty selection differs from failure. Compare actual physical
	// origins, not /var versus /private/var (or another root directory alias).
	result := make([]string, 0, len(names))
	for _, name := range names {
		if !filepath.IsAbs(name) {
			name = filepath.Join(directory, name)
		}
		parent, err := sourcepath.Resolve(filepath.Dir(name))
		if err != nil {
			return nil
		}
		name = filepath.Join(parent, filepath.Base(name))
		rel, err := filepath.Rel(root, name)
		if err != nil || !filepath.IsLocal(rel) {
			return nil
		}
		file := filepath.ToSlash(rel)
		if _, err := CPPRegularSource(root, file); err != nil {
			return nil
		}
		result = append(result, file)
	}
	sort.Strings(result)
	return result
}

func captureInstrumentationTypePackage(input *InstrumentationConsumerInput, actual map[string]string, pkg instrumentationTypeListPackage, graph *instrumentationTypeGraph, export bool) (InstrumentationTypeSourcePackage, error) {
	entry := InstrumentationTypeSourcePackage{Name: pkg.Name, Dependency: InstrumentationDependencyExport{
		Source: ImportExport{ImportPath: pkg.ImportPath, PackagePath: pkg.ImportPath, SourceRole: "stdlib", GoSHA256: make(map[string]string)}, ImportMap: make(map[string]string)}}
	root := filepath.Join(actual["GOROOT"], "src")
	var foreign *instrumentationTypeModuleBinding
	if pkg.Module != nil {
		module := pkg.Module
		if module.Path != input.Original.Module || module.Version != input.Original.Version || module.Main != (input.Original.SourceModule == "") {
			var err error
			foreign, entry.Dependency.Source, err = graph.modules.bindPackage(pkg)
			if err != nil {
				return entry, err
			}
			root, entry.SourceRootID = foreign.root, foreign.source.ID()
			metadata := module.GoMod
			if module.Replace != nil {
				metadata = module.Replace.GoMod
			}
			if err := graph.retain(metadata); err != nil {
				return entry, err
			}
			graph.recordModuleMetadataPath(foreign.source.ID(), metadata)
		} else {
			root = module.Dir
			source := &entry.Dependency.Source
			source.ModulePath, source.Version, source.SourceModule, source.SourceVersion, source.SourceRole = module.Path, module.Version, module.Path, module.Version, "module"
			if module.Main {
				source.SourceRole = "main"
			}
			if module.Replace != nil {
				replacement := module.Replace
				if replacement.Path != input.Original.SourceModule || replacement.Version != input.Original.Version || replacement.Replace != nil || replacement.Main || replacement.Version == "" {
					return entry, fmt.Errorf("original type graph has an unknown/local replacement")
				}
				root = replacement.Dir
				source.SourceModule, source.SourceVersion, source.SourceRole = replacement.Path, replacement.Version, "version_replace"
			} else if input.Original.SourceModule != "" && input.Original.SourceModule != module.Path {
				return entry, fmt.Errorf("original type graph lost its exact archive namespace replacement")
			}
			resolved, err := sourcepath.Resolve(root)
			original, originalErr := sourcepath.Resolve(input.Original.SourceRoot)
			if err != nil || originalErr != nil || resolved != original {
				return entry, fmt.Errorf("actual imported module root differs from the authenticated original source")
			}
			metadata := module.GoMod
			if module.Replace != nil {
				metadata = module.Replace.GoMod
			}
			if err := graph.retainModuleMetadata(input.Original, entry.Dependency.Source, metadata, resolved); err != nil {
				return entry, err
			}
			graph.recordModuleMetadataPath("original", metadata)
		}
	}
	root, err := sourcepath.Resolve(root)
	if err != nil {
		return entry, err
	}
	directory, err := sourcepath.Resolve(pkg.Dir)
	packageDirectory := strings.TrimPrefix(strings.TrimPrefix(pkg.ImportPath, entry.Dependency.Source.ModulePath), "/")
	if packageDirectory == "" {
		packageDirectory = "."
	}
	if err != nil || directory != filepath.Join(root, filepath.FromSlash(packageDirectory)) || len(pkg.CompiledGoFiles) == 0 {
		return entry, fmt.Errorf("actual imported package is not in its stock SDK or exact original module root")
	}
	if len(pkg.GoFiles) > 32768 || len(pkg.CompiledGoFiles) > 32768 {
		return entry, fmt.Errorf("original type graph has an unregistered generated compiler source")
	}
	goFiles := instrumentationTypeNames(pkg.GoFiles, directory, root)
	compiledGoFiles := instrumentationTypeNames(pkg.CompiledGoFiles, directory, root)
	if goFiles == nil || compiledGoFiles == nil || !reflect.DeepEqual(goFiles, compiledGoFiles) {
		return entry, fmt.Errorf("original type graph has an unregistered generated compiler source")
	}
	if foreign != nil {
		entry.SFiles = instrumentationTypeNames(pkg.SFiles, directory, root)
		if entry.SFiles == nil {
			return entry, fmt.Errorf("foreign assembly lost its actual original source selection")
		}
		for _, file := range entry.SFiles {
			if foreign.source.Sources[file] == "" {
				return entry, fmt.Errorf("foreign assembly is absent from its original ZIP source inventory")
			}
			if err := graph.retain(filepath.Join(root, filepath.FromSlash(file))); err != nil {
				return entry, err
			}
			if graph.hashes[filepath.Join(root, filepath.FromSlash(file))] != foreign.source.Sources[file] {
				return entry, fmt.Errorf("foreign selected assembly bytes changed")
			}
		}
	}
	for _, name := range pkg.CompiledGoFiles {
		if !filepath.IsAbs(name) {
			name = filepath.Join(directory, name)
		}
		if err := graph.retain(name); err != nil {
			return entry, err
		}
		rel, err := filepath.Rel(root, graph.paths[name])
		if err != nil || !filepath.IsLocal(rel) || filepath.Dir(rel) != filepath.FromSlash(packageDirectory) {
			return entry, fmt.Errorf("original imported Go bytes have an unbound source role")
		}
		key := filepath.ToSlash(rel)
		if foreign != nil && foreign.source.Sources[key] != graph.hashes[name] {
			return entry, fmt.Errorf("foreign Go bytes differ from their independent original ZIP inventory")
		}
		if pkg.Module != nil && foreign == nil && input.Original.Sources[key] != graph.hashes[name] {
			return entry, fmt.Errorf("imported same-module Go bytes differ from the original ZIP inventory")
		}
		info, err := os.Stat(name)
		if err != nil || info.Size() > instrumentationOriginalFileLimit {
			return entry, fmt.Errorf("original imported compiler source exceeds its byte bound")
		}
		if graph.files[pkg.ImportPath] == nil {
			graph.files[pkg.ImportPath] = make(map[string]string)
		}
		graph.files[pkg.ImportPath][key], entry.Dependency.Source.GoSHA256[key] = name, graph.hashes[name]
	}
	for _, path := range pkg.Imports {
		entry.Dependency.ImportMap[path] = path
	}
	for spelling, target := range pkg.ImportMap {
		if spelling != target {
			delete(entry.Dependency.ImportMap, target)
		}
		entry.Dependency.ImportMap[spelling] = target
	}
	if export {
		if err := graph.retain(pkg.Export); err != nil {
			return entry, fmt.Errorf("original imported package lacks its actual export: %v", err)
		}
		cache, err := sourcepath.Resolve(actual["GOCACHE"])
		rel, relErr := filepath.Rel(cache, graph.paths[pkg.Export])
		if err != nil || relErr != nil || !filepath.IsLocal(rel) {
			return entry, fmt.Errorf("original imported export is outside the actual Go build cache")
		}
		entry.Dependency.Source.ExportSHA256 = graph.hashes[pkg.Export]
	}
	return entry, nil
}

// Metadata outside a legacy archive has a separate signed origin. It never
// becomes a ZIP member or authorizes a namespace alias. Retain both actual Go's
// path and the exact download path so every graph/post-export guard checks them.
func (graph *instrumentationTypeGraph) retainModuleMetadata(input *ConsumerInput, source ImportExport, metadata, root string) error {
	expected := input.Sources["go.mod"]
	if proof := input.ProxyGoMod; proof != nil {
		observed := PackageProof{
			ModulePath: source.ModulePath, ModuleVersion: source.Version,
			SourceModule: source.SourceModule, SourceVersion: source.SourceVersion, SourceRole: source.SourceRole,
			GoModOrigin: proof.Protocol, GoModSHA256: proof.SHA256, GoModSum: proof.GoModSum,
		}
		if err := ValidatePackageModule(input, observed); err != nil {
			return fmt.Errorf("original type graph has an unauthenticated legacy metadata origin: %w", err)
		}
		if _, present := input.Sources["go.mod"]; present || containsString(input.Directories["."], "go.mod") {
			return fmt.Errorf("legacy type metadata cannot impersonate an original ZIP member")
		}
		for _, filename := range []string{metadata, input.ProxyGoModPath} {
			info, err := os.Lstat(filename)
			if err != nil || !filepath.IsAbs(filename) || !info.Mode().IsRegular() {
				return fmt.Errorf("original type proxy metadata lacks a regular absolute observed path")
			}
			if err := graph.retain(filename); err != nil {
				return fmt.Errorf("original type proxy metadata path changed: %w", err)
			}
		}
		if graph.paths[metadata] != graph.paths[input.ProxyGoModPath] {
			return fmt.Errorf("original type proxy metadata differs from its exact download path")
		}
		relative, err := filepath.Rel(root, graph.paths[metadata])
		if err != nil || relative == "." || filepath.IsLocal(relative) {
			return fmt.Errorf("original type proxy metadata must remain outside the original ZIP root")
		}
		expected = proof.SHA256
	}
	if err := graph.retain(metadata); err != nil || expected == "" || graph.hashes[metadata] != expected {
		return fmt.Errorf("original type graph module metadata differs from its authenticated origin: %v", err)
	}
	return nil
}

func (graph *instrumentationTypeGraph) retain(name string) error {
	if !filepath.IsAbs(name) || strings.ContainsAny(name, "\x00\r\n") {
		return fmt.Errorf("actual original source/export has no absolute path")
	}
	resolved, err := sourcepath.Resolve(name)
	if err != nil {
		return err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("actual original source/export is not a regular file")
	}
	digest, err := FileSHA256(resolved)
	if err != nil {
		return err
	}
	if prior := graph.hashes[name]; prior != "" && (prior != digest || graph.paths[name] != resolved) {
		return fmt.Errorf("actual original source/export changed during graph capture")
	}
	graph.hashes[name], graph.paths[name] = digest, resolved
	return nil
}

func retainInstrumentationRequiredTypeSources(input *InstrumentationConsumerInput, proof *InstrumentationTypeSourceProof, captured *instrumentationTypeGraph) error {
	for _, module := range proof.SourceModules {
		for _, header := range module.Headers {
			captured.bytes += len(header)
		}
	}
	copy := *input
	copy.TypeSources = proof
	set := token.NewFileSet()
	root := &instrumentationDeclarationReplay{functions: make(map[string]*ast.FuncDecl), types: make(map[string]*ast.TypeSpec),
		constants: make(map[string]*ast.GenDecl), other: make(map[string]bool), needed: make(map[ast.Node]bool)}
	for _, name := range input.Plan.GoFiles {
		file, err := parser.ParseFile(set, name, input.Sources.Contents[name], 0)
		if err != nil {
			return err
		}
		root.files = append(root.files, file)
		if err := root.index(file); err != nil {
			return err
		}
	}
	graph, err := newInstrumentationTypeReplay(&copy, set, root)
	if err != nil {
		return err
	}
	graph.load = func(pkg *InstrumentationTypeSourcePackage) error {
		files := captured.files[pkg.Dependency.Source.PackagePath]
		if len(files) != len(pkg.Dependency.Source.GoSHA256) {
			return fmt.Errorf("actual original type package lost its complete compiler source paths")
		}
		pkg.Contents = make(map[string]string)
		for name, file := range files {
			data, err := os.ReadFile(file)
			captured.bytes += len(data)
			if err != nil || len(data) > instrumentationOriginalFileLimit || captured.bytes > instrumentationOriginalInventoryLimit ||
				bytesSHA256(data) != pkg.Dependency.Source.GoSHA256[name] {
				return fmt.Errorf("original required imported type bytes changed or exceed their resource bound")
			}
			pkg.Contents[name] = string(data)
		}
		return nil
	}
	for _, function := range root.functions {
		if function.Body == nil && function.Recv == nil {
			if err := root.requireType(function.Type); err != nil {
				return err
			}
		}
	}
	for index := range proof.Dependencies {
		if graph.replays[proof.Dependencies[index].Dependency.Source.PackagePath] == nil {
			proof.Dependencies[index].Contents = nil
		}
	}
	return nil
}
