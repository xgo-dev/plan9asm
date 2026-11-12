package gotoolprofile

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/module"
)

const InstrumentationTypeSourcesProtocol = "actual_go_instrumentation_type_sources_v2"
const instrumentationTypeSourcesProtocol = InstrumentationTypeSourcesProtocol

// This input is captured before metadata and independently recaptured by its
// actual consumer. Digests alone, or two agreeing metadata records, cannot
// authenticate a source root. ZIP authentication and a trusted stock SDK are
// still prerequisites. Only required imported type/constant packages retain
// complete compiler-source bytes; all reachable exports/ImportMaps are bound.
type InstrumentationTypeSourceProof struct {
	Protocol      string                             `json:"protocol"`
	InputSHA256   string                             `json:"input_sha256"`
	UnsafeSHA256  string                             `json:"builtin_unsafe_source_sha256,omitempty"`
	RootImportMap map[string]string                  `json:"root_import_map"`
	Dependencies  []InstrumentationTypeSourcePackage `json:"dependencies"`
	SourceModules []TestModuleSource                 `json:"source_only_modules"`
}

type InstrumentationTypeSourcePackage struct {
	Name         string                          `json:"package_name"`
	Dependency   InstrumentationDependencyExport `json:"dependency"`
	Contents     map[string]string               `json:"contents,omitempty"`
	SourceRootID string                          `json:"source_root_id,omitempty"`
	SFiles       []string                        `json:"selected_source_only_assembly"`
}

func instrumentationTypeSourceInputSHA(input *InstrumentationConsumerInput) string {
	if input == nil {
		return ""
	}
	copy := *input
	copy.TypeSources = nil
	return InstrumentationConsumerInputSHA256(&copy)
}

// This predicate only requests capture cost. It grants no selector, layout or
// source role: all original declarations must still pass the actual source
// capture and the independently replayed imported AST closure.
func InstrumentationRequiresTypeSources(input *InstrumentationConsumerInput) (bool, error) {
	if input == nil || input.Plan == nil || input.Sources == nil {
		return false, fmt.Errorf("missing original type-source planning input")
	}
	replay := &instrumentationDeclarationReplay{functions: make(map[string]*ast.FuncDecl), types: make(map[string]*ast.TypeSpec),
		constants: make(map[string]*ast.GenDecl), other: make(map[string]bool), needed: make(map[ast.Node]bool)}
	found := false
	replay.selector = func(*ast.SelectorExpr) error { found = true; return nil }
	for _, name := range input.Plan.GoFiles {
		file, err := parser.ParseFile(token.NewFileSet(), name, input.Sources.Contents[name], 0)
		if err != nil {
			return false, err
		}
		if err := replay.index(file); err != nil {
			return false, err
		}
	}
	for _, function := range replay.functions {
		if function.Body == nil && function.Recv == nil {
			if err := replay.requireType(function.Type); err != nil {
				return false, err
			}
		}
	}
	return found, nil
}

func ValidateInstrumentationTypeSources(input *InstrumentationConsumerInput, proof *InstrumentationTypeSourceProof) error {
	if input == nil || input.Plan == nil || input.Original == nil || input.Observation == nil || input.Observation.Early == nil || input.Observation.Early.BaselineFeatures == nil || proof == nil ||
		proof.Protocol != instrumentationTypeSourcesProtocol || proof.InputSHA256 != instrumentationTypeSourceInputSHA(input) ||
		proof.RootImportMap == nil || len(proof.RootImportMap) > 4096 || proof.Dependencies == nil || len(proof.Dependencies) > 4096 {
		return fmt.Errorf("original imported type source lost its independent input/scope identity")
	}
	if input.Sources == nil {
		return fmt.Errorf("original import graph lacks complete selected Go source")
	}
	if err := validateInstrumentationTypeModuleCoverage(input, proof); err != nil {
		return err
	}
	if err := validateInstrumentationOriginalImportSpellings(input.Plan.GoFiles, input.Sources.Contents, proof.RootImportMap); err != nil {
		return err
	}
	dependencies := make([]InstrumentationDependencyExport, 0, len(proof.Dependencies))
	header := GeneratedHeaderProof{ImportMap: proof.RootImportMap}
	byPath := make(map[string]InstrumentationDependencyExport)
	total := 0
	for _, module := range proof.SourceModules {
		for _, header := range module.Headers {
			total += len(header)
		}
	}
	unsafeNeeded := proof.RootImportMap["unsafe"] == "unsafe"
	if !sort.SliceIsSorted(proof.Dependencies, func(i, j int) bool {
		return proof.Dependencies[i].Dependency.Source.PackagePath < proof.Dependencies[j].Dependency.Source.PackagePath
	}) {
		return fmt.Errorf("original imported type packages are not canonical")
	}
	for _, pkg := range proof.Dependencies {
		dep := pkg.Dependency
		if dep.ImportMap["unsafe"] == "unsafe" {
			unsafeNeeded = true
		}
		if !token.IsIdentifier(pkg.Name) || pkg.Name == "_" {
			return fmt.Errorf("original imported package lacks its actual source name")
		}
		for name, contents := range pkg.Contents {
			total += len(contents)
			if len(contents) > instrumentationOriginalFileLimit || total > instrumentationOriginalInventoryLimit ||
				bytesSHA256([]byte(contents)) != dep.Source.GoSHA256[name] || strings.ContainsRune(contents, '\x00') {
				return fmt.Errorf("original imported declaration source changed or exceeds its byte bound")
			}
		}
		if pkg.Contents != nil && len(pkg.Contents) != len(dep.Source.GoSHA256) {
			return fmt.Errorf("imported declaration package lacks complete actual compiled source bytes")
		}
		if pkg.Contents != nil {
			names := make([]string, 0, len(dep.Source.GoSHA256))
			for name := range dep.Source.GoSHA256 {
				names = append(names, name)
			}
			if err := validateInstrumentationOriginalImportSpellings(names, pkg.Contents, dep.ImportMap); err != nil {
				return err
			}
		}
		dependencies = append(dependencies, dep)
		byPath[dep.Source.PackagePath] = dep
	}
	if unsafeNeeded != (proof.UnsafeSHA256 != "") || proof.UnsafeSHA256 != "" && !discoverySHA256Pattern.MatchString(proof.UnsafeSHA256) {
		return fmt.Errorf("original type graph lost or invented the actual SDK builtin unsafe source identity")
	}
	for spelling, target := range proof.RootImportMap {
		if target == "unsafe" {
			continue
		}
		dep := byPath[target].Source
		dep.ImportPath = spelling
		header.Imports = append(header.Imports, dep)
	}
	pkg := PackageProof{PackagePath: input.Plan.PackagePath, SourceModule: input.Original.Module,
		SourceVersion: input.Original.Version, SourceRole: "main"}
	if input.Original.SourceModule != "" {
		pkg.SourceRole = "module"
		pkg.SourceModule = input.Original.SourceModule
		if input.Original.SourceModule != input.Original.Module {
			pkg.SourceRole = "version_replace"
		}
	}
	copy := *input
	copy.TypeSources = proof
	return validateInstrumentationMetadataDependencies(&copy, pkg, header, dependencies)
}

// The physical capture supplies each ImportMap's targets. Independently bound
// source bytes supply its exact spelling set, including imports used only by
// bodies, blank imports and repeated spellings across selected files. A paired
// metadata mutation cannot invent an unused edge to an already present export.
func validateInstrumentationOriginalImportSpellings(names []string, contents map[string]string, importMap map[string]string) error {
	if len(names) == 0 {
		return fmt.Errorf("original import graph has no selected compiler Go files")
	}
	imports := make(map[string]bool)
	for _, name := range names {
		source, present := contents[name]
		if !present {
			return fmt.Errorf("original import graph lost selected Go source: %s", name)
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, source, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("original import syntax changed: %w", err)
		}
		for _, spec := range file.Imports {
			spelling, err := strconv.Unquote(spec.Path.Value)
			if err != nil || module.CheckImportPath(spelling) != nil {
				return fmt.Errorf("original source has a noncanonical import spelling")
			}
			imports[spelling] = true
		}
	}
	if len(imports) != len(importMap) {
		return fmt.Errorf("original source/import-map spelling sets differ")
	}
	for spelling := range importMap {
		if !imports[spelling] {
			return fmt.Errorf("original import-map spelling is absent from selected Go bytes: %s", spelling)
		}
	}
	return nil
}

type instrumentationTypeReplay struct {
	input   *InstrumentationConsumerInput
	set     *token.FileSet
	proof   *InstrumentationTypeSourceProof
	replays map[string]*instrumentationDeclarationReplay
	typed   map[string]*types.Package
	active  map[string]bool
	load    func(*InstrumentationTypeSourcePackage) error // Actual capture only; never restored from JSON.
	// Only the separate query-only native-header role supplies these. Existing
	// metadata/ABI replay retains its original SizesFor and SDK-language rules.
	nativeSizes *nativeHeaderGCSizes
	language    func(ImportExport) (string, error)
}

func newInstrumentationTypeReplay(input *InstrumentationConsumerInput, set *token.FileSet, root *instrumentationDeclarationReplay) (*instrumentationTypeReplay, error) {
	if input.TypeSources == nil {
		return nil, nil // The original strict selector error remains in place.
	}
	if err := ValidateInstrumentationTypeSources(input, input.TypeSources); err != nil {
		return nil, err
	}
	graph := &instrumentationTypeReplay{input: input, set: set, proof: input.TypeSources,
		replays: map[string]*instrumentationDeclarationReplay{input.Plan.PackagePath: root},
		typed:   make(map[string]*types.Package), active: make(map[string]bool)}
	root.selector = func(expression *ast.SelectorExpr) error {
		return graph.requireSelector(root, graph.proof.RootImportMap, expression)
	}
	return graph, nil
}

func (graph *instrumentationTypeReplay) dependency(target string) (*instrumentationDeclarationReplay, map[string]string, error) {
	for index := range graph.proof.Dependencies {
		pkg := &graph.proof.Dependencies[index]
		if pkg.Dependency.Source.PackagePath != target {
			continue
		}
		if len(pkg.Contents) == 0 {
			if graph.load == nil {
				return nil, nil, fmt.Errorf("original declaration needs an authenticated imported type/constant closure: %s", target)
			}
			if err := graph.load(pkg); err != nil {
				return nil, nil, err
			}
		}
		if prior := graph.replays[target]; prior != nil {
			return prior, pkg.Dependency.ImportMap, nil
		}
		replay := &instrumentationDeclarationReplay{functions: make(map[string]*ast.FuncDecl), types: make(map[string]*ast.TypeSpec),
			constants: make(map[string]*ast.GenDecl), other: make(map[string]bool), needed: make(map[ast.Node]bool)}
		var names []string
		for name := range pkg.Contents {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			file, err := parser.ParseFile(graph.set, target+"/"+name, pkg.Contents[name], 0)
			if err != nil || file.Name.Name != pkg.Name {
				return nil, nil, fmt.Errorf("original imported declaration package has changed syntax/role: %v", err)
			}
			replay.files = append(replay.files, file)
			if err := replay.index(file); err != nil {
				return nil, nil, err
			}
		}
		graph.replays[target] = replay
		replay.selector = func(expression *ast.SelectorExpr) error {
			return graph.requireSelector(replay, pkg.Dependency.ImportMap, expression)
		}
		return replay, pkg.Dependency.ImportMap, nil
	}
	return nil, nil, fmt.Errorf("original import omitted its independently observed package: %s", target)
}

func (graph *instrumentationTypeReplay) requireSelector(replay *instrumentationDeclarationReplay, importMap map[string]string, expression *ast.SelectorExpr) error {
	qualifier, ok := expression.X.(*ast.Ident)
	if !ok || !token.IsExported(expression.Sel.Name) {
		return fmt.Errorf("original selector lacks a direct exported import identity")
	}
	for _, file := range replay.files {
		if expression.Pos() < file.Pos() || expression.End() > file.End() {
			continue
		}
		for _, spec := range file.Imports {
			spelling, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			target := importMap[spelling]
			name := "unsafe"
			if target != "unsafe" {
				name = ""
				for _, pkg := range graph.proof.Dependencies {
					if pkg.Dependency.Source.PackagePath == target {
						name = pkg.Name
						break
					}
				}
			}
			if spec.Name != nil {
				name = spec.Name.Name
			}
			if name != qualifier.Name {
				continue
			}
			if target == "" || spelling == "unsafe" && target != "unsafe" {
				return fmt.Errorf("original selector has no actual ImportMap edge")
			}
			replay.needed[spec] = true
			if target == "unsafe" {
				if types.Unsafe.Scope().Lookup(expression.Sel.Name) == nil {
					return fmt.Errorf("unknown builtin unsafe selector")
				}
				return nil
			}
			child, _, err := graph.dependency(target)
			if err != nil {
				return err
			}
			return child.requireName(expression.Sel.Name)
		}
	}
	return fmt.Errorf("original selector has no closed file-local import: %s", qualifier.Name)
}

type instrumentationTypeImporter struct {
	graph     *instrumentationTypeReplay
	importMap map[string]string
}

func (importer instrumentationTypeImporter) Import(name string) (*types.Package, error) {
	graph := importer.graph
	// No filename or prefix inference: every package owns its observed map.
	target := importer.importMap[name]
	if target == "unsafe" && name == "unsafe" {
		return types.Unsafe, nil
	}
	if target == "" || graph.active[target] {
		return nil, fmt.Errorf("original imported type graph has a missing edge or cycle")
	}
	if typed := graph.typed[target]; typed != nil {
		return typed, nil
	}
	replay, importMap, err := graph.dependency(target)
	if err != nil {
		return nil, err
	}
	_, arch, _ := strings.Cut(graph.input.Plan.Target, "/")
	minor, err := goMinor(graph.input.Observation.Early.BaselineFeatures.GoVersion)
	if err != nil {
		return nil, err
	}
	graph.active[target] = true
	defer delete(graph.active, target)
	config := types.Config{Sizes: types.SizesFor("gc", arch), GoVersion: fmt.Sprintf("go1.%d", minor), IgnoreFuncBodies: true,
		Importer: instrumentationTypeImporter{graph: graph, importMap: importMap}}
	if graph.nativeSizes != nil {
		config.Sizes = graph.nativeSizes
		for _, dependency := range graph.proof.Dependencies {
			if dependency.Dependency.Source.PackagePath == target {
				config.GoVersion, err = graph.language(dependency.Dependency.Source)
				if err != nil {
					return nil, err
				}
				break
			}
		}
		if err := boundNativeHeaderStrings(replay.selectedFiles()); err != nil {
			return nil, err
		}
	}
	typed, err := config.Check(target, graph.set, replay.selectedFiles(), nil)
	if err != nil {
		return nil, fmt.Errorf("original imported type/constant closure is not independently closed: %w", err)
	}
	graph.typed[target] = typed
	return typed, nil
}

// Verify that metadata consumes the pre-query source capture, not a paired
// export/hash replacement. Every actual dependency and root spelling remains.
func validateInstrumentationTypeSourceAgreement(input *InstrumentationConsumerInput, header GeneratedHeaderProof, dependencies []InstrumentationDependencyExport) error {
	if input.TypeSources == nil {
		return nil
	}
	if err := ValidateInstrumentationTypeSources(input, input.TypeSources); err != nil {
		return err
	}
	wanted := make([]InstrumentationDependencyExport, 0, len(input.TypeSources.Dependencies))
	for _, pkg := range input.TypeSources.Dependencies {
		wanted = append(wanted, pkg.Dependency)
	}
	if !reflect.DeepEqual(input.TypeSources.RootImportMap, header.ImportMap) || !reflect.DeepEqual(wanted, dependencies) {
		return fmt.Errorf("actual metadata dependency origins/source/export/importmap differ from original type capture")
	}
	return nil
}
