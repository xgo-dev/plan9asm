package gotoolprofile

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"
)

const InstrumentationNativeHeaderSourcesProtocol = "same_mode_native_header_property_sources_v1"

// This is a separate planning-query input. It cannot supply TypeSources to an
// object consumer, create an outcome, or grant ABI/native-memory permission.
// Physical producers must recapture the complete sources and exports; JSON
// agreement alone does not authenticate any original module or SDK.
type InstrumentationNativeHeaderSourceProof struct {
	Protocol string                          `json:"protocol"`
	Types    *InstrumentationTypeSourceProof `json:"types"`
	GoMods   map[string]string               `json:"original_module_metadata"`
}

func instrumentationHeaderModuleLanguage(text string) (string, error) {
	parsed, err := modfile.Parse("go.mod", []byte(text), nil)
	if err != nil || parsed.Module == nil {
		return "", fmt.Errorf("native property original module language is not closed: %v", err)
	}
	if parsed.Go == nil {
		return "", &nativeHeaderUnsupportedDomain{"native property query does not register the default historical module language"}
	}
	parts := strings.Split(parsed.Go.Version, ".")
	if len(parts) < 2 || parts[0] != "1" {
		return "", fmt.Errorf("native property original module language is not registered")
	}
	language := "go" + strings.Join(parts[:2], ".")
	minor, err := goMinor(language)
	if err != nil || minor < 20 || minor > 27 {
		return "", &nativeHeaderUnsupportedDomain{"native property query does not register this module language"}
	}
	return language, nil
}

func validateInstrumentationHeaderGoMods(input *InstrumentationConsumerInput, proof *InstrumentationNativeHeaderSourceProof) error {
	if proof == nil || proof.Protocol != InstrumentationNativeHeaderSourcesProtocol || proof.Types == nil || proof.GoMods == nil || len(proof.GoMods) > 4097 {
		return fmt.Errorf("same-mode native header query lost its independent original source role")
	}
	if err := ValidateInstrumentationTypeSources(input, proof.Types); err != nil {
		return err
	}
	wanted := map[string]string{"original": input.Original.Sources["go.mod"]}
	if input.Original.ProxyGoMod != nil {
		wanted["original"] = input.Original.ProxyGoMod.SHA256
	}
	for _, source := range proof.Types.SourceModules {
		if source.SourceModule != "" {
			wanted[source.ID()] = source.GoModSHA256
		}
	}
	if len(wanted) != len(proof.GoMods) {
		return fmt.Errorf("native header original module metadata is missing or unconsumed")
	}
	var total int
	for id, digest := range wanted {
		text, present := proof.GoMods[id]
		total += len(text)
		if !present || len(text) > instrumentationOriginalFileLimit || total > instrumentationOriginalInventoryLimit || digest == "" || bytesSHA256([]byte(text)) != digest {
			return fmt.Errorf("native header original module metadata bytes changed: %s", id)
		}
		parsed, err := modfile.Parse("go.mod", []byte(text), nil)
		if err != nil || parsed.Module == nil {
			return fmt.Errorf("native header original module metadata is invalid: %v", err)
		}
		if id == "original" {
			if parsed.Module.Mod.Path != input.Original.Module {
				return fmt.Errorf("native header original declared module namespace changed")
			}
		}
		// Foreign logical Module.Path and replacement archive namespaces need
		// not coincide. Their actual roles and exact metadata origin are bound
		// by the existing type-source resource validator, not guessed here.
	}
	return nil
}

func instrumentationNativeHeaderReplay(input *InstrumentationConsumerInput, proof *InstrumentationNativeHeaderSourceProof,
	load func(*InstrumentationTypeSourcePackage) error,
) (*instrumentationTypeReplay, *instrumentationDeclarationReplay, *nativeHeaderGCSizes, string, error) {
	if err := validateInstrumentationHeaderGoMods(input, proof); err != nil {
		return nil, nil, nil, "", err
	}
	language, err := instrumentationHeaderModuleLanguage(proof.GoMods["original"])
	if err != nil {
		return nil, nil, nil, "", err
	}
	_, arch, valid := strings.Cut(input.Plan.Target, "/")
	word := int64(8)
	switch arch {
	case "386", "arm":
		word = 4
	case "amd64", "arm64", "wasm":
	default:
		valid = false
	}
	if !valid {
		return nil, nil, nil, "", fmt.Errorf("same-mode native header query has an unknown target")
	}
	set := token.NewFileSet()
	root := &instrumentationDeclarationReplay{functions: make(map[string]*ast.FuncDecl), types: make(map[string]*ast.TypeSpec),
		constants: make(map[string]*ast.GenDecl), other: make(map[string]bool), needed: make(map[ast.Node]bool)}
	for _, name := range input.Plan.GoFiles {
		text, found := input.Sources.Contents[name]
		if !found || bytesSHA256([]byte(text)) != input.Original.Sources[name] {
			return nil, nil, nil, "", fmt.Errorf("native header selected original Go bytes changed")
		}
		file, err := parser.ParseFile(set, name, text, 0)
		if err != nil || file.Name.Name != input.Plan.PackageName {
			return nil, nil, nil, "", fmt.Errorf("native header selected original package changed: %v", err)
		}
		root.files = append(root.files, file)
		if err := root.index(file); err != nil {
			return nil, nil, nil, "", err
		}
	}
	copy := *input
	copy.TypeSources = proof.Types
	graph, err := newInstrumentationTypeReplay(&copy, set, root)
	if err != nil {
		return nil, nil, nil, "", err
	}
	sizes := &nativeHeaderGCSizes{word: word, cache: make(map[types.Type]nativeHeaderLayout), active: make(map[types.Type]bool)}
	graph.load, graph.nativeSizes = load, sizes
	graph.language = func(source ImportExport) (string, error) {
		if source.SourceRole == "stdlib" {
			minor, err := goMinor(input.Observation.Early.BaselineFeatures.GoVersion)
			return fmt.Sprintf("go1.%d", minor), err
		}
		if source.ModulePath == input.Original.Module && source.Version == input.Original.Version {
			return language, nil
		}
		for _, module := range proof.Types.SourceModules {
			if module.SourceModule == source.SourceModule && module.SourceVersion == source.SourceVersion {
				return instrumentationHeaderModuleLanguage(proof.GoMods[module.ID()])
			}
		}
		return "", fmt.Errorf("native header dependency has no authenticated module language")
	}
	// Header properties include every original constant and named struct, not
	// merely names reachable from a bodyless assembly signature. Their imported
	// closure is selected by the same existing declaration graph.
	if err := requireNativeHeaderRoots(root); err != nil {
		return nil, nil, nil, "", err
	}
	if err := boundInstrumentationHeaderStrings(graph); err != nil {
		return nil, nil, nil, "", err
	}
	return graph, root, sizes, language, nil
}

// A qualified constant can itself be a lazy string DAG. Charge it through the
// original per-file ImportMap before any go/types or ExactString evaluation;
// independently checking each package would miss root-level duplication of an
// imported string. The same existing resource budget handles the expressions.
func boundInstrumentationHeaderStrings(graph *instrumentationTypeReplay) error {
	budgets := make(map[string]*nativeHeaderStringBudget)
	for target, replay := range graph.replays {
		budget, err := newNativeHeaderStringBudget(replay.selectedFiles())
		if err != nil {
			return err
		}
		budgets[target] = budget
	}
	for target := range graph.replays {
		replay := graph.replays[target] // Private closures must also be correct on Go 1.20.
		budget := budgets[target]
		importMap := graph.proof.RootImportMap
		if target != graph.input.Plan.PackagePath {
			for _, dependency := range graph.proof.Dependencies {
				if dependency.Dependency.Source.PackagePath == target {
					importMap = dependency.Dependency.ImportMap
					break
				}
			}
		}
		budget.selector = func(expression *ast.SelectorExpr) (uint64, error) {
			qualifier, ok := expression.X.(*ast.Ident)
			if !ok {
				return 0, fmt.Errorf("native property string selector is not a direct original import")
			}
			for _, file := range replay.files {
				if expression.Pos() < file.Pos() || expression.End() > file.End() {
					continue
				}
				for _, spec := range file.Imports {
					spelling, err := strconv.Unquote(spec.Path.Value)
					if err != nil {
						return 0, err
					}
					child := importMap[spelling]
					name := "unsafe"
					for _, dependency := range graph.proof.Dependencies {
						if dependency.Dependency.Source.PackagePath == child {
							name = dependency.Name
							break
						}
					}
					if spec.Name != nil {
						name = spec.Name.Name
					}
					if name != qualifier.Name {
						continue
					}
					if child == "unsafe" {
						return 0, nil // The unchanged typechecker verifies its numeric operation.
					}
					if budgets[child] == nil {
						return 0, fmt.Errorf("native property string selector lost its original closure")
					}
					return budgets[child].expression(&ast.Ident{Name: expression.Sel.Name}, 0)
				}
			}
			return 0, fmt.Errorf("native property string selector lost its file-local import")
		}
	}
	for target, replay := range graph.replays {
		if err := budgets[target].check(replay.selectedFiles()); err != nil {
			return err
		}
	}
	return nil
}

// ReplayInstrumentationNativeGeneratedHeader independently derives properties
// from original module language, selected Go bytes, and imported declarations.
// It queries values only; the actual compiler header and final object consumer
// must still independently agree under this exact mode/CPU/source selection.
func ReplayInstrumentationNativeGeneratedHeader(input *InstrumentationConsumerInput, proof *InstrumentationNativeHeaderSourceProof) (map[string]string, string, error) {
	graph, root, sizes, language, err := instrumentationNativeHeaderReplay(input, proof, nil)
	if err != nil {
		return nil, "", err
	}
	config := &types.Config{Sizes: sizes, GoVersion: language, IgnoreFuncBodies: true,
		Importer: instrumentationTypeImporter{graph: graph, importMap: proof.Types.RootImportMap}}
	pkg, err := config.Check(input.Plan.PackagePath, graph.set, root.selectedFiles(), nil)
	if err != nil || sizes.err != nil {
		return nil, "", fmt.Errorf("same-mode native header declaration replay failed: %v %v", err, sizes.err)
	}
	definitions, err := nativeGeneratedHeaderDefinitions(pkg, sizes)
	return definitions, language, err
}
