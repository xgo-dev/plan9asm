package gotoolprofile

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func instrumentationImportedReplayFixture(t *testing.T, arch string) (*InstrumentationConsumerInput, PackageProof, InstrumentationDeclarationProof) {
	t.Helper()
	const packagePath = "example.invalid/replay"
	const source = `package replay
import renamed "example.invalid/replay/dep"
type Alias = renamed.Row
const Size = renamed.Count
func Probe(value Alias, bytes [Size]byte) uintptr
`
	const dependency = `package dependency
type Element uint16
type Alias = Element
const (
	_ = iota
	Count
	_ = iota
	Length
)
type Row struct { First byte; Payload [Length]Alias; Last uintptr }
`
	input := &InstrumentationConsumerInput{
		Original: &ConsumerInput{Module: packagePath, Sources: map[string]string{
			"replay.go": bytesSHA256([]byte(source)), "dep/types.go": bytesSHA256([]byte(dependency)),
		}},
		Plan:    &InstrumentationOriginalPackagePlan{Target: "linux/" + arch, PackageName: "replay", PackagePath: packagePath, GoFiles: []string{"replay.go"}},
		Sources: &InstrumentationOriginalSourceInventory{Contents: map[string]string{"replay.go": source}},
		Observation: &InstrumentationExportObservation{Early: &InstrumentationEarlyObservation{
			BaselineFeatures: &Observation{GoVersion: runtime.Version()},
		}},
	}
	input.TypeSources = &InstrumentationTypeSourceProof{
		Protocol: instrumentationTypeSourcesProtocol, InputSHA256: instrumentationTypeSourceInputSHA(input),
		SourceModules: []TestModuleSource{},
		RootImportMap: map[string]string{packagePath + "/dep": packagePath + "/dep"},
		Dependencies: []InstrumentationTypeSourcePackage{{
			Name: "dependency", Contents: map[string]string{"dep/types.go": dependency},
			Dependency: InstrumentationDependencyExport{
				Source: ImportExport{ImportPath: packagePath + "/dep", PackagePath: packagePath + "/dep", ModulePath: packagePath,
					SourceModule: packagePath, SourceRole: "main", ExportSHA256: strings.Repeat("1", 64),
					GoSHA256: map[string]string{"dep/types.go": bytesSHA256([]byte(dependency))}},
				ImportMap: map[string]string{},
			},
		}},
	}
	// Independent full-source go/types establishes the fixture's expected layout;
	// it does not use the filtered replay or metadata signature strings.
	set := token.NewFileSet()
	depAST, err := parser.ParseFile(set, "dep/types.go", dependency, 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", arch)
	dep, err := (&types.Config{Sizes: sizes}).Check(packagePath+"/dep", set, []*ast.File{depAST}, nil)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(set, "replay.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	root, err := (&types.Config{Sizes: sizes, Importer: instrumentationFixtureImporter{dep: dep}}).Check(packagePath, set, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	function := root.Scope().Lookup("Probe").(*types.Func)
	layout, err := plan9asm.DeriveGoFuncABI0Signature(packagePath+".Probe", function, arch, sizes)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(layout)
	if err != nil {
		t.Fatal(err)
	}
	return input, PackageProof{PackagePath: packagePath, CompiledGoFiles: []string{"replay.go"}}, InstrumentationDeclarationProof{
		Symbol: layout.Name, File: "replay.go", GoType: types.TypeString(function.Type(), func(pkg *types.Package) string { return pkg.Path() }), Layout: data,
	}
}

type instrumentationFixtureImporter struct{ dep *types.Package }

func (importer instrumentationFixtureImporter) Import(name string) (*types.Package, error) {
	if name != importer.dep.Path() {
		return nil, types.Error{Msg: "fixture requested an unregistered import"}
	}
	return importer.dep, nil
}

func TestInstrumentationImportedTypeReplayRetainsAliasesConstGroupsAndTargetLayout(t *testing.T) {
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(arch, func(t *testing.T) {
			input, pkg, declaration := instrumentationImportedReplayFixture(t, arch)
			needed, err := InstrumentationRequiresTypeSources(input)
			if err != nil || !needed {
				t.Fatalf("original source did not request its imported closure: %v", err)
			}
			if err := replayInstrumentationDeclarationLayouts(input, pkg, []InstrumentationDeclarationProof{declaration}); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			var roundtrip InstrumentationConsumerInput
			if err := json.Unmarshal(encoded, &roundtrip); err != nil {
				t.Fatal(err)
			}
			if err := replayInstrumentationDeclarationLayouts(&roundtrip, pkg, []InstrumentationDeclarationProof{declaration}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInstrumentationImportedTypeReplayRejectsMissingChangedAndPairedMetadata(t *testing.T) {
	input, pkg, declaration := instrumentationImportedReplayFixture(t, "arm64")
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*InstrumentationConsumerInput){
		"paired deletion":    func(p *InstrumentationConsumerInput) { p.TypeSources = nil },
		"protocol downgrade": func(p *InstrumentationConsumerInput) { p.TypeSources.Protocol = "unverified" },
		"input scope":        func(p *InstrumentationConsumerInput) { p.TypeSources.InputSHA256 = strings.Repeat("2", 64) },
		"target":             func(p *InstrumentationConsumerInput) { p.Plan.Target = "linux/386" },
		"SDK":                func(p *InstrumentationConsumerInput) { p.Observation.Early.BaselineFeatures.GoVersion = "go1.26.1" },
		"module": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Dependency.Source.ModulePath = "example.invalid/foreign"
		},
		"version": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Dependency.Source.Version = "v1.2.3"
		},
		"replace origin": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Dependency.Source.SourceRole = "owned_local_replace"
		},
		"import map missing": func(p *InstrumentationConsumerInput) { p.TypeSources.RootImportMap = map[string]string{} },
		"import map changed": func(p *InstrumentationConsumerInput) {
			p.TypeSources.RootImportMap["example.invalid/replay/dep"] = "unsafe"
		},
		"package name": func(p *InstrumentationConsumerInput) { p.TypeSources.Dependencies[0].Name = "forged" },
		"export missing": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Dependency.Source.ExportSHA256 = ""
		},
		"source missing": func(p *InstrumentationConsumerInput) { p.TypeSources.Dependencies[0].Contents = nil },
		"source changed": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Contents["dep/types.go"] += "\nconst Changed=1\n"
		},
		"paired source hash": func(p *InstrumentationConsumerInput) {
			dep := &p.TypeSources.Dependencies[0]
			dep.Contents["dep/types.go"] = strings.Replace(dep.Contents["dep/types.go"], "Length\n", "Length = 4\n", 1)
			dep.Dependency.Source.GoSHA256["dep/types.go"] = bytesSHA256([]byte(dep.Contents["dep/types.go"]))
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed InstrumentationConsumerInput
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := replayInstrumentationDeclarationLayouts(&changed, pkg, []InstrumentationDeclarationProof{declaration}); err == nil {
				t.Fatal("changed original closure acquired imported declaration authority")
			}
		})
	}
	var layout plan9asm.FuncSig
	if err := json.Unmarshal(declaration.Layout, &layout); err != nil {
		t.Fatal(err)
	}
	layout.Frame.Params[0].Offset++
	declaration.Layout, err = json.Marshal(layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := replayInstrumentationDeclarationLayouts(input, pkg, []InstrumentationDeclarationProof{declaration}); err == nil {
		t.Fatal("paired producer/consumer layout bypassed original imported type replay")
	}
}

func TestInstrumentationImportedTypeMetadataMustConsumeIndependentOriginalExportsAndSources(t *testing.T) {
	input, _, _ := instrumentationImportedReplayFixture(t, "arm64")
	dep := input.TypeSources.Dependencies[0].Dependency
	header := GeneratedHeaderProof{ImportMap: input.TypeSources.RootImportMap}
	for _, mutate := range []func(*InstrumentationDependencyExport){
		func(p *InstrumentationDependencyExport) { p.Source.ExportSHA256 = strings.Repeat("3", 64) },
		func(p *InstrumentationDependencyExport) { p.ImportMap = map[string]string{"unsafe": "unsafe"} },
		func(p *InstrumentationDependencyExport) { p.Source.SourceModule = "example.invalid/other" },
	} {
		data, err := json.Marshal(dep)
		if err != nil {
			t.Fatal(err)
		}
		var changed InstrumentationDependencyExport
		if err := json.Unmarshal(data, &changed); err != nil {
			t.Fatal(err)
		}
		mutate(&changed)
		if err := validateInstrumentationTypeSourceAgreement(input, header, []InstrumentationDependencyExport{changed}); err == nil {
			t.Fatal("paired metadata could replace the independent original input source/export/map")
		}
	}
}
