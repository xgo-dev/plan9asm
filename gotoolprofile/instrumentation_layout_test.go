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

func TestInstrumentationDeclarationReplayClosedOriginalTypesAndConstants(t *testing.T) {
	const source = `package replay
type Element uint16
type Alias = Element
const (
	_ = iota
	Length
	Count = Length + 2
)
type Row struct { Prefix byte; Payload [Count]Alias; Tail uintptr }
type Node struct { Next *Node }
func Probe(row Row, node *Node, text string, data []Alias, z complex64) (word uintptr, ok bool)
`
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(arch, func(t *testing.T) {
			input, pkg, declaration := instrumentationReplayFixture(t, source, arch)
			if err := validateInstrumentationPackageDeclarations(input, pkg, []InstrumentationDeclarationProof{declaration}); err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*plan9asm.FuncSig){
				"argument type":      func(sig *plan9asm.FuncSig) { sig.Args[0] = plan9asm.I8 },
				"argument count":     func(sig *plan9asm.FuncSig) { sig.Args = sig.Args[:len(sig.Args)-1] },
				"parameter offset":   func(sig *plan9asm.FuncSig) { sig.Frame.Params[0].Offset++ },
				"parameter index":    func(sig *plan9asm.FuncSig) { sig.Frame.Params[0].Index++ },
				"parameter field":    func(sig *plan9asm.FuncSig) { sig.Frame.Params[0].Field++ },
				"nested field":       func(sig *plan9asm.FuncSig) { sig.Frame.Params[1].Fields[1]++ },
				"parameter name":     func(sig *plan9asm.FuncSig) { sig.Frame.Params[0].Name = "invented" },
				"return type":        func(sig *plan9asm.FuncSig) { sig.Ret = plan9asm.I8 },
				"result offset":      func(sig *plan9asm.FuncSig) { sig.Frame.Results[0].Offset++ },
				"result type":        func(sig *plan9asm.FuncSig) { sig.Frame.Results[0].Type = plan9asm.I8 },
				"result name":        func(sig *plan9asm.FuncSig) { sig.Frame.Results[0].Name = "invented" },
				"missing parameters": func(sig *plan9asm.FuncSig) { sig.Frame.Params = nil },
				"missing results":    func(sig *plan9asm.FuncSig) { sig.Frame.Results = nil },
			} {
				t.Run(name, func(t *testing.T) {
					changed := declaration
					var layout plan9asm.FuncSig
					if err := json.Unmarshal(declaration.Layout, &layout); err != nil {
						t.Fatal(err)
					}
					mutate(&layout)
					var err error
					changed.Layout, err = json.Marshal(layout)
					if err != nil {
						t.Fatal(err)
					}
					if err := validateInstrumentationPackageDeclarations(input, pkg, []InstrumentationDeclarationProof{changed}); err == nil {
						t.Fatal("paired metadata could invent an ordinary ABI0 layout")
					}
				})
			}
			changed := declaration
			changed.GoType = "func() uint8"
			if err := validateInstrumentationPackageDeclarations(input, pkg, []InstrumentationDeclarationProof{changed}); err == nil {
				t.Fatal("metadata GoType overrode original compiled source")
			}
		})
	}
}

func TestInstrumentationDeclarationReplayRequiresOriginalTargetAndCompleteLocalClosure(t *testing.T) {
	input, pkg, declaration := instrumentationReplayFixture(t, `package replay
type Alias = uintptr
const Count = 3
func Probe(a [Count]Alias) uintptr
`, "arm64")
	input.Plan.Target = "linux/386"
	if err := validateInstrumentationPackageDeclarations(input, pkg, []InstrumentationDeclarationProof{declaration}); err == nil {
		t.Fatal("64-bit metadata supplied a different target gc layout")
	}
	input.Plan.Target = "linux/arm64"
	input.Sources.Contents["replay.go"] = strings.Replace(input.Sources.Contents["replay.go"], "const Count = 3", "const Count = 4", 1)
	if err := validateInstrumentationPackageDeclarations(input, pkg, []InstrumentationDeclarationProof{declaration}); err == nil {
		t.Fatal("unchanged function AST digest concealed an altered constant array layout")
	}
	input.Sources.Contents["replay.go"] = strings.Replace(input.Sources.Contents["replay.go"], "type Alias = uintptr", "", 1)
	if err := validateInstrumentationPackageDeclarations(input, pkg, []InstrumentationDeclarationProof{declaration}); err == nil {
		t.Fatal("missing original local type was supplied by metadata")
	}
}

func TestInstrumentationDeclarationReplayRejectsUnclosedImportedTypesAndConstants(t *testing.T) {
	for name, source := range map[string]string{
		"imported type":            "package replay\nimport external \"example.invalid/external\"\nfunc Probe(a external.Value) uintptr\n",
		"imported constant":        "package replay\nimport external \"example.invalid/external\"\nconst Count = external.Size\nfunc Probe(a [Count]byte) uintptr\n",
		"local unknown type":       "package replay\nfunc Probe(a Missing) uintptr\n",
		"local variable length":    "package replay\nvar Count = 3\nfunc Probe(a [Count]byte) uintptr\n",
		"generic type":             "package replay\ntype Box[T any] struct { Value T }\nfunc Probe(a Box[uint64]) uintptr\n",
		"unbounded constant array": "package replay\nconst Count = 1 << 30\nfunc Probe(a [Count]byte) uintptr\n",
	} {
		t.Run(name, func(t *testing.T) {
			input := &InstrumentationConsumerInput{
				Plan:        &InstrumentationOriginalPackagePlan{Target: "linux/arm64", PackageName: "replay"},
				Sources:     &InstrumentationOriginalSourceInventory{Contents: map[string]string{"replay.go": source}},
				Observation: &InstrumentationExportObservation{Early: &InstrumentationEarlyObservation{BaselineFeatures: &Observation{GoVersion: runtime.Version()}}},
			}
			pkg := PackageProof{PackagePath: "example.invalid/replay", CompiledGoFiles: []string{"replay.go"}}
			declaration := InstrumentationDeclarationProof{Symbol: pkg.PackagePath + ".Probe"}
			if err := replayInstrumentationDeclarationLayouts(input, pkg, []InstrumentationDeclarationProof{declaration}); err == nil {
				t.Fatal("metadata invented an unavailable original source/type/constant closure")
			}
		})
	}
}

func TestInstrumentationDeclarationReplayRetainsCrossFileNamesAndConstantGroups(t *testing.T) {
	const source = `package replay
type uint16 uint64
type Alias = uint16
const (
	_ = iota
	Count
	_ = iota
	Length
)
func Probe(a [Length]Alias) uintptr
`
	input, pkg, declaration := instrumentationReplayFixture(t, source, "arm64")
	declarationSource := "package replay\nfunc Probe(a [Length]Alias) uintptr\n"
	typeSource := strings.Replace(source, declarationSource[len("package replay\n"):], "", 1)
	input.Sources.Contents = map[string]string{"declaration.go": declarationSource, "types.go": typeSource}
	pkg.CompiledGoFiles = []string{"declaration.go", "types.go"}
	declaration.File = "declaration.go"
	if err := validateInstrumentationPackageDeclarations(input, pkg, []InstrumentationDeclarationProof{declaration}); err != nil {
		t.Fatal(err)
	}
	pkg.CompiledGoFiles = pkg.CompiledGoFiles[:1]
	if err := validateInstrumentationPackageDeclarations(input, pkg, []InstrumentationDeclarationProof{declaration}); err == nil {
		t.Fatal("missing compiled sibling source supplied type/constant authority")
	}
}

func TestInstrumentationDeclarationReplayZeroSizedParameterNeedsClosedBuilderAgreement(t *testing.T) {
	input, pkg, declaration := instrumentationReplayFixture(t, "package replay\nfunc Probe(values [0]byte) uint64\n", "arm64")
	err := validateInstrumentationPackageDeclarations(input, pkg, []InstrumentationDeclarationProof{declaration})
	if err == nil || !strings.Contains(err.Error(), "two-builder zero-sized parameter difference") {
		t.Fatalf("known root/CLI ABI0 difference became an accepted layout or invalid source: %v", err)
	}
}

func TestInstrumentationABI0ReplayBoundsZeroSizedAggregateWork(t *testing.T) {
	const source = `package replay
type Huge struct { Empty [4096][4096]struct{}; Last byte }
func Probe(values Huge) uint64
`
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "replay.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := (&types.Config{Sizes: types.SizesFor("gc", "arm64")}).Check("example.invalid/replay", set, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	function := typed.Scope().Lookup("Probe").(*types.Func)
	if err := boundInstrumentationABI0Layout(function.Type().(*types.Signature)); err == nil {
		t.Fatal("empty aggregate slots concealed unbounded recursive ABI0 expansion work")
	}
}

func TestInstrumentationABI0ReplayWorkBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, parameters, result string
		accepted                 bool
	}{
		{"exact total", "[4095]byte", "uint64", true},
		{"over total", "[4096]byte", "uint64", false},
		{"nested exact", "[64][64]byte", "", true},
		{"nested over", "[65][64]byte", "", false},
		{"zero array nested over", "[4096][4096][0]byte", "", false},
		{"deep nesting", strings.Repeat("[1]", 130) + "byte", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "package replay\nfunc Probe(values " + test.parameters + ") " + test.result + "\n"
			set := token.NewFileSet()
			file, err := parser.ParseFile(set, "replay.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			typed, err := (&types.Config{Sizes: types.SizesFor("gc", "arm64")}).Check("example.invalid/replay", set, []*ast.File{file}, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = boundInstrumentationABI0Layout(typed.Scope().Lookup("Probe").Type().(*types.Signature))
			if (err == nil) != test.accepted {
				t.Fatalf("typed source expansion bound = %v, want accepted=%v", err, test.accepted)
			}
		})
	}
}

func instrumentationReplayFixture(t *testing.T, source, arch string) (*InstrumentationConsumerInput, PackageProof, InstrumentationDeclarationProof) {
	t.Helper()
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "replay.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	const packagePath = "example.invalid/replay"
	sizes := types.SizesFor("gc", arch)
	typed, err := (&types.Config{Sizes: sizes}).Check(packagePath, set, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	function := typed.Scope().Lookup("Probe").(*types.Func)
	layout, err := plan9asm.DeriveGoFuncABI0Signature(packagePath+".Probe", function, arch, sizes)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(layout)
	if err != nil {
		t.Fatal(err)
	}
	declaration := InstrumentationDeclarationProof{Symbol: layout.Name, File: "replay.go", GoType: types.TypeString(function.Type(), func(pkg *types.Package) string { return pkg.Path() }), Layout: data}
	for _, node := range file.Decls {
		if function, ok := node.(*ast.FuncDecl); ok && function.Name.Name == "Probe" {
			declaration.DeclarationSHA256, err = ASTSHA(set, function)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	input := &InstrumentationConsumerInput{
		Plan:        &InstrumentationOriginalPackagePlan{Target: "linux/" + arch, PackageName: "replay"},
		Sources:     &InstrumentationOriginalSourceInventory{Contents: map[string]string{"replay.go": source}},
		Observation: &InstrumentationExportObservation{Early: &InstrumentationEarlyObservation{BaselineFeatures: &Observation{GoVersion: runtime.Version()}}},
	}
	return input, PackageProof{PackagePath: packagePath, CompiledGoFiles: []string{"replay.go"}}, declaration
}
