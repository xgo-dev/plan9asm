package plan9asm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func goAMD64FrameTypedFixture(t *testing.T, declaration, assembly string) (GoPackage, GoAMD64FrameCaptureRequest) {
	t.Helper()
	_, request := goAMD64FrameSourceFixture(t)
	source := []byte("package framefixture\n" + declaration + "\n")
	filename := filepath.Join(request.Directory, "value.go")
	if err := os.WriteFile(filename, source, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := (&types.Config{Sizes: types.SizesFor("gc", "amd64")}).Check("example.invalid/framefixture", fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{file}}, request
}

func TestGoAMD64FrameTypedSourceSliceObservation(t *testing.T) {
	pkg, request := goAMD64FrameTypedFixture(t, "func Value(a []byte, n uint64) uint64", "#include \"textflag.h\"\nTEXT ·Value(SB),NOSPLIT,$160-40\nMOVQ n+24(FP),AX\nMOVQ AX,16(SP)\nMOVQ 16(SP),AX\nMOVQ AX,ret+32(FP)\nRET\n")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	fn := source.functions[pkg.Path+".Value"]
	if fn.args != 40 || fn.locals != 168 || len(fn.signature.Frame.Params) != 4 || fn.signature.Frame.Results[0].Offset != 32 {
		t.Fatalf("actual slice observation lost complete original ABI0 frame: %+v", fn)
	}
	if fn.transport != goAMD64FrameCompositeTransport || fn.languageType == "" {
		t.Fatal("slice observation lost its nonnumeric transport role")
	}
	for i, slot := range fn.signature.Frame.Params[:3] {
		if slot.Offset != int64(i*8) || slot.Index != 0 || slot.Field != i {
			t.Fatalf("slice field %d has an invented offset/identity: %+v", i, slot)
		}
	}
	if !errors.Is(source.numericDeclarations(pkg), ErrProbeNeedsContext) {
		t.Fatal("slice observation entered the numeric-only fixed-local contract")
	}
}

func TestGoAMD64FrameTypedSourceActualLayoutMatrix(t *testing.T) {
	for _, test := range []struct {
		name, declaration string
		args              int64
		params, results   []int64
		role              goAMD64FrameTransport
	}{
		{"integer widths", "func Value(a int8, b uint8, c int16, d uint16, e int32, f uint32, g int64, h uint64, i int, j uint, k uintptr) (r uint64)", 64, []int64{0, 1, 2, 4, 8, 12, 16, 24, 32, 40, 48}, []int64{56}, goAMD64FrameNumericTransport},
		{"named integer", "type Count uint64\nfunc Value(a Count) Count", 16, []int64{0}, []int64{8}, goAMD64FrameNumericTransport},
		{"integer alias", "type Count = uint64\nfunc Value(a Count) Count", 16, []int64{0}, []int64{8}, goAMD64FrameNumericTransport},
		{"pointer", "func Value(a *uint64, n uint64) uint64", 24, []int64{0, 8}, []int64{16}, goAMD64FrameCompositeTransport},
		{"pointer to array", "func Value(a *[64]byte, n uint64) uint64", 24, []int64{0, 8}, []int64{16}, goAMD64FrameCompositeTransport},
		{"nested fields", "type Packet struct { Tag byte; Samples [3]int16; Tail uint64 }\nfunc Value(a *Packet, n uint64) uint64", 24, []int64{0, 8}, []int64{16}, goAMD64FrameCompositeTransport},
		{"nested pointer fields", "type Packet struct { P *[4]uint16; S []uint32 }\nfunc Value(a *Packet, n uint64) uint64", 24, []int64{0, 8}, []int64{16}, goAMD64FrameCompositeTransport},
		{"named pointer", "type Pointer *uint64\nfunc Value(a Pointer, n uint64) uint64", 24, []int64{0, 8}, []int64{16}, goAMD64FrameCompositeTransport},
		{"pointer alias", "type Pointer = *uint64\nfunc Value(a Pointer, n uint64) uint64", 24, []int64{0, 8}, []int64{16}, goAMD64FrameCompositeTransport},
		{"slice integer", "func Value(a []int32, n uint64) uint64", 40, []int64{0, 8, 16, 24}, []int64{32}, goAMD64FrameCompositeTransport},
		{"slice pointer", "func Value(a []*uint64, n uint64) uint64", 40, []int64{0, 8, 16, 24}, []int64{32}, goAMD64FrameCompositeTransport},
		{"named slice", "type Bytes []byte\nfunc Value(a Bytes, n uint64) uint64", 40, []int64{0, 8, 16, 24}, []int64{32}, goAMD64FrameCompositeTransport},
		{"slice alias", "type Bytes = []byte\nfunc Value(a Bytes, n uint64) uint64", 40, []int64{0, 8, 16, 24}, []int64{32}, goAMD64FrameCompositeTransport},
		{"pointer result", "func Value(a *uint64, n uint64) *uint64", 24, []int64{0, 8}, []int64{16}, goAMD64FrameCompositeTransport},
		{"slice result", "func Value(a []byte, n uint64) []byte", 56, []int64{0, 8, 16, 24}, []int64{32, 40, 48}, goAMD64FrameCompositeTransport},
		{"mixed results", "func Value(a *uint64, n int32) (p *uint64, count uint32)", 32, []int64{0, 8}, []int64{16, 24}, goAMD64FrameCompositeTransport},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Object capture does not execute the body or claim initialized
			// results/GC safety. The independent ABI0 offsets are the oracle.
			assembly := fmt.Sprintf("TEXT ·Value(SB),4,$160-%d\nRET\n", test.args)
			pkg, request := goAMD64FrameTypedFixture(t, test.declaration, assembly)
			source := requireGoAMD64FrameCapture(t, pkg, request)
			fn := source.functions[pkg.Path+".Value"]
			if fn.args != test.args || fn.locals != 168 || fn.transport != test.role || fn.languageType == "" {
				t.Fatalf("actual object/transport mismatch: %+v", fn)
			}
			check := func(slots []FrameSlot, offsets []int64) {
				t.Helper()
				if len(slots) != len(offsets) {
					t.Fatalf("complete ABI0 slots differ: %+v; want %v", slots, offsets)
				}
				for i, slot := range slots {
					if slot.Offset != offsets[i] {
						t.Fatalf("ABI0 slot %d is %+v; want offset %d", i, slot, offsets[i])
					}
				}
			}
			check(fn.signature.Frame.Params, test.params)
			check(fn.signature.Frame.Results, test.results)
			object := filepath.Join(source.owned, request.AssemblyFile+".o")
			t.Logf("actual stock-Go observation: target=%s object_sha=%x listing_sha=%x code_bytes=%d args=%d locals=%d transport=%d", request.Target, source.inputs[object], source.inputs[object+".listing"], len(fn.code), fn.args, fn.locals, fn.transport)
			err := source.numericDeclarations(pkg)
			if test.role == goAMD64FrameNumericTransport && err != nil || test.role != goAMD64FrameNumericTransport && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("numeric-only consumer role mismatch: %v", err)
			}
		})
	}
}

func goAMD64FrameTypedSelection(t *testing.T, pkg GoPackage, request GoAMD64FrameCaptureRequest) *GoAMD64FrameSource {
	t.Helper()
	// The production capture entry resolves the source root before binding
	// selection paths. This internal fixture must exercise that same contract,
	// including temporary-directory aliases supplied by the host OS.
	canonical, err := filepath.EvalSymlinks(request.Directory)
	if err != nil {
		t.Fatal(err)
	}
	request.Directory = canonical
	return &GoAMD64FrameSource{
		request: request, inputs: make(map[string][32]byte),
		selection: goAMD64FrameSelection{GoFiles: []string{"value.go"}, CompiledGoFiles: []string{filepath.Join(request.Directory, "value.go")}},
	}
}

func TestGoAMD64FrameTypedSelectionCanonicalSourceRoot(t *testing.T) {
	pkg, request := goAMD64FrameTypedFixture(t, "func Value(a *uint64) uint64", "TEXT ·Value(SB),4,$160-16\nRET\n")
	canonical, err := filepath.EvalSymlinks(request.Directory)
	if err != nil {
		t.Fatal(err)
	}
	source := goAMD64FrameTypedSelection(t, pkg, request)
	if source.request.Directory != canonical || len(source.selection.CompiledGoFiles) != 1 ||
		source.selection.CompiledGoFiles[0] != filepath.Join(canonical, "value.go") {
		t.Fatal("typed fixture did not bind the production entry's canonical source root")
	}
	if _, err := source.typedDeclarations(pkg, false); err != nil {
		t.Fatalf("canonical source must reach the independent language check: %v", err)
	}
}

func TestGoAMD64FrameTypedSourceLanguageIdentityMutations(t *testing.T) {
	for _, test := range []struct{ name, original, mutation string }{
		{"same pointer width", "func Value(a *uint64) uint64", "func Value(a *int64) uint64"},
		{"slice element", "func Value(a []byte) uint64", "func Value(a []uint16) uint64"},
		{"slice versus pointer", "func Value(a []byte) uint64", "func Value(a *byte) uint64"},
		{"array length", "func Value(a *[16]byte) uint64", "func Value(a *[32]byte) uint64"},
		{"named underlying", "type Count uint64\nfunc Value(a *Count) uint64", "type Count int64\nfunc Value(a *Count) uint64"},
		{"alias versus named", "type Count = uint64\nfunc Value(a *Count) uint64", "type Count uint64\nfunc Value(a *Count) uint64"},
		{"alias RHS identity", "type A uint64\ntype B uint64\ntype Choice = A\nfunc Value(a *Choice) uint64", "type A uint64\ntype B uint64\ntype Choice = B\nfunc Value(a *Choice) uint64"},
		{"field signedness", "type Packet struct { X uint64 }\nfunc Value(a *Packet) uint64", "type Packet struct { X int64 }\nfunc Value(a *Packet) uint64"},
		{"field identity", "type Packet struct { X uint64 }\nfunc Value(a *Packet) uint64", "type Packet struct { Y uint64 }\nfunc Value(a *Packet) uint64"},
		{"field order", "type Packet struct { X byte; Y uint64 }\nfunc Value(a *Packet) uint64", "type Packet struct { Y uint64; X byte }\nfunc Value(a *Packet) uint64"},
		{"field tag", "type Packet struct { X uint64 `a` }\nfunc Value(a *Packet) uint64", "type Packet struct { X uint64 `b` }\nfunc Value(a *Packet) uint64"},
		{"embedded identity", "type Count uint64\ntype Packet struct { Count }\nfunc Value(a *Packet) uint64", "type Count uint64\ntype Packet struct { Count Count }\nfunc Value(a *Packet) uint64"},
		{"parameter name", "func Value(a *uint64) uint64", "func Value(b *uint64) uint64"},
		{"result pointee", "func Value(a *uint64) *uint64", "func Value(a *uint64) *int64"},
		{
			"unrelated interface does not hide signedness",
			"type XOF interface { Clone() XOF }\nfunc Value(a *uint64) uint64",
			"type XOF interface { Clone() XOF }\nfunc Value(a *int64) uint64",
		},
		{
			"unrelated recursive type does not hide extent",
			"type Node struct { Next *Node }\nfunc Value(a *[16]byte) uint64",
			"type Node struct { Next *Node }\nfunc Value(a *[32]byte) uint64",
		},
		{
			"unrelated callback does not hide alias RHS",
			"type Callback func()\ntype A uint64\ntype B uint64\ntype Choice = A\nfunc Value(a *Choice) uint64",
			"type Callback func()\ntype A uint64\ntype B uint64\ntype Choice = B\nfunc Value(a *Choice) uint64",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pkg, request := goAMD64FrameTypedFixture(t, test.original, "TEXT ·Value(SB),4,$160-16\nRET\n")
			guard := goAMD64FrameTypedSelection(t, pkg, request)
			if _, err := guard.typedDeclarations(pkg, false); err != nil {
				t.Fatalf("unmutated independent typecheck failed: %v", err)
			}
			if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte("package framefixture\n"+test.mutation+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			guard.inputs = make(map[string][32]byte)
			if _, err := guard.typedDeclarations(pkg, false); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("stale supplied type tree accepted actual source mutation: %v", err)
			}
		})
	}
}

func TestGoAMD64FrameTypedSourceUnsupportedRolesRemainContext(t *testing.T) {
	for _, declaration := range []string{
		"func Value(a float32) uint64", "func Value(a complex128) uint64",
		"func Value(a string) uint64", "func Value(a *float64) uint64",
		"func Value(a map[uint64]uint64) uint64", "func Value(a chan uint64) uint64",
		"func Value(a func(uint64) uint64) uint64", "func Value(a interface{}) uint64",
		"func Value(a [2]uint64) uint64", "func Value(a struct { X uint64 }) uint64",
		"type Node struct { Next *Node }\nfunc Value(a *Node) uint64",
		"type Node[T any] struct { Value T }\nfunc Value(a *Node[uint64]) uint64",
		"func Value[T ~uint64](a T) uint64 { return uint64(a) }", "func Value(a ...uint64) uint64",
		"func Value(a *uint64) uint64 { return *a }",
	} {
		t.Run(declaration, func(t *testing.T) {
			pkg, request := goAMD64FrameTypedFixture(t, declaration, "TEXT ·Value(SB),4,$160-16\nRET\n")
			guard := goAMD64FrameTypedSelection(t, pkg, request)
			_, err := guard.typedDeclarations(pkg, false)
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unknown/GC/aggregate role did not retain Context: %v", err)
			}
			if strings.Contains(err.Error(), "input path is redirected or inaccessible") {
				t.Fatalf("path rejection cannot prove an unsupported language role: %v", err)
			}
		})
	}
}

func TestGoAMD64FrameTypedSourceOrdinaryPointerValueIsObservationOnly(t *testing.T) {
	pkg, request := goAMD64FrameTypedFixture(t,
		"var P *uint64\nfunc Value(a *uint64) uint64",
		"TEXT ·Value(SB),4,$160-16\nRET\n")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	if len(source.functions) != 1 || len(source.declarations) != 1 {
		t.Fatal("ordinary pointer value created an additional frame capability")
	}
	function := source.functions[pkg.Path+".Value"]
	if function.transport != goAMD64FrameCompositeTransport || function.args != 16 {
		t.Fatalf("original pointer declaration lost its separate observation role: %+v", function)
	}
	if !errors.Is(source.numericDeclarations(pkg), ErrProbeNeedsContext) {
		t.Fatal("ordinary pointer value or declaration entered numeric-only fixed-local admission")
	}
}

func TestGoAMD64FrameTypedSourceActualCaptureRejectsStalePointee(t *testing.T) {
	for _, test := range []struct{ original, mutation string }{
		{"func Value(a *uint64) uint64", "func Value(a *int64) uint64"},
		{"type Packet struct { X [4]byte }\nfunc Value(a *Packet) uint64", "type Packet struct { X [8]byte }\nfunc Value(a *Packet) uint64"},
		{"type A uint64\ntype B uint64\ntype Choice = A\nfunc Value(a *Choice) uint64", "type A uint64\ntype B uint64\ntype Choice = B\nfunc Value(a *Choice) uint64"},
	} {
		t.Run(test.mutation, func(t *testing.T) {
			pkg, request := goAMD64FrameTypedFixture(t, test.original, "TEXT ·Value(SB),4,$160-16\nRET\n")
			if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte("package framefixture\n"+test.mutation+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if source != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("actual compiler export accepted stale supplied language identity: %v", err)
			}
		})
	}
}

func TestGoAMD64FrameTypedSourceLanguageBounds(t *testing.T) {
	sizes := types.SizesFor("gc", "amd64")
	constraint := types.NewInterfaceType(nil, nil).Complete()
	parameter := types.NewTypeParam(types.NewTypeName(token.NoPos, nil, "T", nil), constraint)
	for _, typ := range []types.Type{nil, parameter, types.Typ[types.UntypedInt], types.Typ[types.Float64], types.NewMap(types.Typ[types.Uint64], types.Typ[types.Uint64])} {
		if _, err := goAMD64FrameLanguageType(typ, sizes); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unknown language role did not fail closed: %v", err)
		}
	}
	deep := types.Type(types.Typ[types.Uint64])
	for i := 0; i < 34; i++ {
		deep = types.NewPointer(deep)
	}
	fields := make([]*types.Var, 4097)
	for i := range fields {
		fields[i] = types.NewVar(token.NoPos, nil, fmt.Sprintf("F%d", i), types.Typ[types.Uint64])
	}
	for _, typ := range []types.Type{deep, types.NewStruct(fields, nil), types.NewArray(types.Typ[types.Uint64], 1<<62)} {
		if _, err := goAMD64FrameLanguageType(typ, sizes); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unbounded or overflowing type obtained an observation: %v", err)
		}
	}
	large := types.NewArray(types.Typ[types.Uint8], 1<<62)
	fields = []*types.Var{
		types.NewVar(token.NoPos, nil, "A", large),
		types.NewVar(token.NoPos, nil, "B", large),
	}
	if _, err := goAMD64FrameLanguageType(types.NewStruct(fields, nil), sizes); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("aggregate size overflow was recorded as a layout: %v", err)
	}
	if _, err := goAMD64FrameLanguageType(types.Typ[types.Uint64], nil); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("missing target sizes were treated as a layout")
	}
}

func TestGoAMD64FrameTypedSourceMissingSignatureRemainsContext(t *testing.T) {
	pkg, request := goAMD64FrameTypedFixture(t, "func Value(a []byte) uint64", "TEXT ·Value(SB),4,$160-32\nRET\n")
	pkg.Types = types.NewPackage(pkg.Path, "framefixture")
	pkg.Types.Scope().Insert(types.NewFunc(token.NoPos, pkg.Types, "Value", nil))
	guard := goAMD64FrameTypedSelection(t, pkg, request)
	if _, err := guard.typedDeclarations(pkg, false); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("missing supplied typed signature did not retain Context: %v", err)
	}
}

func TestGoAMD64FrameTypedSourceMutationAndCloseRevocation(t *testing.T) {
	for _, change := range []string{"source", "object", "header inventory", "cancel", "close"} {
		t.Run(change, func(t *testing.T) {
			pkg, request := goAMD64FrameTypedFixture(t, "func Value(a []byte, n uint64) uint64", "TEXT ·Value(SB),4,$160-40\nRET\n")
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			switch change {
			case "source":
				if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte("package framefixture\nfunc Value(a []uint16, n uint64) uint64\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "object":
				if err := os.WriteFile(filepath.Join(source.owned, request.AssemblyFile+".o"), []byte("not the original object"), 0600); err != nil {
					t.Fatal(err)
				}
			case "header inventory":
				if err := os.WriteFile(filepath.Join(request.Directory, "late.h"), []byte("#define NEW 1\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			case "close":
				if err := source.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := source.Verify(ctx); err == nil {
				t.Fatal("changed/closed composite source retained its observation")
			}
			if !errors.Is(source.Verify(context.Background()), ErrProbeNeedsContext) {
				t.Fatal("failed composite Verify did not permanently revoke the token")
			}
		})
	}
}

func TestGoAMD64FrameTypedSourceNoMemoryPermissionInThreeAPIs(t *testing.T) {
	assembly := "TEXT ·Value(SB),4,$160-40\nPXOR X0,X0\nMOVOU X0,16(SP)\nPADDQ 16(SP),X0\nRET\n"
	pkg, request := goAMD64FrameTypedFixture(t, "func Value(a []byte, n uint64) uint64", assembly)
	source := requireGoAMD64FrameCapture(t, pkg, request)
	sig := source.functions[pkg.Path+".Value"].signature
	if !errors.Is(source.numericDeclarations(pkg), ErrProbeNeedsContext) {
		t.Fatal("composite observation entered fixed-local numeric transport")
	}
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) }
	opt := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: map[string]FuncSig{sig.Name: sig}}
	for _, api := range []string{"Translate", "TranslateModuleInContext", "TranslateGoModule"} {
		t.Run(api, func(t *testing.T) {
			var err error
			switch api {
			case "Translate":
				_, err = Translate(file, opt)
			case "TranslateModuleInContext":
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, failure := TranslateModuleInContext(ctx, file, opt)
				err = failure
				if !module.IsNil() {
					defer module.Dispose()
				}
			case "TranslateGoModule":
				translation, failure := TranslateGoModule(pkg, []byte(assembly), GoModuleOptions{GOOS: "linux", GOARCH: "amd64", TargetTriple: opt.TargetTriple, ResolveSym: resolve})
				err = failure
				if translation != nil && !translation.Module.IsNil() {
					defer translation.Module.Dispose()
				}
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("sealed observation alone granted native local memory: %v", err)
			}
		})
	}
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var restored GoAMD64FrameSource
	if err := json.Unmarshal(encoded, &restored); err != nil || !errors.Is(restored.Verify(context.Background()), ErrProbeNeedsContext) {
		t.Fatalf("public JSON recreated a composite observation: %v", err)
	}
	if !reflect.DeepEqual(source.declarations[sig.Name].signature, sig) {
		t.Fatal("object signature diverged from independently typed declaration")
	}
}

type goAMD64FrameLayoutCounter struct {
	types.Sizes
	structCalls int
}

func (counter *goAMD64FrameLayoutCounter) Sizeof(typ types.Type) int64 {
	if _, ok := typ.(*types.Struct); ok {
		counter.structCalls++
	}
	return counter.Sizes.Sizeof(typ)
}

func TestGoAMD64FrameTypedSourceMetadataByteBoundBeforeLayout(t *testing.T) {
	for _, field := range []string{"name", "tag", "package"} {
		t.Run(field, func(t *testing.T) {
			name, tag := "Value", ""
			pkg := types.NewPackage("example.invalid/model", "model")
			switch field {
			case "name":
				name = strings.Repeat("x", 64<<10+1)
			case "tag":
				tag = strings.Repeat("x", 64<<10+1)
			case "package":
				pkg = types.NewPackage("example.invalid/"+strings.Repeat("x", 64<<10+1), "model")
			}
			field := types.NewVar(token.NoPos, pkg, name, types.Typ[types.Uint64])
			structure := types.NewStruct([]*types.Var{field}, []string{tag})
			counter := &goAMD64FrameLayoutCounter{Sizes: types.SizesFor("gc", "amd64")}
			if _, err := goAMD64FrameLanguageType(structure, counter); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("oversized field metadata was recorded: %v", err)
			}
			if counter.structCalls != 0 {
				t.Fatalf("aggregate layout continued after metadata exceeded its bound: %d calls", counter.structCalls)
			}
		})
	}
}

func TestGoAMD64FrameTypedSourcePointeeModelIsNotMachineExtent(t *testing.T) {
	declaration := `type Packet struct { X uint64; Y byte }
type EmptyTail struct { X uint64; Y struct{} }
func Value(a *Packet, b *EmptyTail, n uint64) uint64`
	pkg, request := goAMD64FrameTypedFixture(t, declaration, "TEXT ·Value(SB),4,$160-32\nRET\n")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	header := filepath.Join(source.owned, "pointee-layout.h")
	archive := filepath.Join(source.owned, "pointee-layout.a")
	if _, err := source.run(ctx, "tool", "compile", "-p", pkg.Path, "-asmhdr", header, "-o", archive, "value.go"); err != nil {
		t.Fatal(err)
	}
	data, err := source.read(header)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := source.read(archive); err != nil || len(data) == 0 {
		t.Fatalf("actual original compiler archive missing: %v", err)
	}
	definitions := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "#define" {
			if _, duplicate := definitions[fields[1]]; duplicate {
				t.Fatalf("duplicate original machine definition: %s", line)
			}
			definitions[fields[1]] = fields[2]
		}
	}
	fn := source.functions[pkg.Path+".Value"]
	for _, name := range []string{"Packet", "EmptyTail"} {
		// This is the independently observed machine definition. The
		// capture descriptor is deliberately only the go/types model.
		if definitions[name+"__size"] != "16" || definitions[name+"_X"] != "0" || definitions[name+"_Y"] != "8" {
			t.Fatalf("unexpected actual compiler padded layout for %s: %v", name, definitions)
		}
		typ := pkg.Types.Scope().Lookup(name).Type()
		model := types.SizesFor("gc", "amd64").Sizeof(typ)
		identity, err := goAMD64FrameLanguageType(typ, types.SizesFor("gc", "amd64"))
		if err != nil || !strings.Contains(fn.languageType, identity) {
			t.Fatalf("missing independent language model: %v", err)
		}
		t.Logf("%s: recorded go/types model=%d; independently observed stock-Go machine size=16", name, model)
	}
	if fn.transport != goAMD64FrameCompositeTransport || !errors.Is(source.numericDeclarations(pkg), ErrProbeNeedsContext) {
		t.Fatal("language model was used as a numeric backing/pointee permission")
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}
