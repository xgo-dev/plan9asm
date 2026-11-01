package plan9asm

import (
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"
)

type x86CallerTestImporter struct{}

func (x86CallerTestImporter) Import(path string) (*types.Package, error) {
	if path == "unsafe" {
		return types.Unsafe, nil
	}
	panic("unexpected caller-region fixture import: " + path)
}

const x86CallerFixtureSource = `package caller
import "unsafe"

//go:noescape
func kernel(a, b, res, length unsafe.Pointer)

func Call(x, y []float32) float32 {
	var res float32
	length := len(x)
	kernel(
		unsafe.Pointer(unsafe.SliceData(x)),
		unsafe.Pointer(unsafe.SliceData(y)),
		unsafe.Pointer(&res),
		unsafe.Pointer(&length))
	return res
}
`

const x86CallerFixtureAssembly = `TEXT ·kernel(SB),4,$0-32
MOVQ a+0(FP),DI
MOVQ b+8(FP),SI
MOVQ res+16(FP),DX
MOVQ length+24(FP),CX
BYTE $0x55
WORD $0x8948
BYTE $0xe5
LONG $0xf8e48348
MOVL $7,AX
MOVL AX,(DX)
WORD $0x8948
BYTE $0xec
BYTE $0x5d
BYTE $0xc3
`

func x86CallerFixture(t *testing.T, source string) (GoPackage, GoSourceSelection, Func, FuncSig) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "caller.go", source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}
	pkg, err := (&types.Config{
		Importer: x86CallerTestImporter{},
		Sizes:    types.SizesFor("gc", "amd64"),
	}).Check("caller", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := Parse(ArchAMD64, x86CallerFixtureAssembly)
	if err != nil {
		t.Fatal(err)
	}
	goPkg := GoPackage{Path: "caller", Types: pkg, Syntax: []*ast.File{file}}
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	sigs, err := goSigsForAsmFile(goPkg, assembly, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected := GoSourceSelection{
		Fset:                  fset,
		TypesInfo:             info,
		Sizes:                 types.SizesFor("gc", "amd64"),
		SelectedGoFiles:       []string{"caller.go"},
		GoSources:             map[string][]byte{"caller.go": []byte(source)},
		SelectedAssemblyFiles: []string{"kernel_amd64.s"},
		Assembly:              map[string]*File{"kernel_amd64.s": assembly},
	}
	return goPkg, selected, assembly.Funcs[0], sigs["caller.kernel"]
}

func TestX86GoCallerRegionsDeriveActualTypedArguments(t *testing.T) {
	pkg, selected, fn, sig := x86CallerFixture(t, x86CallerFixtureSource)
	proof, err := deriveX86GoCallerRegions(pkg, selected, fn, sig, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if proof == nil || proof.symbol != "caller.kernel" || len(proof.arguments) != 4 || proof.calls != 1 {
		t.Fatalf("missing actual caller/parameter binding: %+v", proof)
	}
	wantKinds := []x86CallerRegionKind{x86CallerSliceInput, x86CallerSliceInput, x86CallerFreshResult, x86CallerLocalLength}
	wantWidths := []int64{4, 4, 4, 8}
	for index, argument := range proof.arguments {
		if argument.kind != wantKinds[index] || argument.width != wantWidths[index] || argument.slot != int64(index*8) {
			t.Fatalf("argument %d: %+v", index, argument)
		}
	}
	// A caller producer by itself must not turn this into a raw-return pass.
	file, err := Parse(ArchAMD64, x86CallerFixtureAssembly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "amd64", Sigs: map[string]FuncSig{sig.Name: sig},
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
	}); err == nil {
		t.Fatal("region metadata without a whole-source control proof became a pass")
	}
}

func TestX86GoCallerRegionsBindNumericalResultWidthsAndEveryCaller(t *testing.T) {
	for _, result := range []struct {
		name  string
		width int64
	}{
		{name: "uint8", width: 1}, {name: "int8", width: 1},
		{name: "uint16", width: 2}, {name: "int16", width: 2},
		{name: "uint32", width: 4}, {name: "int32", width: 4}, {name: "float32", width: 4},
		{name: "uint64", width: 8}, {name: "int64", width: 8}, {name: "float64", width: 8},
	} {
		t.Run(result.name, func(t *testing.T) {
			source := strings.ReplaceAll(x86CallerFixtureSource, "float32", result.name)
			caller := source[strings.Index(source, "func Call("):]
			source += strings.Replace(caller, "func Call(", "func SecondCall(", 1)
			pkg, selected, fn, sig := x86CallerFixture(t, source)
			proof, err := deriveX86GoCallerRegions(pkg, selected, fn, sig, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if proof.calls != 2 || proof.arguments[2].width != result.width {
				t.Fatalf("actual typed callers/result envelope: %+v", proof)
			}
		})
	}
}

func TestX86GoCallerRegionsRejectIncompleteAndChangedSelection(t *testing.T) {
	for _, change := range []string{
		"missing types", "missing type info", "missing Go bytes", "missing Go AST", "changed Go bytes",
		"extra Go bytes", "missing ASM", "extra ASM", "changed signature", "wrong parameter index", "custom registers", "wrong architecture", "missing sizes", "wrong actual sizes",
	} {
		t.Run(change, func(t *testing.T) {
			pkg, selected, fn, sig := x86CallerFixture(t, x86CallerFixtureSource)
			arch := "amd64"
			switch change {
			case "missing types":
				pkg.Types = nil
			case "missing type info":
				selected.TypesInfo = nil
			case "missing Go bytes":
				delete(selected.GoSources, "caller.go")
			case "missing Go AST":
				pkg.Syntax = nil
			case "changed Go bytes":
				selected.GoSources["caller.go"] = []byte(strings.Replace(x86CallerFixtureSource, "&res", "unsafe.SliceData(x)", 1))
			case "extra Go bytes":
				selected.GoSources["unselected.go"] = []byte("package caller\n")
			case "missing ASM":
				delete(selected.Assembly, "kernel_amd64.s")
			case "extra ASM":
				selected.Assembly["unselected.s"] = selected.Assembly["kernel_amd64.s"]
			case "changed signature":
				sig.Args = []LLVMType{I64, Ptr, Ptr, Ptr}
			case "wrong parameter index":
				sig.Frame.Params[0].Index, sig.Frame.Params[1].Index = 1, 0
			case "custom registers":
				sig.ArgRegs = []Reg{AX, BX, CX, DX}
			case "wrong architecture":
				arch = "arm64"
			case "missing sizes":
				selected.Sizes = nil
			case "wrong actual sizes":
				selected.Sizes = types.SizesFor("gc", "386")
			}
			if proof, err := deriveX86GoCallerRegions(pkg, selected, fn, sig, arch); err == nil || proof != nil {
				t.Fatalf("incomplete/changed actual source got a caller certificate: %+v, %v", proof, err)
			}
		})
	}
}

func TestX86GoCallerRegionsRejectUnclosedCallsAndUnsafeRegions(t *testing.T) {
	for _, source := range []string{
		x86CallerFixtureSource + "\nvar addressTaken = kernel\n",
		strings.Replace(x86CallerFixtureSource, "//go:noescape", "//go:linkname kernel external.kernel", 1),
		strings.Replace(x86CallerFixtureSource, "kernel(\n", "indirect := kernel\n\tindirect(\n", 1),
		strings.Replace(x86CallerFixtureSource, "unsafe.Pointer(&res)", "unsafe.Pointer(unsafe.SliceData(x))", 1),
		strings.Replace(x86CallerFixtureSource, "unsafe.Pointer(&res)", "unsafe.Pointer(uintptr(unsafe.Pointer(&res)) + 1)", 1),
		strings.Replace(x86CallerFixtureSource, "length := len(x)", "length := 7", 1),
		strings.Replace(x86CallerFixtureSource, "length := len(x)", "length := len(x)\n\tlength++", 1),
		strings.Replace(x86CallerFixtureSource, "length := len(x)", "length := len(x)\n\tEscape(&res)", 1) + "\nfunc Escape(*float32) {}\n",
		strings.Replace(x86CallerFixtureSource, "kernel(\n", "func() { kernel(\n", 1),
	} {
		// The last source is intentionally replaced with a valid closure below.
		if strings.Contains(source, "func() { kernel") {
			source = strings.Replace(source, "unsafe.Pointer(&length))", "unsafe.Pointer(&length)) }()", 1)
		}
		pkg, selected, fn, sig := x86CallerFixture(t, source)
		if proof, err := deriveX86GoCallerRegions(pkg, selected, fn, sig, "amd64"); err == nil || proof != nil {
			t.Fatalf("unclosed/unsafe source got a caller certificate:\n%s\n%+v, %v", source, proof, err)
		}
	}
}

func TestX86GoCallerRegionsRejectAssemblyCallersAndAddressTaking(t *testing.T) {
	for _, body := range []string{
		"CALL ·kernel(SB)",
		"MOVQ $·kernel(SB),AX",
		"JMP ·kernel(SB)",
		"JMP external·unknown(SB)",
		"BYTE $0xe8\nLONG $0",
		"JMP AX",
	} {
		pkg, selected, fn, sig := x86CallerFixture(t, x86CallerFixtureSource)
		sibling, err := Parse(ArchAMD64, "TEXT ·Sibling(SB),4,$0-0\n"+body+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		selected.SelectedAssemblyFiles = append(selected.SelectedAssemblyFiles, "sibling_amd64.s")
		selected.Assembly["sibling_amd64.s"] = sibling
		if proof, err := deriveX86GoCallerRegions(pkg, selected, fn, sig, "amd64"); err == nil || proof != nil {
			t.Fatalf("unregistered assembly caller got a certificate: %s: %+v, %v", body, proof, err)
		}
	}
}

func TestX86GoCallerRegionsRejectAssemblyMemorySymbolExposure(t *testing.T) {
	pkg, selected, fn, sig := x86CallerFixture(t, x86CallerFixtureSource)
	sibling, err := Parse(ArchAMD64, "TEXT ·Sibling(SB),4,$0-0\nMOVQ (AX),BX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	// The actual parser usually spells SB references as OpSym. A compiler's
	// selected File may also carry a symbolic memory operand; closure must
	// inspect that representation rather than silently treating it as numeric.
	sibling.Funcs[0].Instrs[1].Args[0].Mem.Sym = "·kernel(SB)"
	selected.SelectedAssemblyFiles = append(selected.SelectedAssemblyFiles, "sibling_amd64.s")
	selected.Assembly["sibling_amd64.s"] = sibling
	if proof, err := deriveX86GoCallerRegions(pkg, selected, fn, sig, "amd64"); err == nil || proof != nil {
		t.Fatalf("assembly memory exposed entry without closing its callers: %+v, %v", proof, err)
	}
}

func TestX86GoCallerRegionsKeepIndependentSourceAndSignatureSnapshots(t *testing.T) {
	pkg, selected, fn, sig := x86CallerFixture(t, x86CallerFixtureSource)
	proof, err := deriveX86GoCallerRegions(pkg, selected, fn, sig, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	before := proof.source
	fn.Instrs[1].Args[0].FPOffset = 8
	sig.Args[0] = I64
	sig.Frame.Params[0].Offset = 8
	selected.GoSources["caller.go"][0] = 'X'
	after, err := x86CallerSourceFingerprint(fn)
	if err != nil {
		t.Fatal(err)
	}
	if proof.source != before || proof.source == after ||
		proof.signature.Args[0] != Ptr || proof.signature.Frame.Params[0].Offset != 0 ||
		proof.goSources["caller.go"] == sha256.Sum256(selected.GoSources["caller.go"]) {
		t.Fatal("mutable compiler inputs changed an already-produced witness")
	}
}

func TestX86CallerSourceFingerprintRejectsOpaqueInput(t *testing.T) {
	if _, err := x86CallerSourceFingerprint(make(chan int)); err == nil {
		t.Fatal("opaque input acquired a source fingerprint")
	}
}

func TestX86GoCallerRegionsRejectEditedASTWithStaleTypeInfo(t *testing.T) {
	pkg, selected, fn, sig := x86CallerFixture(t, x86CallerFixtureSource)
	changed := false
	ast.Inspect(pkg.Syntax[0], func(node ast.Node) bool {
		if changed {
			return false
		}
		address, ok := node.(*ast.UnaryExpr)
		if !ok || address.Op != token.AND {
			return true
		}
		identifier, ok := address.X.(*ast.Ident)
		if ok && identifier.Name == "res" {
			identifier.Name = "length"
			changed = true
		}
		return true
	})
	selected.GoSources["caller.go"] = []byte(strings.Replace(x86CallerFixtureSource, "&res", "&length", 1))
	if proof, err := deriveX86GoCallerRegions(pkg, selected, fn, sig, "amd64"); err == nil || proof != nil {
		t.Fatalf("edited AST retained stale typechecked local identity: %+v, %v", proof, err)
	}
}

func TestX86GoCallerRegionsRejectAssemblyDataAddressTaking(t *testing.T) {
	pkg, selected, fn, sig := x86CallerFixture(t, x86CallerFixtureSource)
	selected.Assembly["kernel_amd64.s"].Data = []DataStmt{{
		Sym: "entryAddress", Width: 8, Addr: "·kernel(SB)",
	}}
	if proof, err := deriveX86GoCallerRegions(pkg, selected, fn, sig, "amd64"); err == nil || proof != nil {
		t.Fatalf("assembly DATA exposed a closed entry: %+v, %v", proof, err)
	}
}
