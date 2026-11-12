package plan9asm

import (
	"errors"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"strings"
	"testing"
)

func mustGoPackageWithImports(t *testing.T, pkgPath string, files map[string]string) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	astFiles := make([]*ast.File, 0, len(files))
	for name, src := range files {
		f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		astFiles = append(astFiles, f)
	}
	conf := types.Config{Importer: nil}
	pkg, err := conf.Check(pkgPath, fset, astFiles, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: pkgPath, Types: pkg, Syntax: astFiles}
}

func TestGoTranslateHelperCoverage(t *testing.T) {
	if _, err := goArchFor("mips64"); err == nil {
		t.Fatalf("goArchFor(mips64) unexpectedly succeeded")
	}

	for _, tc := range []struct {
		in      string
		base    string
		off     int64
		tail    bool
		validOp Op
	}{
		{"name+8", "name", 8, false, ""},
		{"name-4", "name", -4, false, ""},
		{"plain", "plain", 0, false, ""},
		{"target<>(SB)", "target<>", 0, false, "CALL"},
	} {
		if tc.validOp == "" {
			gotBase, gotOff := goSplitSymPlusOff(tc.in)
			if gotBase != tc.base || gotOff != tc.off {
				t.Fatalf("goSplitSymPlusOff(%q) = (%q, %d), want (%q, %d)", tc.in, gotBase, gotOff, tc.base, tc.off)
			}
			continue
		}
		base, tail, ok := goReferencedFunc(Instr{Op: tc.validOp, Args: []Operand{{Kind: OpSym, Sym: tc.in}}})
		if !ok || base != tc.base || tail != tc.tail {
			t.Fatalf("goReferencedFunc(%q) = (%q, %v, %v)", tc.in, base, tail, ok)
		}
	}
	for _, ins := range []Instr{
		{Op: "MOVQ", Args: []Operand{{Kind: OpSym, Sym: "x(SB)"}}},
		{Op: "CALL", Args: []Operand{{Kind: OpImm, Imm: 1}}},
		{Op: "CALL", Args: []Operand{{Kind: OpSym, Sym: "x+4(SB)"}}},
		{Op: "CALL", Args: []Operand{{Kind: OpSym, Sym: "x"}}},
	} {
		if _, _, ok := goReferencedFunc(ins); ok {
			t.Fatalf("goReferencedFunc(%q) unexpectedly succeeded", ins.Op)
		}
	}

	if fs, ok := goLookupManualSig(nil, "x"); ok || fs.Name != "" {
		t.Fatalf("goLookupManualSig(nil) = (%v, %v)", fs, ok)
	}
	fs, ok := goLookupManualSig(func(resolved string) (FuncSig, bool) {
		if resolved != "pkg.f" {
			return FuncSig{}, false
		}
		return FuncSig{Ret: I64}, true
	}, "pkg.f")
	if !ok || fs.Name != "pkg.f" || fs.Ret != I64 {
		t.Fatalf("goLookupManualSig() = (%v, %v)", fs, ok)
	}

	if got, err := goDeclNameForSymbol("·local", nil); err != nil || got != "local" {
		t.Fatalf("goDeclNameForSymbol(local) = (%q, %v)", got, err)
	}
	if got, err := goDeclNameForSymbol("runtime·cmp", map[string]string{"runtime.cmp": "cmp"}); err != nil || got != "cmp" {
		t.Fatalf("goDeclNameForSymbol(linkname) = (%q, %v)", got, err)
	}
	if _, err := goDeclNameForSymbol("runtime·cmp", nil); err == nil {
		t.Fatalf("goDeclNameForSymbol(missing linkname) unexpectedly succeeded")
	}

	files := []*ast.File{
		nil,
		{Comments: []*ast.CommentGroup{{List: []*ast.Comment{
			{Text: "//go:linkname local runtime.remote"},
			{Text: "//go:linkname malformed"},
		}}}},
	}
	links := goLinknameRemoteToLocal(files)
	if links["runtime.remote"] != "local" {
		t.Fatalf("goLinknameRemoteToLocal() = %#v", links)
	}
}

func TestGoTranslateTypeCoverage(t *testing.T) {
	word32 := types.Typ[types.Int]
	namedObj := types.NewTypeName(token.NoPos, nil, "MyInt", nil)
	named := types.NewNamed(namedObj, types.Typ[types.Int32], nil)
	aliasObj := types.NewTypeName(token.NoPos, nil, "MyUint64", nil)
	alias := newAliasTypeForTest(aliasObj, types.Typ[types.Uint64])
	for _, tc := range []struct {
		typ    types.Type
		goarch string
		want   LLVMType
		ok     bool
	}{
		{types.Typ[types.Bool], "amd64", I1, true},
		{types.Typ[types.UnsafePointer], "amd64", Ptr, true},
		{types.Typ[types.Int8], "amd64", I8, true},
		{types.Typ[types.Uint16], "amd64", I16, true},
		{types.Typ[types.Int32], "amd64", I32, true},
		{types.Typ[types.Uint64], "amd64", I64, true},
		{word32, "arm", I32, true},
		{types.Typ[types.Uintptr], "arm64", I64, true},
		{types.Typ[types.Float32], "amd64", LLVMType("float"), true},
		{types.Typ[types.Float64], "amd64", LLVMType("double"), true},
		{types.Typ[types.String], "arm", LLVMType("{ ptr, i32 }"), true},
		{types.NewPointer(types.Typ[types.Int]), "amd64", Ptr, true},
		{types.NewSlice(types.Typ[types.Byte]), "arm64", LLVMType("{ ptr, i64, i64 }"), true},
		{types.NewInterfaceType(nil, nil), "amd64", LLVMType("{ ptr, ptr }"), true},
		{named, "amd64", I32, true},
		{alias, "arm64", I64, true},
		{types.Typ[types.Complex64], "amd64", "{ float, float }", true},
		{types.NewStruct(nil, nil), "amd64", LLVMType("[0 x i8]"), true},
		{types.NewStruct([]*types.Var{types.NewVar(token.NoPos, nil, "x", types.Typ[types.Int])}, nil), "amd64", "{ i64 }", true},
	} {
		got, err := goLLVMTypeForType(tc.typ, tc.goarch)
		if (err == nil) != tc.ok || got != tc.want {
			t.Fatalf("goLLVMTypeForType(%s,%s) = (%q, %v), want (%q, ok=%v)", tc.typ, tc.goarch, got, err, tc.want, tc.ok)
		}
	}

	if parts, ok := goFramePartsForType(types.Typ[types.String], "amd64"); !ok || len(parts) != 2 || parts[1].Offset != 8 {
		t.Fatalf("goFramePartsForType(string) = (%v, %v)", parts, ok)
	}
	if parts, ok := goFramePartsForType(types.NewSlice(types.Typ[types.Int]), "arm"); !ok || len(parts) != 3 || parts[2].Field != 2 {
		t.Fatalf("goFramePartsForType(slice) = (%v, %v)", parts, ok)
	}
	if parts, ok := goFramePartsForType(types.NewInterfaceType(nil, nil), "amd64"); !ok || len(parts) != 2 {
		t.Fatalf("goFramePartsForType(interface) = (%v, %v)", parts, ok)
	}
	if _, ok := goFramePartsForType(types.Typ[types.Int], "amd64"); ok {
		t.Fatalf("goFramePartsForType(int) unexpectedly succeeded")
	}

	tup := types.NewTuple(
		types.NewVar(token.NoPos, nil, "s", types.Typ[types.String]),
		types.NewVar(token.NoPos, nil, "b", types.NewSlice(types.Typ[types.Byte])),
		types.NewVar(token.NoPos, nil, "n", types.Typ[types.Int32]),
	)
	sz := types.SizesFor("gc", "arm64")
	args, slots, next, err := goLLVMArgsAndFrameSlotsForTuple(tup, "arm64", sz, sz, 8, false)
	if err != nil || len(args) != 3 || len(slots) != 6 || next <= 8 {
		t.Fatalf("goLLVMArgsAndFrameSlotsForTuple(flat=false) = (%v, %v, %d, %v)", args, slots, next, err)
	}
	args, slots, next, err = goLLVMArgsAndFrameSlotsForTuple(tup, "arm64", sz, sz, 8, true)
	if err != nil || len(args) != 6 || len(slots) != 6 || next <= 8 {
		t.Fatalf("goLLVMArgsAndFrameSlotsForTuple(flat=true) = (%v, %v, %d, %v)", args, slots, next, err)
	}

	if goWordSize("arm") != 4 || goWordSize("arm64") != 8 {
		t.Fatalf("goWordSize() mismatch")
	}
	if got := goAlignOff(5, 4); got != 8 {
		t.Fatalf("goAlignOff(5,4) = %d", got)
	}
}

func TestModerncUint128ABI0Signature(t *testing.T) {
	pkg := mustGoPackageWithImports(t, "modernc.org/libc", map[string]string{
		"abi0_linux_amd64.go": `package libc
			type TLS struct{}
			type Uint128 struct { Lo, Hi uint64 }
			func Y__builtin_mul_overflowUint128(t *TLS, a, b Uint128, res uintptr) (result int32)`,
	})
	fn, ok := pkg.Types.Scope().Lookup("Y__builtin_mul_overflowUint128").(*types.Func)
	if !ok {
		t.Fatal("missing assembly declaration")
	}
	sizes := types.SizesFor("gc", "amd64")
	sig, err := goFuncSigForDeclaredFunc("modernc.org/libc.Y__builtin_mul_overflowUint128", fn, "amd64", sizes, sizes, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sig.Args, []LLVMType{Ptr, "{ i64, i64 }", "{ i64, i64 }", I64}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Args = %v, want %v", got, want)
	}
	if sig.Ret != I32 {
		t.Fatalf("Ret = %s, want %s", sig.Ret, I32)
	}
	for _, slot := range []struct {
		index  int
		offset int64
		field  int
	}{
		{0, 0, -1},
		{1, 8, 0},
		{1, 16, 1},
		{2, 24, 0},
		{2, 32, 1},
		{3, 40, -1},
	} {
		found := false
		for _, got := range sig.Frame.Params {
			if got.Index == slot.index && got.Offset == slot.offset && got.Field == slot.field {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing ABI0 parameter slot %+v in %+v", slot, sig.Frame.Params)
		}
	}
	if len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Offset != 48 {
		t.Fatalf("Results = %+v, want one slot at offset 48", sig.Frame.Results)
	}
}

func TestGoTranslateSignatureCoverage(t *testing.T) {
	pkg := mustGoPackage(t, "test/pkg", `package testpkg
type S struct{}
func (S) Method(x int) int { return x }
func Variadic(x ...int) {}
func Plain(a string, b []byte, c any, d uintptr) (int, string) { return 0, "" }
func helper(a int) int { return a }
//go:linkname cmp runtime.cmp
func cmp(a, b int) int { return a }
`)
	scope := pkg.Types.Scope()
	plain := scope.Lookup("Plain").(*types.Func)
	sz := types.SizesFor("gc", "arm64")
	sig, err := goFuncSigForDeclaredFunc("test/pkg.Plain", plain, "arm64", sz, sz, true)
	if err != nil || sig.Ret == Void || len(sig.Frame.Params) == 0 || len(sig.Frame.Results) == 0 {
		t.Fatalf("goFuncSigForDeclaredFunc(Plain) = (%v, %v)", sig, err)
	}
	variadic := scope.Lookup("Variadic").(*types.Func)
	sz = types.SizesFor("gc", "amd64")
	if _, err := goFuncSigForDeclaredFunc("test/pkg.Variadic", variadic, "amd64", sz, sz, false); err == nil {
		t.Fatalf("goFuncSigForDeclaredFunc(Variadic) unexpectedly succeeded")
	}
	named := scope.Lookup("S").Type().(*types.Named)
	if _, err := goFuncSigForDeclaredFunc("test/pkg.Method", named.Method(0), "amd64", sz, sz, false); err == nil {
		t.Fatalf("goFuncSigForDeclaredFunc(Method) unexpectedly succeeded")
	}

	file := &File{
		Arch: ArchARM64,
		Funcs: []Func{
			{
				Sym: "·Plain",
				Instrs: []Instr{
					{Op: OpTEXT},
					{Op: "CALL", Args: []Operand{{Kind: OpSym, Sym: "runtime·cmp(SB)"}}},
					{Op: "CALL", Args: []Operand{{Kind: OpSym, Sym: "undeclared_call(SB)"}}},
					{Op: "B", Args: []Operand{{Kind: OpSym, Sym: "localtarget<>(SB)"}}},
					{Op: OpRET},
				},
			},
			{
				Sym: "localhelper<>",
				Instrs: []Instr{
					{Op: OpTEXT},
					{Op: "B", Args: []Operand{{Kind: OpSym, Sym: "helper<>(SB)"}}},
					{Op: OpRET},
				},
			},
			{Sym: "localtarget<>"},
		},
	}
	manual := func(resolved string) (FuncSig, bool) {
		if resolved == "test/pkg.localhelper" {
			return FuncSig{Name: resolved, Args: []LLVMType{I64}, Ret: I64}, true
		}
		return FuncSig{}, false
	}
	if _, err := goSigsForAsmFile(pkg, file, testResolveSym("test/pkg"), "arm64", nil, nil, manual); !errors.Is(err, ErrProbeNeedsContext) ||
		!strings.Contains(err.Error(), "no declaration or explicit register transport") {
		t.Fatalf("unbound private tail inherited its caller's signature: %v", err)
	}

	// Ordinary unresolved calls remain untyped. Changing the query fixture's
	// edge does not supply a declaration, register ABI or executable contract.
	file.Funcs[0].Instrs[3].Op = "CALL"
	file.Funcs = file.Funcs[:2]
	sigs, err := goSigsForAsmFile(pkg, file, testResolveSym("test/pkg"), "arm64", nil, nil, manual)
	if err != nil {
		t.Fatalf("goSigsForAsmFile() error = %v", err)
	}
	for _, want := range []string{"test/pkg.Plain", "runtime.cmp", "test/pkg.localhelper"} {
		if _, ok := sigs[want]; !ok {
			t.Fatalf("missing signature %q", want)
		}
	}
	if _, ok := sigs["test/pkg.undeclared_call"]; ok {
		t.Fatalf("ordinary unresolved CALL unexpectedly received a synthesized signature")
	}
	if _, ok := sigs["test/pkg.localtarget"]; ok {
		t.Fatal("unresolved local helper CALL unexpectedly received a synthesized signature")
	}

	builder := goSigBuilder{
		sigs:      map[string]FuncSig{},
		scope:     scope,
		sz:        types.SizesFor("gc", "arm64"),
		linknames: map[string]string{"runtime.cmp": "cmp"},
		pkgPath:   "test/pkg",
		resolve:   testResolveSym("test/pkg"),
		goarch:    "arm64",
	}
	if err := builder.addGoDeclSig("runtime·cmp"); err != nil {
		t.Fatalf("addGoDeclSig(linkname) error = %v", err)
	}
	if err := builder.addGoDeclSig("·helper"); err != nil {
		t.Fatalf("addGoDeclSig(local) error = %v", err)
	}
	if err := builder.addGoDeclSig("missing.remote"); err != nil {
		t.Fatalf("addGoDeclSig(missing) error = %v", err)
	}
	if _, ok := builder.sigs["runtime.cmp"]; !ok {
		t.Fatalf("addGoDeclSig(linkname) did not record runtime.cmp")
	}

	badPkg := mustGoPackage(t, "bad/pkg", `package badpkg
var helper int
`)
	badBuilder := goSigBuilder{
		sigs:    map[string]FuncSig{},
		scope:   badPkg.Types.Scope(),
		sz:      types.SizesFor("gc", "arm64"),
		pkgPath: "bad/pkg",
		resolve: testResolveSym("bad/pkg"),
		goarch:  "arm64",
	}
	badFile := &File{Funcs: []Func{{Sym: "·helper"}}}
	if err := badBuilder.addDeclaredFuncSigs(badFile); err == nil {
		t.Fatalf("addDeclaredFuncSigs(non-func) unexpectedly succeeded")
	}
	if err := builder.addDeclaredFuncSigs(&File{Funcs: []Func{{Sym: "·missing"}}}); err == nil {
		t.Fatalf("addDeclaredFuncSigs(missing) unexpectedly succeeded")
	}
	nilLocalBuilder := goSigBuilder{
		sigs:      map[string]FuncSig{},
		localSigs: nil,
		scope:     scope,
		sz:        types.SizesFor("gc", "arm64"),
		pkgPath:   "test/pkg",
		resolve:   testResolveSym("test/pkg"),
		goarch:    "arm64",
	}
	if err := nilLocalBuilder.addDeclaredFuncSigs(&File{Funcs: []Func{{Sym: "missing_local<>"}}}); err != nil {
		t.Fatalf("addDeclaredFuncSigs(local with nil map) error = %v", err)
	}
	if _, err := goSigsForAsmFile(pkg, file, testResolveSym("test/pkg"), "madeup", nil, nil, nil); err == nil {
		t.Fatalf("goSigsForAsmFile(madeup) unexpectedly succeeded")
	}
}

func TestTranslateGoModuleErrorCoverage(t *testing.T) {
	pkg := mustGoPackage(t, "test/pkg", `package testpkg
const Answer = 42
func F(x int) int { return x }
`)
	if _, err := TranslateGoModule(GoPackage{}, nil, GoModuleOptions{GOARCH: "arm64"}); err == nil {
		t.Fatalf("TranslateGoModule(empty pkg) unexpectedly succeeded")
	}
	if _, err := TranslateGoModule(GoPackage{Path: "x"}, nil, GoModuleOptions{GOARCH: "arm64"}); err == nil {
		t.Fatalf("TranslateGoModule(missing types) unexpectedly succeeded")
	}
	if _, err := TranslateGoModule(pkg, nil, GoModuleOptions{}); err == nil {
		t.Fatalf("TranslateGoModule(empty arch) unexpectedly succeeded")
	}
	if _, err := TranslateGoModule(pkg, []byte("TEXT ·F(SB"), GoModuleOptions{GOARCH: "arm64"}); err == nil {
		t.Fatalf("TranslateGoModule(parse error) unexpectedly succeeded")
	}
	if _, err := TranslateGoModule(pkg, []byte(`TEXT ·F(SB),NOSPLIT,$0-0
RET
`), GoModuleOptions{
		GOARCH: "arm64",
		KeepFunc: func(textSym, resolved string) bool {
			return false
		},
	}); err == nil || !strings.Contains(err.Error(), "empty file") {
		t.Fatalf("TranslateGoModule(KeepFunc=false) error = %v", err)
	}

	tr, err := TranslateGoModule(pkg, []byte(`TEXT ·F(SB),NOSPLIT,$0-8
MOVD $const_Answer, R0
RET
`), GoModuleOptions{
		FileName:     "f_arm64.s",
		GOARCH:       "arm64",
		TargetTriple: "aarch64-unknown-linux-gnu",
		ResolveSym:   testResolveSym("test/pkg"),
	})
	if err != nil {
		t.Fatalf("TranslateGoModule(const expansion) error = %v", err)
	}
	defer tr.Module.Dispose()
	if len(tr.Functions) != 1 || tr.Signatures["test/pkg.F"].Name != "test/pkg.F" {
		t.Fatalf("TranslateGoModule() returned unexpected metadata: %#v %#v", tr.Functions, tr.Signatures["test/pkg.F"])
	}

	pkgTypes := pkg.Types
	imports := map[string]*types.Package{
		"other/pkg": types.NewPackage("other/pkg", "other"),
	}
	cobj := types.NewConst(token.NoPos, imports["other/pkg"], "Limit", types.Typ[types.Int], constant.MakeInt64(7))
	imports["other/pkg"].Scope().Insert(cobj)
	expanded := string(goExpandConsts([]byte("MOVD other/pkg.Value+const_Limit(SB), R0\nMOVD $const_Answer, R1\n"), pkgTypes, imports))
	if !strings.Contains(expanded, "other/pkg.Value+7(SB)") || !strings.Contains(expanded, "$42") {
		t.Fatalf("goExpandConsts() = %q", expanded)
	}
}

func TestTranslateGoModuleUndeclaredLocalTrampoline(t *testing.T) {
	pkg := mustGoPackage(t, "test/pkg", `package testpkg
func F() {}
`)
	_, err := TranslateGoModule(pkg, []byte(`TEXT local_trampoline<>(SB),NOSPLIT,$0-0
JMP external_symbol(SB)
`), GoModuleOptions{
		GOARCH:       "arm64",
		TargetTriple: "aarch64-unknown-linux-gnu",
		ResolveSym:   testResolveSym("test/pkg"),
	})
	if err == nil || !strings.Contains(err.Error(), "missing signature for file-local assembly") {
		t.Fatalf("undeclared trampoline must not receive a guessed void signature: %v", err)
	}
}
