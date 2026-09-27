package main

import (
	"errors"
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

func TestLoadPkgsAvoidsTransitiveSyntax(t *testing.T) {
	pkgs, err := loadPkgs(runtime.GOOS, runtime.GOARCH, []string{"crypto/md5"}, nil, "", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Types == nil {
		t.Fatalf("loaded packages = %d, want one typed package", len(pkgs))
	}
	if pkgs[0].Types.Scope().Lookup("block") == nil {
		t.Fatal("unexported assembly declaration was not loaded")
	}

	if len(pkgs[0].Types.Imports()) == 0 {
		t.Fatal("package type information lost direct imports")
	}
	typedImports := 0
	for path, imported := range pkgs[0].Imports {
		if imported.Types != nil {
			typedImports++
		}
		if len(imported.Syntax) != 0 {
			t.Fatalf("dependency %s retained %d syntax trees", path, len(imported.Syntax))
		}
	}
	if typedImports == 0 {
		t.Fatal("package imports lost the types needed for assembly constants")
	}
}

func TestLoadLinknameSyntaxOnlyForRelevantTargetFiles(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.go")
	linked := filepath.Join(dir, "linked.go")
	if err := os.WriteFile(plain, []byte("package p\nfunc plain() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := "package p\n//go:linkname local example.com/remote.F\nfunc local() {}\n"
	if err := os.WriteFile(linked, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := &packages.Package{GoFiles: []string{plain, linked}}
	if err := loadLinknameSyntax(pkg); err != nil {
		t.Fatal(err)
	}
	if len(pkg.Syntax) != 1 {
		t.Fatalf("retained %d syntax trees, want only the linkname file", len(pkg.Syntax))
	}
	if got := linknameRemoteToLocal(pkg.Syntax)["example.com/remote.F"]; got != "local" {
		t.Fatalf("remote linkname resolves to %q, want local", got)
	}
}

func TestWASMABIForGoPackageTarget(t *testing.T) {
	if got := wasmABIForGoPackageTarget("wasm"); got != plan9asm.WASMABIGo {
		t.Fatalf("wasmABIForGoPackageTarget(wasm) = %v, want Go stack ABI", got)
	}
	for _, goarch := range []string{"amd64", "386", "arm", "arm64"} {
		if got := wasmABIForGoPackageTarget(goarch); got != plan9asm.WASMABIDirect {
			t.Fatalf("wasmABIForGoPackageTarget(%s) = %v, want direct ABI", goarch, got)
		}
	}
}

func TestLLCCompileArgsSelectsExplicitOptimizationLevel(t *testing.T) {
	for _, tc := range []struct {
		level int
		want  string
	}{
		{level: 0, want: "-O0"},
		{level: 2, want: "-O2"},
	} {
		args := llcCompileArgs("x86_64-unknown-linux-gnu", "amd64", "input.ll", "output.o", tc.level)
		if !containsArg(args, tc.want) {
			t.Errorf("level %d args = %v, want %s", tc.level, args, tc.want)
		}
	}
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func TestContainsTestAssembly(t *testing.T) {
	for _, name := range []string{"pkg/routine_test_amd64.s", "pkg/routine_test.s"} {
		if !containsTestAssembly([]string{name}) {
			t.Errorf("containsTestAssembly(%q) = false, want true", name)
		}
	}
	if containsTestAssembly([]string{"pkg/contest_amd64.s", "pkg/routine_amd64.s"}) {
		t.Fatal("containsTestAssembly accepted non-test assembly")
	}
}

func TestIsTestVariantPackage(t *testing.T) {
	base := &packages.Package{ID: "example.com/p", PkgPath: "example.com/p"}
	variant := &packages.Package{ID: "example.com/p [example.com/p.test]", PkgPath: "example.com/p"}
	if isTestVariantPackage(base) || !isTestVariantPackage(variant) {
		t.Fatalf("test variant classification: base=%v variant=%v", isTestVariantPackage(base), isTestVariantPackage(variant))
	}
}

func TestRunOneTargetUsesTestDeclarationForExactTestAssembly(t *testing.T) {
	report, _, err := runOneTarget(
		targetSpec{Goos: "linux", Goarch: "amd64"},
		[]string{"./testdata/testsignature"},
		nil,
		[]string{"testdata/testsignature/convert_test_amd64.s"},
		"github.com/xgo-dev/plan9asm/cmd/plan9asmll",
		t.TempDir(),
		false,
		0,
		true,
		false,
		false,
		filepath.Join("..", ".."),
		compileConfig{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if report.TotalAsm != 1 || report.Success != 1 || report.Failed != 0 {
		t.Fatalf("test assembly report = %#v, want one successful translation", report)
	}
}

func TestCompileOneExpandsGoAsmPackageConstants(t *testing.T) {
	typesPkg := types.NewPackage("example.com/constants", "constants")
	typesPkg.Scope().Insert(types.NewConst(token.NoPos, typesPkg, "q", types.Typ[types.UntypedInt], constant.MakeUint64(2013265921)))
	typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, "vectorConstant", types.NewSignatureType(nil, nil, nil, nil, nil, false)))
	pkg := &packages.Package{
		PkgPath: "example.com/constants",
		Types:   typesPkg,
		Imports: map[string]*packages.Package{},
	}
	dir := t.TempDir()
	asm := filepath.Join(dir, "constant_arm64.s")
	if err := os.WriteFile(asm, []byte("TEXT ·vectorConstant(SB),$0-0\n\tVMOVS $const_q, V0\n\tRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "constant.ll")
	if err := compileOne(pkg, plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu", asmTask{
		PkgPath: pkg.PkgPath,
		AsmFile: asm,
		OutLL:   out,
	}, false, compileConfig{}); err != nil {
		t.Fatal(err)
	}
	ir, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ir), "i32 2013265921") {
		t.Fatalf("translated package constant is absent from IR:\n%s", ir)
	}
}

func TestCompileOneInfersVoidABI0LocalHelperAtTargetWordSize(t *testing.T) {
	typesPkg := types.NewPackage("runtime", "runtime")
	voidSignature := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, "systemstack", voidSignature))
	pkg := &packages.Package{
		PkgPath:    typesPkg.Path(),
		Types:      typesPkg,
		TypesSizes: types.SizesFor("gc", "386"),
		Imports:    map[string]*packages.Package{},
	}
	dir := t.TempDir()
	asm := filepath.Join(dir, "asm_386.s")
	const source = `TEXT runtime·systemstack(SB),NOSPLIT,$0-0
	CALL gosave_systemstack_switch<>(SB)
	RET

TEXT gosave_systemstack_switch<>(SB),NOSPLIT,$0
	LEAL arg+0(FP), AX
	RET
`
	if err := os.WriteFile(asm, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "asm_386.ll")
	if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "386", "i386-unknown-linux-gnu", asmTask{
		PkgPath: pkg.PkgPath,
		AsmFile: asm,
		OutLL:   out,
	}, false, compileConfig{}); err != nil {
		t.Fatal(err)
	}
	ir, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`define void @"runtime.gosave_systemstack_switch$local"(i32 %arg0)`,
		`call void @"runtime.gosave_systemstack_switch$local"(i32 %`,
	} {
		if !strings.Contains(string(ir), want) {
			t.Fatalf("translated ABI0 local helper omitted %q:\n%s", want, ir)
		}
	}
}

func TestTryDeclSigResolvesSamePackageQualifiedPlan9Symbol(t *testing.T) {
	pkg := types.NewPackage("runtime/internal/atomic", "atomic")
	params := types.NewTuple(
		types.NewParam(token.NoPos, pkg, "ptr", types.NewPointer(types.Typ[types.Uint64])),
		types.NewParam(token.NoPos, pkg, "delta", types.Typ[types.Int64]),
	)
	results := types.NewTuple(types.NewParam(token.NoPos, pkg, "ret", types.Typ[types.Uint64]))
	signature := types.NewSignatureType(nil, nil, nil, params, results, false)
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "Xadd64", signature))

	got, _, ok, err := tryDeclSig(
		pkg.Scope(),
		"runtime∕internal∕atomic·Xadd64",
		"runtime/internal/atomic.Xadd64",
		nil,
		"386",
		types.SizesFor("gc", "386"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.Ret != plan9asm.I64 || len(got.Args) != 2 || got.Args[0] != plan9asm.Ptr || got.Args[1] != plan9asm.I64 {
		t.Fatalf("qualified declaration signature = %#v, ok=%v; want (ptr, i64) i64", got, ok)
	}
}

func TestTryDeclSigUsesOfficialWASMFrameWordSize(t *testing.T) {
	pkg := types.NewPackage("internal/bytealg", "bytealg")
	params := types.NewTuple(
		types.NewParam(token.NoPos, pkg, "a", types.Typ[types.String]),
		types.NewParam(token.NoPos, pkg, "b", types.Typ[types.String]),
	)
	results := types.NewTuple(types.NewParam(token.NoPos, pkg, "ret", types.Typ[types.Int]))
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "abigen_runtime_cmpstring", types.NewSignatureType(nil, nil, nil, params, results, false)))

	sig, argSize, ok, err := tryDeclSig(
		pkg.Scope(),
		"runtime·cmpstring",
		"runtime.cmpstring",
		map[string]string{"runtime.cmpstring": "abigen_runtime_cmpstring"},
		"wasm",
		types.SizesFor("gc", "wasm"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("runtime.cmpstring declaration was not resolved")
	}
	var paramOffsets []int64
	for _, slot := range sig.Frame.Params {
		paramOffsets = append(paramOffsets, slot.Offset)
	}
	if want := []int64{0, 8, 16, 24}; !reflect.DeepEqual(paramOffsets, want) {
		t.Fatalf("wasm frame parameter offsets = %v, want %v", paramOffsets, want)
	}
	if len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Offset != 32 || argSize != 40 {
		t.Fatalf("wasm result frame = %#v, arg size = %d; want result at 32 and size 40", sig.Frame.Results, argSize)
	}
}

func TestSigsForAsmFileInfersWASMLocalNativeSignature(t *testing.T) {
	typesPkg := types.NewPackage("internal/bytealg", "bytealg")
	pkg := &packages.Package{
		PkgPath:    typesPkg.Path(),
		Types:      typesPkg,
		TypesSizes: types.SizesFor("gc", "wasm"),
	}
	file, err := plan9asm.Parse(plan9asm.ArchWASM, `TEXT memchr<>(SB), NOSPLIT, $0
	Get R0
	I32Load8U $0
	Get R1
	I32Eq
	Get R2
	Select
	Return
`)
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "wasm")
	if err != nil {
		t.Fatal(err)
	}
	wantName := pkg.PkgPath + ".memchr$local"
	got, ok := sigs[wantName]
	if !ok {
		t.Fatalf("local wasm signature %q is missing; signatures: %#v", wantName, sigs)
	}
	wantArgs := []plan9asm.LLVMType{plan9asm.I32, plan9asm.I32, plan9asm.I32}
	wantRegs := []plan9asm.Reg{"R0", "R1", "R2"}
	if !reflect.DeepEqual(got.Args, wantArgs) || !reflect.DeepEqual(got.ArgRegs, wantRegs) || got.Ret != plan9asm.I32 || !got.WASMNative {
		t.Fatalf("local wasm signature = %#v; want args %v in %v, i32 return, native ABI", got, wantArgs, wantRegs)
	}
}

func TestSigsForAsmFileUsesGoWASMSpecialNativeSignature(t *testing.T) {
	typesPkg := types.NewPackage("runtime", "runtime")
	pkg := &packages.Package{
		PkgPath:    typesPkg.Path(),
		Types:      typesPkg,
		TypesSizes: types.SizesFor("gc", "wasm"),
	}
	file, err := plan9asm.Parse(plan9asm.ArchWASM, `TEXT gcWriteBarrier<>(SB), NOSPLIT, $0
	Get R1
	Get R0
	I64Add
	Set R1
	Get R1
	I64Load 0(R2)
	I64LeU
	If
		Get R1
		Get R0
		I64Sub
		Return
	End
`)
	if err != nil {
		t.Fatal(err)
	}
	sigs, _, err := sigsForAsmFile(pkg, file, resolveSymFunc(pkg.PkgPath), "wasm")
	if err != nil {
		t.Fatal(err)
	}
	wantName := pkg.PkgPath + ".gcWriteBarrier$local"
	got := sigs[wantName]
	if wantArgs := []plan9asm.LLVMType{plan9asm.I64}; !reflect.DeepEqual(got.Args, wantArgs) || !reflect.DeepEqual(got.ArgRegs, []plan9asm.Reg{"R0"}) || got.Ret != plan9asm.I64 || !got.WASMNative {
		t.Fatalf("special local wasm signature = %#v; want R0:i64 -> i64 native ABI", got)
	}
}

func TestSigsForAsmFileUsesGoWASMSpecialReferencedSignature(t *testing.T) {
	typesPkg := types.NewPackage("runtime", "runtime")
	pkg := &packages.Package{
		PkgPath:    typesPkg.Path(),
		Types:      typesPkg,
		TypesSizes: types.SizesFor("gc", "wasm"),
	}
	file, err := plan9asm.Parse(plan9asm.ArchWASM, "TEXT wasm_export_run(SB),NOSPLIT,$0\n\tCall wasm_pc_f_loop(SB)\n\tReturn\n")
	if err != nil {
		t.Fatal(err)
	}
	sigs, _, err := sigsForAsmFile(pkg, file, resolveSymFunc(pkg.PkgPath), "wasm")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := sigs["wasm_pc_f_loop"]
	if !ok || len(got.Args) != 0 || got.Ret != plan9asm.Void || !got.WASMNative {
		t.Fatalf("referenced special wasm signature = %#v, present=%v; want () -> void native ABI", got, ok)
	}
}

func TestSigsForAsmFileKeepsWASMLocalRETHelperOnGoABI(t *testing.T) {
	typesPkg := types.NewPackage("runtime", "runtime")
	voidSig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, "caller", voidSig))
	pkg := &packages.Package{
		PkgPath:    typesPkg.Path(),
		Types:      typesPkg,
		TypesSizes: types.SizesFor("gc", "wasm"),
	}
	file, err := plan9asm.Parse(plan9asm.ArchWASM, `TEXT ·caller(SB), NOSPLIT, $0-0
	CALL callRet<>(SB)
	RET
TEXT callRet<>(SB), NOSPLIT, $40-0
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	sigs, _, err := sigsForAsmFile(pkg, file, resolveSymFunc(pkg.PkgPath), "wasm")
	if err != nil {
		t.Fatal(err)
	}
	got := sigs[pkg.PkgPath+".callRet$local"]
	if got.WASMNative {
		t.Fatalf("RET-based local helper signature = %#v; want Go WebAssembly ABI", got)
	}
}

func TestFallbackSigIncludesAddressedFrameParameters(t *testing.T) {
	fn := plan9asm.Func{
		Sym: "kernelCAS64<>",
		Instrs: []plan9asm.Instr{
			{Op: "MOVW", Args: []plan9asm.Operand{{Kind: plan9asm.OpFP, FPName: "addr", FPOffset: 0}, {Kind: plan9asm.OpReg, Reg: "R2"}}},
			{Op: "MOVW", Args: []plan9asm.Operand{{Kind: plan9asm.OpFPAddr, FPName: "oldval", FPOffset: 4}, {Kind: plan9asm.OpReg, Reg: "R0"}}},
			{Op: "MOVW", Args: []plan9asm.Operand{{Kind: plan9asm.OpFPAddr, FPName: "newval", FPOffset: 12}, {Kind: plan9asm.OpReg, Reg: "R1"}}},
			{Op: "MOVW", Args: []plan9asm.Operand{{Kind: plan9asm.OpReg, Reg: "R0"}, {Kind: plan9asm.OpFP, FPName: "ret", FPOffset: 20}}},
		},
	}
	sig := fallbackSigForAsmFunc(fn, "example.kernelCAS64$local", "arm")
	var offsets []int64
	for _, slot := range sig.Frame.Params {
		offsets = append(offsets, slot.Offset)
	}
	want := []int64{0, 4, 12}
	if !reflect.DeepEqual(offsets, want) {
		t.Fatalf("fallback frame parameter offsets = %v, want %v", offsets, want)
	}
}

func TestSigsForAsmFileDiscoversRETTailTarget(t *testing.T) {
	typesPkg := types.NewPackage("example.com/retjmp", "retjmp")
	voidSig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, "f", voidSig))
	typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, "f2", voidSig))
	pkg := &packages.Package{
		PkgPath:    typesPkg.Path(),
		Types:      typesPkg,
		TypesSizes: types.SizesFor("gc", "wasm"),
	}
	file, err := plan9asm.Parse(plan9asm.ArchWASM, "TEXT ·f(SB), NOSPLIT, $0-0\n\tRET ·f2(SB)\n")
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "wasm")
	if err != nil {
		t.Fatal(err)
	}
	want := pkg.PkgPath + ".f2"
	if sig, ok := sigs[want]; !ok || sig.Name != want || sig.Ret != plan9asm.Void {
		t.Fatalf("RET tail target signature = %#v, present=%v; want void signature for %q", sig, ok, want)
	}
}

func TestSigsForAsmFilePreservesLocalMarkerOnDirectCallTarget(t *testing.T) {
	typesPkg := types.NewPackage("example.com/caller", "caller")
	voidSig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, "MoreStack", voidSig))
	pkg := &packages.Package{
		PkgPath:    typesPkg.Path(),
		Types:      typesPkg,
		TypesSizes: types.SizesFor("gc", "amd64"),
	}
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT ·MoreStack(SB),NOSPLIT,$0-0\n\tCALL runtime·morestack_noctxt<>(SB)\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	sigs, _, err := sigsForAsmFile(pkg, file, resolveSymFunc(pkg.PkgPath), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sigs["runtime.morestack_noctxt$local"]; !ok {
		t.Fatalf("local direct-call target signature missing; signatures: %#v", sigs)
	}
}

func TestSigsForAsmFileDiscoversAllDirectCallOpcodes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		goarch string
		arch   plan9asm.Arch
		op     string
	}{
		{name: "wasm native call", goarch: "wasm", arch: plan9asm.ArchWASM, op: "Call"},
		{name: "wasm no-resume call", goarch: "wasm", arch: plan9asm.ArchWASM, op: "CALLNORESUME"},
		{name: "machine call", goarch: "amd64", arch: plan9asm.ArchAMD64, op: "CALL"},
		{name: "arm branch-link", goarch: "arm", arch: plan9asm.ArchARM, op: "BL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			typesPkg := types.NewPackage("example.com/calls", "calls")
			voidSig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
			typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, "caller", voidSig))
			typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, "target", voidSig))
			pkg := &packages.Package{
				PkgPath:    typesPkg.Path(),
				Types:      typesPkg,
				TypesSizes: types.SizesFor("gc", tc.goarch),
			}
			file, err := plan9asm.Parse(tc.arch, "TEXT ·caller(SB),NOSPLIT,$0-0\n\t"+tc.op+" ·target(SB)\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			sigs, _, err := sigsForAsmFile(pkg, file, resolveSymFunc(pkg.PkgPath), tc.goarch)
			if err != nil {
				t.Fatal(err)
			}
			want := pkg.PkgPath + ".target"
			if sig, ok := sigs[want]; !ok || sig.Name != want || sig.Ret != plan9asm.Void {
				t.Fatalf("%s target signature = %#v, present=%v; want void signature for %q", tc.op, sig, ok, want)
			}
		})
	}
}

func TestSigsForAsmFileInfersUndeclaredTailForwarderFromDeclaredTarget(t *testing.T) {
	typesPkg := types.NewPackage("example.com/fakecgo", "fakecgo")
	params := types.NewTuple(
		types.NewParam(token.NoPos, typesPkg, "g", types.NewPointer(types.Typ[types.Uint8])),
		types.NewParam(token.NoPos, typesPkg, "setg", types.Typ[types.Uintptr]),
	)
	voidSig := types.NewSignatureType(nil, nil, nil, params, nil, false)
	typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, "x_cgo_init", voidSig))
	pkg := &packages.Package{
		PkgPath:    typesPkg.Path(),
		Types:      typesPkg,
		TypesSizes: types.SizesFor("gc", "386"),
	}
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT x_cgo_init_trampoline(SB),NOSPLIT|NOFRAME,$0\n\tJMP ·x_cgo_init(SB)\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "386")
	if err != nil {
		t.Fatal(err)
	}
	caller := sigs["x_cgo_init_trampoline"]
	target := sigs[pkg.PkgPath+".x_cgo_init"]
	if caller.Ret != plan9asm.Void || len(caller.Args) != 2 || caller.Args[0] != plan9asm.Ptr || caller.Args[1] != plan9asm.I32 {
		t.Fatalf("tail-forwarder signature = %#v, target = %#v; want (ptr, i32) void inherited from declared target", caller, target)
	}
}

func TestSigsForAsmFileInfersPureTailForwarderFromABI0Body(t *testing.T) {
	// The Go declarations may be disabled by build tags while the assembly
	// remains selected (gomlx/compute uses goexperiment.simd this way).
	for _, tc := range []struct {
		arch                      plan9asm.Arch
		goarch, move, branch, reg string
		word                      int
	}{
		{plan9asm.ArchAMD64, "amd64", "MOVQ", "JMP", "AX", 8},
		{plan9asm.ArchAMD64, "386", "MOVL", "JMP", "AX", 4},
		{plan9asm.ArchARM, "arm", "MOVW", "B", "R0", 4},
		{plan9asm.ArchARM64, "arm64", "MOVD", "B", "R0", 8},
	} {
		t.Run(tc.goarch, func(t *testing.T) {
			typesPkg := types.NewPackage("example.com/forward", "forward")
			pkg := &packages.Package{PkgPath: typesPkg.Path(), Types: typesPkg, TypesSizes: types.SizesFor("gc", tc.goarch)}
			for _, body := range []string{
				"TEXT ·forward(SB),$0-%d\n\t%s ·body(SB)\n",
				"TEXT ·forward(SB),$0-%d\n\t%s ·middle(SB)\nTEXT ·middle(SB),$0\n\t" + tc.branch + " ·body(SB)\n",
			} {
				source := fmt.Sprintf(body, tc.word, tc.branch) + fmt.Sprintf("TEXT ·body(SB),$0-%d\n\t%s arg+0(FP), %s\n\tRET\n", tc.word, tc.move, tc.reg)
				file, err := plan9asm.Parse(tc.arch, source)
				if err != nil {
					t.Fatal(err)
				}
				sigs, _, err := sigsForAsmFile(pkg, file, resolveSymFunc(pkg.PkgPath), tc.goarch)
				if err != nil {
					t.Fatal(err)
				}
				want := sigs[pkg.PkgPath+".body"]
				got := sigs[pkg.PkgPath+".forward"]
				want.Name = got.Name
				if !reflect.DeepEqual(got, want) || got.Ret != plan9asm.Void || len(got.Args) != 1 {
					t.Fatalf("pure tail forwarder = %#v, want body ABI %#v", got, want)
				}
				if _, err := plan9asm.Translate(file, plan9asm.Options{Goarch: tc.goarch, ResolveSym: resolveSymFunc(pkg.PkgPath), Sigs: sigs}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestSigsForAsmFileInfersLocalTailTargetFromDeclaredCaller(t *testing.T) {
	typesPkg := types.NewPackage("internal/runtime/atomic", "atomic")
	params := types.NewTuple(
		types.NewParam(token.NoPos, typesPkg, "addr", types.NewPointer(types.Typ[types.Uint64])),
		types.NewParam(token.NoPos, typesPkg, "delta", types.Typ[types.Int64]),
	)
	results := types.NewTuple(types.NewParam(token.NoPos, typesPkg, "new", types.Typ[types.Uint64]))
	typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, "Xadd64", types.NewSignatureType(nil, nil, nil, params, results, false)))
	pkg := &packages.Package{
		PkgPath:    typesPkg.Path(),
		Types:      typesPkg,
		TypesSizes: types.SizesFor("gc", "arm"),
	}
	file, err := plan9asm.Parse(plan9asm.ArchARM, `TEXT ·Xadd64(SB),NOSPLIT,$-4-20
	B armXadd64<>(SB)
TEXT armXadd64<>(SB),NOSPLIT,$0-20
	MOVW R4, new_lo+12(FP)
	MOVW R5, new_hi+16(FP)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "arm")
	if err != nil {
		t.Fatal(err)
	}
	caller := sigs[pkg.PkgPath+".Xadd64"]
	target := sigs[pkg.PkgPath+".armXadd64$local"]
	caller.Name = ""
	target.Name = ""
	if !reflect.DeepEqual(target, caller) {
		t.Fatalf("local tail target signature = %#v, want declared caller signature %#v", target, caller)
	}
}

func TestSigsForAsmFileInfersSharedLocalTailTargetReturnFromDeclaredCallers(t *testing.T) {
	typesPkg := types.NewPackage("internal/bytealg", "bytealg")
	boolResult := types.NewTuple(types.NewParam(token.NoPos, typesPkg, "equal", types.Typ[types.Bool]))
	for name, params := range map[string]*types.Tuple{
		"Equal": types.NewTuple(
			types.NewParam(token.NoPos, typesPkg, "a", types.NewPointer(types.Typ[types.Uint8])),
			types.NewParam(token.NoPos, typesPkg, "b", types.NewPointer(types.Typ[types.Uint8])),
			types.NewParam(token.NoPos, typesPkg, "size", types.Typ[types.Uintptr]),
		),
		"EqualVarlen": types.NewTuple(
			types.NewParam(token.NoPos, typesPkg, "a", types.NewPointer(types.Typ[types.Uint8])),
			types.NewParam(token.NoPos, typesPkg, "b", types.NewPointer(types.Typ[types.Uint8])),
		),
	} {
		typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, name, types.NewSignatureType(nil, nil, nil, params, boolResult, false)))
	}
	pkg := &packages.Package{
		PkgPath:    typesPkg.Path(),
		Types:      typesPkg,
		TypesSizes: types.SizesFor("gc", "386"),
	}
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, `TEXT ·Equal(SB),NOSPLIT,$0-13
	JMP memeqbody<>(SB)
TEXT ·EqualVarlen(SB),NOSPLIT,$0-9
	JMP memeqbody<>(SB)
TEXT memeqbody<>(SB),NOSPLIT,$0-0
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "386")
	if err != nil {
		t.Fatal(err)
	}
	target := sigs[pkg.PkgPath+".memeqbody$local"]
	if target.Ret != plan9asm.I1 {
		t.Fatalf("shared local tail target signature = %#v, want common declared return i1", target)
	}
	if len(target.Args) != 0 || len(target.Frame.Params) != 0 || len(target.Frame.Results) != 0 {
		t.Fatalf("shared local tail target inherited incompatible caller frame: %#v", target)
	}
}

func TestSigsForAsmFileInfersSharedABI0ResultPointerHelper(t *testing.T) {
	typesPkg := types.NewPackage("example.com/hash", "hash")
	hashType := types.NewNamed(
		types.NewTypeName(token.NoPos, typesPkg, "Hash128", nil),
		types.NewStruct([]*types.Var{
			types.NewField(token.NoPos, typesPkg, "Lo", types.Typ[types.Uint64], false),
			types.NewField(token.NoPos, typesPkg, "Hi", types.Typ[types.Uint64], false),
		}, nil),
		nil,
	)
	for name, params := range map[string]*types.Tuple{
		"HashPointerAndSeed": types.NewTuple(
			types.NewParam(token.NoPos, typesPkg, "p", types.Typ[types.UnsafePointer]),
			types.NewParam(token.NoPos, typesPkg, "seed", types.Typ[types.Uintptr]),
		),
		"HashPointer": types.NewTuple(
			types.NewParam(token.NoPos, typesPkg, "p", types.Typ[types.UnsafePointer]),
		),
	} {
		results := types.NewTuple(types.NewParam(token.NoPos, typesPkg, "ret", hashType))
		sig := types.NewSignatureType(nil, nil, nil, params, results, false)
		typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, name, sig))
	}
	pkg := &packages.Package{
		PkgPath:    typesPkg.Path(),
		Types:      typesPkg,
		TypesSizes: types.SizesFor("gc", "amd64"),
	}
	const source = `TEXT ·HashPointerAndSeed(SB),NOSPLIT,$0-32
	MOVQ p+0(FP), AX
	MOVQ seed+8(FP), CX
	LEAQ ret+16(FP), DX
	JMP hashbody<>(SB)
TEXT ·HashPointer(SB),NOSPLIT,$0-24
	MOVQ p+0(FP), AX
	MOVQ $0, CX
	LEAQ ret+8(FP), DX
	JMP hashbody<>(SB)
TEXT hashbody<>(SB),NOSPLIT,$0-0
	MOVQ AX, (DX)
	MOVQ CX, 8(DX)
	RET
`
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	helper := sigs[pkg.PkgPath+".hashbody$local"]
	if helper.Ret != plan9asm.Void {
		t.Fatalf("shared output-pointer helper return = %s, want void", helper.Ret)
	}
	for _, reg := range []plan9asm.Reg{plan9asm.AX, plan9asm.CX, plan9asm.DX} {
		found := false
		for _, got := range helper.ArgRegs {
			found = found || got == reg
		}
		if !found {
			t.Fatalf("shared output-pointer helper omitted live-in register %s: %+v", reg, helper.ArgRegs)
		}
	}
	if len(helper.Args) != len(helper.ArgRegs) || len(helper.Frame.Results) != 0 {
		t.Fatalf("shared helper has inconsistent custom ABI: %+v", helper)
	}

	dir := t.TempDir()
	asm := filepath.Join(dir, "asm_amd64.s")
	if err := os.WriteFile(asm, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "asm_amd64.ll")
	if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu", asmTask{
		PkgPath: pkg.PkgPath,
		AsmFile: asm,
		OutLL:   out,
	}, false, compileConfig{}); err != nil {
		t.Fatal(err)
	}
	ir, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`define void @"example.com/hash.hashbody$local"(`,
		`call void @"example.com/hash.hashbody$local"(`,
		`ret { i64, i64 }`,
	} {
		if !strings.Contains(string(ir), want) {
			t.Fatalf("shared output-pointer IR omitted %q", want)
		}
	}

	for _, test := range []struct {
		name   string
		source string
	}{
		{
			name: "helper does not write through result pointer",
			source: strings.NewReplacer(
				"MOVQ AX, (DX)", "MOVQ AX, BX",
				"MOVQ CX, 8(DX)", "MOVQ CX, SI",
			).Replace(source),
		},
		{
			name:   "callers disagree on result pointer register",
			source: strings.Replace(source, "LEAQ ret+8(FP), DX", "LEAQ ret+8(FP), SI", 1),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed, err := plan9asm.Parse(plan9asm.ArchAMD64, test.source)
			if err != nil {
				t.Fatal(err)
			}
			changedSigs, _, err := sigsForAsmFile(pkg, changed, resolve, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if changedSigs[pkg.PkgPath+".hashbody$local"].Ret == plan9asm.Void {
				t.Fatal("bridged helper without evidence for shared result pointer")
			}
		})
	}
}

func TestSigsForAsmFileARM64TailHelperBorrowsCallerFrame(t *testing.T) {
	typesPkg := types.NewPackage("example.com/ring0", "ring0")
	for _, name := range []string{"El1Sync", "HaltEl1ExceptionAndResume"} {
		sig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
		typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, name, sig))
	}
	pkg := &packages.Package{
		PkgPath:    typesPkg.Path(),
		Types:      typesPkg,
		TypesSizes: types.SizesFor("gc", "arm64"),
	}
	const source = `TEXT ·El1Sync(SB),NOSPLIT,$0-0
	MOVD $7, R3
	MOVD R3, 8(RSP)
	B ·HaltEl1ExceptionAndResume(SB)
TEXT ·HaltEl1ExceptionAndResume(SB),NOSPLIT,$0-0
	MOVD vector+0(FP), R3
	RET
`
	file, err := plan9asm.Parse(plan9asm.ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs, _, err := sigsForAsmFile(pkg, file, resolveSymFunc(pkg.PkgPath), "arm64")
	if err != nil {
		t.Fatal(err)
	}
	helper := sigs[pkg.PkgPath+".HaltEl1ExceptionAndResume"]
	if len(helper.Args) != 1 || helper.Args[0] != plan9asm.I64 ||
		len(helper.Frame.Params) != 1 || helper.Frame.Params[0].Offset != 0 {
		t.Fatalf("tail helper did not borrow caller's ABI0 frame: %+v", helper)
	}

	dir := t.TempDir()
	asm := filepath.Join(dir, "entry_arm64.s")
	if err := os.WriteFile(asm, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "entry_arm64.ll")
	if err := compileOne(pkg, plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu", asmTask{
		PkgPath: pkg.PkgPath,
		AsmFile: asm,
		OutLL:   out,
	}, false, compileConfig{}); err != nil {
		t.Fatal(err)
	}
	ir, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`define void @"example.com/ring0.HaltEl1ExceptionAndResume"(i64 %arg0)`,
		`call void @"example.com/ring0.HaltEl1ExceptionAndResume"(i64 %`,
	} {
		if !strings.Contains(string(ir), want) {
			t.Fatalf("borrowed-frame IR omitted %q:\n%s", want, ir)
		}
	}
}

func TestValidateDeclaredTextArgSizesClassifiesOnlyExplicitABIMismatches(t *testing.T) {
	resolve := func(sym string) string { return "example.com/ext." + strings.TrimPrefix(sym, "·") }
	declared := map[string]int64{"example.com/ext.StructFieldB": 17}

	tests := []struct {
		name    string
		text    string
		argSize int64
		wantErr bool
	}{
		{name: "wrong explicit size", text: "TEXT ·StructFieldB(SB), $0-25", argSize: 25, wantErr: true},
		{name: "matching explicit size", text: "TEXT ·StructFieldB(SB), $0-17", argSize: 17},
		{name: "legacy zero size", text: "TEXT ·StructFieldB(SB), $0-0"},
		{name: "omitted argument size", text: "TEXT ·StructFieldB(SB), $0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file := &plan9asm.File{Funcs: []plan9asm.Func{{
				Sym:     "·StructFieldB",
				ArgSize: test.argSize,
				Instrs:  []plan9asm.Instr{{Op: plan9asm.OpTEXT, Raw: test.text}},
			}}}
			err := validateDeclaredTextArgSizes(file, resolve, declared, "386")
			var mismatch *asmABINotApplicableError
			if test.wantErr {
				if !errors.As(err, &mismatch) {
					t.Fatalf("validateDeclaredTextArgSizes() error = %v, want asmABINotApplicableError", err)
				}
				if mismatch.Symbol != "example.com/ext.StructFieldB" || mismatch.DeclaredArgSize != test.argSize || mismatch.ExpectedArgSize != 17 || mismatch.Goarch != "386" {
					t.Fatalf("mismatch = %#v", mismatch)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateDeclaredTextArgSizes() error = %v", err)
			}
		})
	}
}

func TestTryDeclSigDoesNotPadVoidArgumentFrame(t *testing.T) {
	tests := []struct {
		name    string
		goarch  string
		params  []types.Type
		results []types.Type
		want    int64
	}{
		{name: "amd64 uint32 void", goarch: "amd64", params: []types.Type{types.Typ[types.Uint32]}, want: 4},
		{name: "arm64 uint32 void", goarch: "arm64", params: []types.Type{types.Typ[types.Uint32]}, want: 4},
		{name: "amd64 slice and uint32 void", goarch: "amd64", params: []types.Type{types.NewSlice(types.Typ[types.Byte]), types.Typ[types.Uint32]}, want: 28},
		{name: "amd64 uint32 result remains word aligned", goarch: "amd64", params: []types.Type{types.Typ[types.Uint32]}, results: []types.Type{types.Typ[types.Uint32]}, want: 12},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkg := types.NewPackage("example.com/frame", "frame")
			vars := func(items []types.Type) *types.Tuple {
				out := make([]*types.Var, len(items))
				for i, item := range items {
					out[i] = types.NewParam(token.NoPos, pkg, "", item)
				}
				return types.NewTuple(out...)
			}
			sig := types.NewSignatureType(nil, nil, nil, vars(test.params), vars(test.results), false)
			pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "frame", sig))
			_, got, ok, err := tryDeclSig(pkg.Scope(), "·frame", pkg.Path()+".frame", nil, test.goarch, types.SizesFor("gc", test.goarch))
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("tryDeclSig did not find declaration")
			}
			if got != test.want {
				t.Fatalf("TEXT argument size = %d, want %d", got, test.want)
			}
		})
	}
}

func TestReadAsmSourceExpandsLocalIncludesRecursively(t *testing.T) {
	dir := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ops.h", "#define STEP(a, b) ADDQ a, b\n")
	write("macros.h", "#include \"ops.h\"\n#define ROUND(a, b) STEP(a, b)\n")
	write("macro_amd64.s", "#include \"textflag.h\"\n#include \"macros.h\"\nTEXT ·macro(SB),NOSPLIT,$0-0\nROUND(AX, BX)\nRET\n")

	src, err := readAsmSource(filepath.Join(dir, "macro_amd64.s"), dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), `#include "macros.h"`) || !strings.Contains(string(src), "#define STEP") {
		t.Fatalf("local include was not expanded:\n%s", src)
	}
	if strings.Contains(string(src), `#include "textflag.h"`) || !strings.Contains(string(src), "#define NOSPLIT") {
		t.Fatalf("standard textflag.h was not expanded from GOROOT:\n%s", src)
	}
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, string(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := file.Funcs[0].Instrs[1].Op; got != plan9asm.Op("ADDQ") {
		t.Fatalf("expanded opcode = %s, want ADDQ", got)
	}
}

func TestReadAsmSourceExpandsStandardFuncdataMacros(t *testing.T) {
	dir := t.TempDir()
	asm := filepath.Join(dir, "macro_amd64.s")
	src := `#include "funcdata.h"
TEXT ·macro(SB),NOSPLIT,$0-0
GO_ARGS
GO_RESULTS_INITIALIZED
NO_LOCAL_POINTERS
RET
`
	if err := os.WriteFile(asm, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	expanded, err := readAsmSource(asm, dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(expanded), `#include "funcdata.h"`) || !strings.Contains(string(expanded), "#define GO_ARGS") {
		t.Fatalf("standard funcdata.h was not expanded from GOROOT:\n%s", expanded)
	}
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, string(expanded))
	if err != nil {
		t.Fatal(err)
	}
	var got []plan9asm.Op
	for _, ins := range file.Funcs[0].Instrs {
		got = append(got, ins.Op)
	}
	want := []plan9asm.Op{"TEXT", "FUNCDATA", "PCDATA", "FUNCDATA", plan9asm.OpRET}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expanded funcdata ops = %v, want %v", got, want)
	}
}

func TestReadAsmSourceResolvesGoIncludePathRelativeToPkgInclude(t *testing.T) {
	dir := t.TempDir()
	asm := filepath.Join(dir, "tls_386.s")
	if err := os.WriteFile(asm, []byte("#include \"../../src/runtime/go_tls.h\"\nTEXT ·tls(SB),NOSPLIT,$0-0\nRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expanded, err := readAsmSource(asm, dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(expanded), `#include "../../src/runtime/go_tls.h"`) || !strings.Contains(string(expanded), "get_tls") {
		t.Fatalf("GOROOT-relative runtime header was not expanded:\n%s", expanded)
	}
}

func TestExtractSupportedOpsFindsCompleteAddedInstructionFamilies(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	supported, err := extractSupportedOps(repoRoot, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"MOVD", "VMOVW", "VMOVD", "VMOVQ", "PREFETCHNTA", "PREFETCHT0", "PREFETCHT1", "PREFETCHT2", "UD2",
		"CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "CVTPL2PS", "CVTPL2PD",
		"VBROADCASTSS", "VBROADCASTSD",
		"VADDPH", "VSUBPH", "VMULPH", "VDIVPH", "VMINPH", "VMAXPH",
		"VCVTNEPS2BF16X", "VCVTNEPS2BF16Y", "VCVTNEPS2BF16",
		"PMULDQ", "PMULULQ", "VPMULDQ", "VPMULUDQ",
		"MOVDDUP", "MOVSHDUP", "MOVSLDUP",
		"VMOVDDUP", "VMOVSHDUP", "VMOVSLDUP",
		"PMULLD", "VPMULLD",
		"PMULLW", "PMULHW", "PMULHUW", "PMULHRSW",
		"VPMULLW", "VPMULHW", "VPMULHUW", "VPMULHRSW",
		"PMADDWL", "VPMADDWD", "PMADDUBSW", "VPMADDUBSW",
		"VPDPBUSD", "VPDPBUSDS", "VPDPWSSD", "VPDPWSSDS",
		"PAVGB", "PAVGW", "VPAVGB", "VPAVGW",
		"PCMPGTB", "PCMPGTW", "PCMPGTL", "PCMPGTQ",
		"PSRAW", "PSRAL", "VPSRAW", "VPSRAD", "VPSRAQ",
		"VPMINSB", "VPMINUB", "VPMAXSB", "VPMAXUB",
		"VPMINSW", "VPMINUW", "VPMAXSW", "VPMAXUW",
		"VPMINSD", "VPMINUD", "VPMAXSD", "VPMAXUD",
		"VPMINSQ", "VPMINUQ", "VPMAXSQ", "VPMAXUQ",
		"SHUFPS", "SHUFPD", "VSHUFPS", "VSHUFPD",
		"PBLENDW", "BLENDPS", "BLENDPD", "VPBLENDW", "VPBLENDD", "VBLENDPS", "VBLENDPD",
		"PUNPCKLBW", "PUNPCKHBW", "PUNPCKLWL", "PUNPCKHWL",
		"PUNPCKLLQ", "PUNPCKHLQ", "PUNPCKLQDQ", "PUNPCKHQDQ",
		"VPUNPCKLBW", "VPUNPCKHBW", "VPUNPCKLWD", "VPUNPCKHWD",
		"VPUNPCKLDQ", "VPUNPCKHDQ", "VPUNPCKLQDQ", "VPUNPCKHQDQ",
		"UNPCKLPS", "UNPCKHPS", "UNPCKLPD", "UNPCKHPD",
		"VUNPCKLPS", "VUNPCKHPS", "VUNPCKLPD", "VUNPCKHPD",
		"VPERMQ", "VPERMPD",
		"VPERMILPD", "VPERMILPS",
		"VMOVAPD", "VMOVAPS", "VMOVUPD", "VMOVUPS",
		"VMOVDQA32", "VMOVDQA64", "VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64",
		"MOVNTO", "MOVNTPD", "MOVNTPS", "MOVNTDQA",
		"VMOVNTDQ", "VMOVNTPD", "VMOVNTPS", "VMOVNTDQA",
		"MOVNTQ", "MOVNTDQ", "MOVQOZX", "MOVDQ2Q", "PSHUFW",
		"VINSERTF128", "VINSERTI128",
		"VINSERTF32X4", "VINSERTF64X2", "VINSERTI32X4", "VINSERTI64X2",
		"VINSERTF32X8", "VINSERTF64X4", "VINSERTI32X8", "VINSERTI64X4",
		"PSHUFB", "VPSHUFB",
		"ADDSUBPS", "ADDSUBPD", "VADDSUBPS", "VADDSUBPD",
		"VCVTDQ2PS", "VCVTPS2DQ", "VCVTTPS2DQ", "VSQRTPD", "VSQRTPS", "VSQRTPH", "VSQRTSH",
		"VDPBF16PS",
		"VCVTPH2PSX", "VCVTPS2PHX",
		"VCVTSH2SS", "VCVTSS2SH", "VCVTSH2SD", "VCVTSD2SH",
		"PMOVSXBW", "PMOVSXBD", "PMOVSXBQ", "PMOVSXWD", "PMOVSXWQ", "PMOVSXDQ",
		"VPMOVSXBW", "VPMOVSXBD", "VPMOVSXBQ", "VPMOVSXWD", "VPMOVSXWQ", "VPMOVSXDQ",
		"PMOVZXBW", "PMOVZXBD", "PMOVZXBQ", "PMOVZXWD", "PMOVZXWQ", "PMOVZXDQ",
		"VPMOVZXBW", "VPMOVZXBD", "VPMOVZXBQ", "VPMOVZXWD", "VPMOVZXWQ", "VPMOVZXDQ",
		"PHADDD", "PHADDSW", "PHADDW", "PHSUBD", "PHSUBSW", "PHSUBW",
		"VPHADDD", "VPHADDSW", "VPHADDW", "VPHSUBD", "VPHSUBSW", "VPHSUBW",
		"PHMINPOSUW", "VPHMINPOSUW",
		"BLENDVPS", "BLENDVPD", "PBLENDVB", "VBLENDVPS", "VBLENDVPD", "VPBLENDVB",
		"MASKMOVQ", "MASKMOVOU", "MASKMOVDQU", "VMASKMOVDQU",
		"JCXZW", "JCXZL", "JCXZQ",
		"PALIGNR", "VPALIGNR",
		"PCLMULQDQ", "VPCLMULQDQ",
		"PSLLO", "PSLLDQ", "PSRLO", "PSRLDQ", "VPSLLDQ", "VPSRLDQ",
		"RCLB", "RCLW", "RCLL", "RCLQ", "RCRB", "RCRW", "RCRL", "RCRQ",
		"PSHUFHW", "PSHUFLW", "VPSHUFHW", "VPSHUFLW",
		"AESENC", "AESENCLAST", "AESDEC", "AESDECLAST", "AESIMC", "AESKEYGENASSIST",
		"VAESENC", "VAESENCLAST", "VAESDEC", "VAESDECLAST", "VAESIMC", "VAESKEYGENASSIST",
		"CVTSS2SL", "CVTSS2SQ", "CVTSD2SL", "CVTSD2SQ",
		"CVTTSS2SL", "CVTTSS2SQ", "CVTTSD2SL", "CVTTSD2SQ",
		"VCVTSS2SI", "VCVTSS2SIQ", "VCVTSD2SI", "VCVTSD2SIQ",
		"VCVTTSS2SI", "VCVTTSS2SIQ", "VCVTTSD2SI", "VCVTTSD2SIQ",
		"VCVTSS2USIL", "VCVTSS2USIQ", "VCVTSD2USIL", "VCVTSD2USIQ",
		"VCVTTSS2USIL", "VCVTTSS2USIQ", "VCVTTSD2USIL", "VCVTTSD2USIQ",
		"ROUNDPS", "ROUNDPD", "ROUNDSS", "ROUNDSD",
		"VROUNDPS", "VROUNDPD", "VROUNDSS", "VROUNDSD",
		"DPPD", "DPPS", "VDPPD", "VDPPS",
		"BOUNDW", "BOUNDL",
		"CLC", "STC", "CMC",
		"PUSHW", "PUSHL", "PUSHQ", "POPW", "POPL", "POPQ",
		"PUSHFW", "PUSHFL", "PUSHFQ", "POPFW", "POPFL", "POPFQ",
		"PSLLW", "PSLLL", "PSLLQ", "PSRLW", "PSRLL", "PSRLQ",
		"VPSLLW", "VPSLLD", "VPSLLQ", "VPSRLW", "VPSRLD", "VPSRLQ",
		"VPSLLVW", "VPSLLVD", "VPSLLVQ",
		"VPSRLVW", "VPSRLVD", "VPSRLVQ",
		"VPSRAVW", "VPSRAVD", "VPSRAVQ",
		"PMULLW", "PMULHW", "PMULHUW", "PMULHRSW",
		"VPMULLW", "VPMULHW", "VPMULHUW", "VPMULHRSW",
		"LDMXCSR", "VLDMXCSR", "STMXCSR", "VSTMXCSR",
		"CVTPS2PL", "CVTTPS2PL", "CVTPS2PD", "VCVTPS2PD",
		"RCPPS", "RSQRTPS", "VRCPPS", "VRSQRTPS",
		"RCPSS", "RSQRTSS", "VRCPSS", "VRSQRTSS",
		"PCMPESTRI", "PCMPESTRM", "PCMPISTRI", "PCMPISTRM",
		"VPCMPESTRI", "VPCMPESTRM", "VPCMPISTRI", "VPCMPISTRM",
		"KUNPCKBW", "KUNPCKWD", "KUNPCKDQ",
		"VRCP14PS", "VRCP14PD", "VRCP14SS", "VRCP14SD",
		"VRSQRT14PS", "VRSQRT14PD", "VRSQRT14SS", "VRSQRT14SD",
		"VEXP2PS", "VEXP2PD",
		"VRCP28PS", "VRCP28PD", "VRCP28SS", "VRCP28SD",
		"VRSQRT28PS", "VRSQRT28PD", "VRSQRT28SS", "VRSQRT28SD",
		"V4FMADDPS", "V4FMADDSS", "V4FNMADDPS", "V4FNMADDSS", "VP4DPWSSD", "VP4DPWSSDS",
		"VPCMPEQB", "VPCMPEQW", "VPCMPEQD", "VPCMPEQQ",
		"VPCMPGTB", "VPCMPGTW", "VPCMPGTD", "VPCMPGTQ",
		"VPTESTMB", "VPTESTMW", "VPTESTMD", "VPTESTMQ",
		"VPTESTNMB", "VPTESTNMW", "VPTESTNMD", "VPTESTNMQ",
		"PTEST", "VPTEST", "VTESTPD", "VTESTPS",
		"VPCONFLICTD", "VPCONFLICTQ",
		"VBLENDMPS", "VBLENDMPD",
		"VEXPANDPD", "VEXPANDPS", "VPEXPANDB", "VPEXPANDW", "VPEXPANDD", "VPEXPANDQ",
		"PAND", "PANDN", "POR", "PXOR", "VPANDN", "VPANDND", "VPANDNQ",
		"VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ",
		"VPBROADCASTMB2Q", "VPBROADCASTMW2D",
		"PADDB", "PADDL", "PADDD", "PADDQ", "PADDSB", "PADDSW", "PADDUSB", "PADDUSW", "PADDW",
		"VPADDB", "VPADDD", "VPADDQ", "VPADDSB", "VPADDSW", "VPADDUSB", "VPADDUSW", "VPADDW",
		"PSUBB", "PSUBL", "PSUBQ", "PSUBSB", "PSUBSW", "PSUBUSB", "PSUBUSW", "PSUBW",
		"VPSUBB", "VPSUBD", "VPSUBQ", "VPSUBSB", "VPSUBSW", "VPSUBUSB", "VPSUBUSW", "VPSUBW",
		"PSADBW", "VPSADBW", "MPSADBW", "VMPSADBW", "VDBPSADBW",
		"PINSRB", "PINSRW", "PINSRD", "PINSRQ",
		"VPINSRB", "VPINSRW", "VPINSRD", "VPINSRQ",
		"VPMOVDB", "VPMOVDW", "VPMOVQB", "VPMOVQD", "VPMOVQW", "VPMOVWB",
		"VPMOVSDB", "VPMOVSDW", "VPMOVSQB", "VPMOVSQD", "VPMOVSQW", "VPMOVSWB",
		"VPMOVUSDB", "VPMOVUSDW", "VPMOVUSQB", "VPMOVUSQD", "VPMOVUSQW", "VPMOVUSWB",
		"EXTRACTPS", "VEXTRACTPS", "VEXTRACTF128", "VEXTRACTI128",
		"VEXTRACTF32X4", "VEXTRACTF64X2", "VEXTRACTI32X4", "VEXTRACTI64X2",
		"VEXTRACTF32X8", "VEXTRACTF64X4", "VEXTRACTI32X8", "VEXTRACTI64X4",
		"PEXTRB", "PEXTRW", "PEXTRD", "PEXTRQ",
		"VPEXTRB", "VPEXTRW", "VPEXTRD", "VPEXTRQ",
		"MOVHLPS", "MOVLHPS", "VMOVHLPS", "VMOVLHPS",
		"MOVHPS", "MOVLPS", "MOVHPD", "MOVLPD", "VMOVHPS", "VMOVLPS", "VMOVHPD", "VMOVLPD",
		"LDDQU", "VLDDQU",
		"POPCNTW", "POPCNTL", "POPCNTQ",
		"NOTB", "NOTW", "NOTL", "NOTQ",
		"PDEPL", "PDEPQ", "PEXTL", "PEXTQ",
		"BTW", "BTL", "BTQ", "BTCW", "BTCL", "BTCQ",
		"BTRW", "BTRL", "BTRQ", "BTSW", "BTSL", "BTSQ",
		"RDMSR", "WRMSR",
		"VMRUN", "VMMCALL", "VMLOAD", "VMSAVE", "STGI", "CLGI", "SKINIT", "INVLPGA",
		"LGDT", "LIDT", "SGDT", "SIDT",
		"LLDT", "LTR", "LMSW",
		"LARW", "LARL", "LARQ", "LSLW", "LSLL", "LSLQ",
		"VERR", "VERW",
		"LFSW", "LFSL", "LFSQ", "LGSW", "LGSL", "LGSQ", "LSSW", "LSSL", "LSSQ",
		"FXSAVE", "FXSAVE64", "FXRSTOR", "FXRSTOR64",
		"XSAVE", "XSAVE64", "XSAVEOPT", "XSAVEOPT64", "XSAVEC", "XSAVEC64", "XSAVES", "XSAVES64",
		"XRSTOR", "XRSTOR64", "XRSTORS", "XRSTORS64",
		"RDFSBASEL", "RDFSBASEQ", "RDGSBASEL", "RDGSBASEQ",
		"WRFSBASEL", "WRFSBASEQ", "WRGSBASEL", "WRGSBASEQ",
		"SLDTW", "SLDTL", "SLDTQ",
		"SMSWW", "SMSWL", "SMSWQ",
		"STRW", "STRL", "STRQ",
		"CLFLUSH", "CLFLUSHOPT", "CLWB",
		"CLDEMOTE", "INVLPG", "INVPCID",
		"MONITOR", "MWAIT", "RDPMC", "RDPKRU", "WRPKRU", "XSETBV", "UMONITOR", "UMWAIT", "TPAUSE",
		"XBEGIN", "XABORT", "XEND", "XTEST",
		"CLAC", "CLI", "CLTS", "ENDBR64", "ICEBP", "INVD", "RSM", "STAC", "STI", "SWAPGS", "UD1", "WBINVD",
		"IRETW", "IRETL", "IRETQ", "RETFW", "RETFL", "RETFQ",
		"SYSENTER", "SYSENTER64", "SYSEXIT", "SYSEXIT64", "SYSRET",
		"LEAVEW", "LEAVEL", "LEAVEQ", "XLAT",
		"XADDB", "XADDW", "XADDL", "XADDQ",
		"XCHGB", "XCHGW", "XCHGL", "XCHGQ",
		"NEGB", "NEGW", "NEGL", "NEGQ",
		"SARXL", "SARXQ", "SHLXL", "SHLXQ", "SHRXL", "SHRXQ",
		"BEXTRL", "BEXTRQ", "BZHIL", "BZHIQ",
		"CRC32B", "CRC32W", "CRC32L", "CRC32Q",
		"CMPSB", "CMPSW", "CMPSL", "CMPSQ",
		"LODSB", "LODSW", "LODSL", "LODSQ",
		"NOPW", "NOPL",
		"MOVBEW", "MOVBEL", "MOVBEQ",
		"MOVNTIL", "MOVNTIQ",
		"CBW", "CWDE", "CDQE", "CWD", "CDQ", "CQO",
		"FCMOVCC", "FCMOVCS", "FCMOVEQ", "FCMOVHI", "FCMOVLS",
		"FCMOVB", "FCMOVBE", "FCMOVNB", "FCMOVNBE", "FCMOVE", "FCMOVNE", "FCMOVNU", "FCMOVU", "FCMOVUN",
		"LEAW", "LEAL", "LEAQ",
		"LZCNTW", "LZCNTL", "LZCNTQ",
		"ADCXL", "ADCXQ", "ADOXL", "ADOXQ",
		"CMPXCHGB", "CMPXCHGW", "CMPXCHGL", "CMPXCHGQ", "CMPXCHG8B", "CMPXCHG16B",
		"TZCNTW", "TZCNTL", "TZCNTQ",
		"CMPPD", "CMPPS", "CMPSD", "CMPSS", "VCMPPD", "VCMPPS", "VCMPSD", "VCMPSS",
		"PACKSSLW", "PACKSSWB", "PACKUSDW", "PACKUSWB",
		"VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB",
		"VPERMD", "VPERMPS",
		"SETCC", "SETCS", "SETEQ", "SETGE", "SETGT", "SETHI", "SETLE", "SETLS",
		"SETLT", "SETMI", "SETNE", "SETOC", "SETOS", "SETPC", "SETPL", "SETPS",
		"VMOVSD", "VMOVSS", "VMOVSH",
		"VADDSH", "VSUBSH", "VMULSH", "VDIVSH", "VMINSH", "VMAXSH",
		"VCOMISD", "VCOMISS", "VUCOMISD", "VUCOMISS",
		"INCB", "INCW", "INCL", "INCQ", "DECB", "DECW", "DECL", "DECQ",
		"MOVBWSX", "MOVBWZX", "MOVBLSX", "MOVBLZX", "MOVBQSX", "MOVBQZX",
		"MOVWLSX", "MOVWLZX", "MOVWQSX", "MOVWQZX", "MOVLQSX", "MOVLQZX",
		"MOVSWW", "MOVZWW",
		"KMOVB", "KMOVW", "KMOVD", "KMOVQ",
		"KADDB", "KADDW", "KADDD", "KADDQ",
		"KSHIFTLB", "KSHIFTLW", "KSHIFTLD", "KSHIFTLQ",
		"KSHIFTRB", "KSHIFTRW", "KSHIFTRD", "KSHIFTRQ",
		"VGATHERDPS", "VGATHERQPD", "VPGATHERDD", "VPGATHERQQ",
		"VGATHERDPD", "VPGATHERDQ", "VGATHERQPS", "VPGATHERQD",
		"VGATHERPF0DPD", "VGATHERPF0DPS", "VGATHERPF0QPD", "VGATHERPF0QPS",
		"VGATHERPF1DPD", "VGATHERPF1DPS", "VGATHERPF1QPD", "VGATHERPF1QPS",
		"VSCATTERPF0DPD", "VSCATTERPF0DPS", "VSCATTERPF0QPD", "VSCATTERPF0QPS",
		"VSCATTERPF1DPD", "VSCATTERPF1DPS", "VSCATTERPF1QPD", "VSCATTERPF1QPS",
		"VPTERNLOGD", "VPTERNLOGQ",
		"VALIGND", "VALIGNQ",
		"VPMADD52HUQ", "VPMADD52LUQ",
		"VPSHLDW", "VPSHLDD", "VPSHLDQ", "VPSHLDVW", "VPSHLDVD", "VPSHLDVQ",
		"VPSHRDW", "VPSHRDD", "VPSHRDQ", "VPSHRDVW", "VPSHRDVD", "VPSHRDVQ",
		"VPROLD", "VPROLQ", "VPROLVD", "VPROLVQ",
		"VPRORD", "VPRORQ", "VPRORVD", "VPRORVQ",
		"VPANDD", "VPANDQ", "VPANDND", "VPANDNQ",
		"VPORD", "VPORQ", "VPXORD", "VPXORQ",
		"ANDPS", "ANDPD", "ANDNPS", "ANDNPD", "ORPS", "ORPD", "XORPS", "XORPD",
		"VANDPS", "VANDPD", "VANDNPS", "VANDNPD", "VORPS", "VORPD", "VXORPS", "VXORPD",
		"HADDPS", "HADDPD", "HSUBPS", "HSUBPD", "VHADDPS", "VHADDPD", "VHSUBPS", "VHSUBPD",
		"PABSB", "PABSW", "PABSD", "VPABSB", "VPABSW", "VPABSD", "VPABSQ",
		"PSIGNB", "PSIGNW", "PSIGND", "VPSIGNB", "VPSIGNW", "VPSIGND",
		"VCVTPH2PS", "VCVTPS2PH",
		"CVTPD2PL", "CVTTPD2PL", "VCVTDQ2PD",
		"VCVTPD2DQ", "VCVTPD2DQX", "VCVTPD2DQY",
		"VCVTTPD2DQ", "VCVTTPD2DQX", "VCVTTPD2DQY",
		"VSQRTSS", "VSQRTSD",
		"VCVTSI2SDL", "VCVTSI2SDQ", "VCVTSI2SSL", "VCVTSI2SSQ",
		"VCVTUSI2SDL", "VCVTUSI2SDQ", "VCVTUSI2SSL", "VCVTUSI2SSQ",
		"FMOVB", "FMOVBP", "FMOVD", "FMOVDP", "FMOVF", "FMOVFP", "FMOVL", "FMOVLP",
		"FMOVV", "FMOVVP", "FMOVW", "FMOVWP", "FMOVX", "FMOVXP",
		"FCOMD", "FCOMDP", "FCOMDPP", "FCOMF", "FCOMFP", "FCOMI", "FCOMIP",
		"FCOML", "FCOMLP", "FCOMW", "FCOMWP", "FUCOM", "FUCOMI", "FUCOMIP", "FUCOMP", "FUCOMPP",
		"FBLD", "FBSTP", "FLDCW", "FLDENV", "FRSTOR", "FSAVE", "FSTCW", "FSTENV", "FSTSW",
		"F2XM1", "FABS", "FCHS", "FCLEX", "FCOS", "FDECSTP", "FINCSTP", "FINIT",
		"FLD1", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2", "FLDPI", "FLDZ", "FNOP",
		"FPATAN", "FPREM", "FPREM1", "FPTAN", "FRNDINT", "FSCALE", "FSIN", "FSINCOS",
		"FSQRT", "FTST", "FXAM", "FXTRACT", "FYL2X", "FYL2XP1", "FXCHD", "LAHF", "SAHF",
	}
	for _, stem := range []string{"FADD", "FMUL", "FSUB", "FSUBR", "FDIV", "FDIVR"} {
		for _, suffix := range []string{"W", "L", "F", "D", "DP"} {
			want = append(want, stem+suffix)
		}
	}
	for _, stem := range []string{"ROL", "ROR", "SAR", "SAL", "SHL", "SHR"} {
		for _, width := range []string{"B", "W", "L", "Q"} {
			want = append(want, stem+width)
		}
	}
	for _, stem := range []string{"KAND", "KANDN", "KOR", "KXNOR", "KXOR", "KNOT", "KTEST", "KORTEST"} {
		for _, width := range []string{"B", "W", "D", "Q"} {
			want = append(want, stem+width)
		}
	}
	for _, family := range []string{"VFMADD", "VFMSUB", "VFNMADD", "VFNMSUB", "VFMADDSUB", "VFMSUBADD"} {
		for _, order := range []string{"132", "213", "231"} {
			for _, element := range []string{"PS", "PD", "PH"} {
				want = append(want, family+order+element)
			}
			if family != "VFMADDSUB" && family != "VFMSUBADD" {
				for _, element := range []string{"SS", "SD", "SH"} {
					want = append(want, family+order+element)
				}
			}
		}
	}
	for _, family := range []string{"VADD", "VSUB", "VMUL", "VDIV", "VMAX", "VMIN"} {
		for _, element := range []string{"PS", "PD", "SS", "SD"} {
			want = append(want, family+element)
		}
	}
	for _, width := range []string{"W", "L", "Q"} {
		for _, condition := range []string{"CC", "CS", "EQ", "GE", "GT", "HI", "LE", "LS", "LT", "MI", "NE", "OC", "OS", "PC", "PL", "PS"} {
			want = append(want, "CMOV"+width+condition)
		}
	}
	for _, op := range want {
		if _, ok := supported[op]; !ok {
			t.Errorf("supported opcode extraction omitted %s", op)
		}
	}
	supported386, err := extractSupportedOps(repoRoot, "386")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"VADDPH", "VSUBPH", "VMULPH", "VDIVPH", "VMINPH", "VMAXPH"} {
		if _, ok := supported386[op]; !ok {
			t.Errorf("386 supported opcode extraction omitted raw FP16 %s", op)
		}
	}
	for _, op := range []string{
		"VPOPCNTB", "VPOPCNTW", "VPOPCNTD", "VPOPCNTQ",
		"VPLZCNTD", "VPLZCNTQ",
		"VGF2P8MULB", "VGF2P8AFFINEQB", "VGF2P8AFFINEINVQB",
		"VPERMB", "VPERMW",
		"VPERMI2B", "VPERMI2W", "VPERMI2D", "VPERMI2Q", "VPERMI2PS", "VPERMI2PD",
		"VPERMT2B", "VPERMT2W", "VPERMT2D", "VPERMT2Q", "VPERMT2PS", "VPERMT2PD",
		"VPMULTISHIFTQB", "VPSHUFBITQMB",
		"VRANGEPS", "VRANGEPD", "VRANGESS", "VRANGESD",
		"VMASKMOVPS", "VMASKMOVPD", "VPMASKMOVD", "VPMASKMOVQ",
		"VFPCLASSPDX", "VFPCLASSPDY", "VFPCLASSPDZ",
		"VFPCLASSPSX", "VFPCLASSPSY", "VFPCLASSPSZ", "VFPCLASSSD", "VFPCLASSSS",
		"VGETEXPPS", "VGETEXPPD", "VGETEXPSS", "VGETEXPSD",
		"VGETMANTPS", "VGETMANTPD", "VGETMANTSS", "VGETMANTSD",
		"VFIXUPIMMPS", "VFIXUPIMMPD", "VFIXUPIMMSS", "VFIXUPIMMSD",
		"VRNDSCALEPS", "VRNDSCALEPD", "VRNDSCALESS", "VRNDSCALESD",
		"VREDUCEPS", "VREDUCEPD", "VREDUCESS", "VREDUCESD",
		"VSCALEFPS", "VSCALEFPD", "VSCALEFSS", "VSCALEFSD",
		"VCVTPD2QQ", "VCVTPD2UQQ", "VCVTTPD2QQ", "VCVTTPD2UQQ",
		"VCVTPS2QQ", "VCVTPS2UQQ", "VCVTTPS2QQ", "VCVTTPS2UQQ",
		"VCVTPS2UDQ", "VCVTTPS2UDQ", "VCVTUDQ2PS", "VCVTUDQ2PD",
		"VCVTPD2UDQ", "VCVTPD2UDQX", "VCVTPD2UDQY",
		"VCVTTPD2UDQ", "VCVTTPD2UDQX", "VCVTTPD2UDQY",
		"VCVTQQ2PD", "VCVTUQQ2PD", "VCVTQQ2PS", "VCVTQQ2PSX", "VCVTQQ2PSY",
		"VCVTUQQ2PS", "VCVTUQQ2PSX", "VCVTUQQ2PSY",
		"VCOMPRESSPS", "VCOMPRESSPD", "VPCOMPRESSB", "VPCOMPRESSW", "VPCOMPRESSD", "VPCOMPRESSQ",
		"VBROADCASTF128", "VBROADCASTI128",
	} {
		if _, ok := supported[op]; !ok {
			t.Errorf("supported opcode extraction omitted %s", op)
		}
	}
	arm64Supported, err := extractSupportedOps(repoRoot, "arm64")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{
		"ADR", "ADRP",
		"SMOV", "SMOVW",
		"VFCVTNS", "VFCVTNU", "VFCVTMS", "VFCVTMU", "VFCVTAS", "VFCVTAU", "VFCVTPS", "VFCVTPU", "VFCVTZS", "VFCVTZU",
		"VZIP1", "VZIP2", "VUZP1", "VUZP2", "VTRN1", "VTRN2",
		"VUSHLL", "VUSHLL2", "VSSHLL", "VSSHLL2",
		"VUXTL", "VUXTL2", "VSXTL", "VSXTL2",
		"SXTB", "SXTBW", "SXTH", "SXTHW", "SXTW",
		"UXTB", "UXTBW", "UXTH", "UXTHW", "UXTW",
		"VCNT",
		"VUADDW", "VUADDW2",
	} {
		if _, ok := arm64Supported[op]; !ok {
			t.Errorf("ARM64 supported opcode extraction omitted %s", op)
		}
	}
}

func TestExtractSupportedOpsFindsPackageLevelSpecTableWithoutOpcodeName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "amd64_table.go"), []byte(`package sample
var packedFamilySpecs = map[string]int{
	"VTABLEOP": 1,
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "translate.go"), []byte("package sample\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	supported, err := extractSupportedOps(dir, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := supported["VTABLEOP"]; !ok {
		t.Fatal("package-level table-driven opcode was not extracted")
	}
}

func TestExplicitSingleTargetUsesMatrixReport(t *testing.T) {
	tests := []struct {
		name       string
		allTargets bool
		targets    string
		reports    int
		want       bool
	}{
		{name: "legacy-default-single", reports: 1, want: false},
		{name: "explicit-single", targets: "linux/amd64", reports: 1, want: true},
		{name: "explicit-multiple", targets: "linux/amd64,windows/amd64", reports: 2, want: true},
		{name: "all-targets", allTargets: true, reports: 9, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := useMatrixReport(test.allTargets, test.targets, test.reports); got != test.want {
				t.Fatalf("useMatrixReport(%v, %q, %d) = %v, want %v", test.allTargets, test.targets, test.reports, got, test.want)
			}
		})
	}
}

func TestExtractSupportedOpsFindsCompleteARM64AddedFamilies(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	supported, err := extractSupportedOps(repoRoot, "arm64")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{
		// NEON SM4 is WORD-only; the named SM4 forms below are SVE.
		"WORD",
		"MADD", "MSUB", "MADDW", "MSUBW", "SMADDL", "SMSUBL", "UMADDL", "UMSUBL",
		"FABSS", "FABSD", "FNEGS", "FNEGD", "FSQRTS", "FSQRTD", "FMOVS", "FMOVD",
		"FCVTSD", "FCVTDS", "FCVTSH", "FCVTHS", "FCVTDH", "FCVTHD",
		"FRINTNS", "FRINTND", "FRINTPS", "FRINTPD", "FRINTMS", "FRINTMD",
		"FRINTZS", "FRINTZD", "FRINTAS", "FRINTAD", "FRINTXS", "FRINTXD", "FRINTIS", "FRINTID",
		"FMADDS", "FMADDD", "FMSUBS", "FMSUBD", "FNMADDS", "FNMADDD", "FNMSUBS", "FNMSUBD",
		"SCVTFD", "SCVTFS", "SCVTFWD", "SCVTFWS", "UCVTFD", "UCVTFS", "UCVTFWD", "UCVTFWS",
		"FADDS", "FADDD", "FSUBS", "FSUBD", "FMULS", "FMULD", "FNMULS", "FNMULD", "FDIVS", "FDIVD",
		"FMAXS", "FMAXD", "FMINS", "FMIND", "FMAXNMS", "FMAXNMD", "FMINNMS", "FMINNMD",
		"CASPW", "CASPD",
		"LDXPW", "LDXP", "LDAXPW", "LDAXP",
		"STXPW", "STXP", "STLXPW", "STLXP",
		"VADDV", "VADDP", "VSMAX", "VSMIN", "VUMAX", "VUMIN", "VSMAXP", "VSMINP", "VUMAXP", "VUMINP",
		"VABS", "VNEG", "VSQABS", "VSQNEG",
		"VSSHR", "VSSRA", "VSRSHR", "VSRSRA", "VUSHR", "VUSRA", "VURSHR", "VURSRA",
		"VSQSHRN", "VSQSHRN2", "VSQRSHRN", "VSQRSHRN2",
		"VSQSHRUN", "VSQSHRUN2", "VSQRSHRUN", "VSQRSHRUN2",
		"VUQSHRN", "VUQSHRN2", "VUQRSHRN", "VUQRSHRN2",
		"VXTN", "VXTN2", "VSQXTN", "VSQXTN2", "VSQXTUN", "VSQXTUN2", "VUQXTN", "VUQXTN2",
		"VSHADD", "VSRHADD", "VUHADD", "VURHADD",
		"VSQADD", "VUQADD", "VSQSUB", "VUQSUB",
		"VSMULL", "VSMULL2", "VSMLAL", "VSMLAL2", "VSMLSL", "VSMLSL2",
		"VUMULL", "VUMULL2", "VUMLAL", "VUMLAL2", "VUMLSL", "VUMLSL2",
		"VMUL", "VMLA", "VMLS",
		"VCMHI", "VCMHS",
		"VSMAXV", "VSMINV", "VUMAXV", "VUMINV",
		"VFMAXV", "VFMINV", "VFMAXNMV", "VFMINNMV",
		"VLD1", "VLD2", "VLD3", "VLD4", "VLD1R", "VLD2R", "VLD3R", "VLD4R", "VST1", "VST2", "VST3", "VST4",
		"VMOVS", "VMOVD", "VMOVQ", "VDUP", "VADD", "VSUB",
		"VCLS", "VCLZ",
		"VEXT",
		"VEOR3", "VBCAX", "VRAX1", "VXAR",
		"SHA1C", "SHA1P", "SHA1M", "SHA1H", "SHA1SU0", "SHA1SU1",
		"SHA256H", "SHA256H2", "SHA256SU0", "SHA256SU1",
		"SHA512H", "SHA512H2", "SHA512SU0", "SHA512SU1",
		"VSHL", "VSSHL", "VSRSHL", "VUSHL", "VURSHL",
		"ZAND", "ZBIC", "ZEOR", "ZORR",
		"ZSUB", "ZSUBR", "ZSQADD", "ZSQSUB", "ZSQSUBR", "ZUQADD", "ZUQSUB", "ZUQSUBR",
		"ZASR", "ZLSL",
		"ZFADD", "ZFSUB", "ZFSUBR",
		"ZCMPEQ", "ZCMPGE", "ZCMPGT", "ZCMPHI", "ZCMPHS", "ZCMPNE",
		"ZFACGE", "ZFACGT", "ZFCMEQ", "ZFCMGE", "ZFCMGT", "ZFCMLE", "ZFCMLT", "ZFCMNE", "ZFCMUO",
		"ZSMAX", "ZSMAXP", "ZSMAXQV", "ZSMAXVB", "ZSMAXVH", "ZSMAXVS", "ZSMAXVD",
		"ZSMIN", "ZSMINP", "ZSMINQV", "ZSMINVB", "ZSMINVH", "ZSMINVS", "ZSMINVD",
		"ZUMAX", "ZUMAXP", "ZUMAXQV", "ZUMAXVB", "ZUMAXVH", "ZUMAXVS", "ZUMAXVD",
		"ZUMIN", "ZUMINP", "ZUMINQV", "ZUMINVB", "ZUMINVH", "ZUMINVS", "ZUMINVD",
		"ZADDQV", "ZANDQV", "ZANDVB", "ZANDVH", "ZANDVS", "ZANDVD",
		"ZEORQV", "ZEORVB", "ZEORVH", "ZEORVS", "ZEORVD",
		"ZORQV", "ZORVB", "ZORVH", "ZORVS", "ZORVD",
		"ZFADDAD", "ZFADDAH", "ZFADDAS", "ZFADDQV", "ZFADDVD", "ZFADDVH", "ZFADDVS",
		"ZSADDVD", "ZUADDVD",
		"ZADDHNB", "ZADDHNT", "ZRADDHNB", "ZRADDHNT", "ZSUBHNB", "ZSUBHNT", "ZRSUBHNB", "ZRSUBHNT",
		"ZSADDLB", "ZSADDLBT", "ZSADDLT", "ZSADDWB", "ZSADDWT",
		"ZSSUBLB", "ZSSUBLBT", "ZSSUBLT", "ZSSUBLTB", "ZSSUBWB", "ZSSUBWT",
		"ZUADDLB", "ZUADDLT", "ZUADDWB", "ZUADDWT", "ZUSUBLB", "ZUSUBLT", "ZUSUBWB", "ZUSUBWT",
		"ZSABA", "ZUABA", "ZSABD", "ZUABD",
		"ZSABALB", "ZSABALT", "ZUABALB", "ZUABALT",
		"ZSABDLB", "ZSABDLT", "ZUABDLB", "ZUABDLT", "ZSADALP", "ZUADALP",
		"ZSHADD", "ZSRHADD", "ZUHADD", "ZURHADD", "ZSHSUB", "ZSHSUBR", "ZUHSUB", "ZUHSUBR",
		"ZSDIV", "ZSDIVR", "ZUDIV", "ZUDIVR",
		"ZBCAX", "ZBSL", "ZBSL1N", "ZBSL2N", "ZEOR3", "ZNBSL",
		"ZBDEP", "ZBEXT", "ZBGRP",
		"ZADCLB", "ZADCLT", "ZSBCLB", "ZSBCLT",
		"ZSCLAMP", "ZUCLAMP", "ZFCLAMP", "ZBFCLAMP",
		"ZSUNPKHI", "ZSUNPKLO", "ZUUNPKHI", "ZUUNPKLO",
		"ZSQXTNB", "ZSQXTNT", "ZSQXTUNB", "ZSQXTUNT", "ZUQXTNB", "ZUQXTNT",
		"ZSHRNB", "ZSHRNT", "ZRSHRNB", "ZRSHRNT",
		"ZSQSHRNB", "ZSQSHRNT", "ZSQRSHRNB", "ZSQRSHRNT",
		"ZSQSHRUNB", "ZSQSHRUNT", "ZSQRSHRUNB", "ZSQRSHRUNT",
		"ZUQSHRNB", "ZUQSHRNT", "ZUQRSHRNB", "ZUQRSHRNT",
		"ZSQRSHL", "ZSQRSHLR", "ZSQSHLR", "ZUQRSHL", "ZUQRSHLR", "ZUQSHLR",
		"ZSRSHL", "ZSRSHLR", "ZURSHL", "ZURSHLR",
		"ZFMAX", "ZFMAXP", "ZFMAXQV", "ZFMAXVH", "ZFMAXVS", "ZFMAXVD",
		"ZFMIN", "ZFMINP", "ZFMINQV", "ZFMINVH", "ZFMINVS", "ZFMINVD",
		"ZFMAXNM", "ZFMAXNMP", "ZFMAXNMQV", "ZFMAXNMVH", "ZFMAXNMVS", "ZFMAXNMVD",
		"ZFMINNM", "ZFMINNMP", "ZFMINNMQV", "ZFMINNMVH", "ZFMINNMVS", "ZFMINNMVD",
		"ZFABS", "ZFNEG", "ZFRECPE", "ZFRECPX", "ZFRSQRTE", "ZFSQRT",
		"ZFRINT32X", "ZFRINT32Z", "ZFRINT64X", "ZFRINT64Z",
		"ZFRINTA", "ZFRINTI", "ZFRINTM", "ZFRINTN", "ZFRINTP", "ZFRINTX", "ZFRINTZ",
		"ZABS", "ZCLS", "ZCLZ", "ZCNOT", "ZCNT", "ZNEG", "ZNOT", "ZRBIT",
		"ZREV", "ZREVB", "ZREVH", "ZREVW",
		"PAND", "PANDS", "PBIC", "PBICS", "PEOR", "PEORS", "PNAND", "PNANDS",
		"PNOR", "PNORS", "PORN", "PORNS", "PORR", "PORRS",
		"PBRKA", "PBRKAS", "PBRKB", "PBRKBS", "PBRKN", "PBRKNS",
		"PBRKPA", "PBRKPAS", "PBRKPB", "PBRKPBS",
		"PREV", "PTRN1", "PTRN2", "PUZP1", "PUZP2", "PZIP1", "PZIP2",
		"PPUNPKHI", "PPUNPKLO",
		"PSEL",
		"PPFALSE", "PPTEST",
		"PRDFFR", "PRDFFRS", "PWRFFR", "SETFFR",
		"PPFIRST", "PPNEXT",
		"PFIRSTP", "PLASTP",
		"PPTRUE", "PCNTP", "PPEXT",
		"PWHILEGE", "PWHILEGT", "PWHILEHI", "PWHILEHS",
		"PWHILELE", "PWHILELO", "PWHILELS", "PWHILELT",
		"PWHILEGEW", "PWHILEGTW", "PWHILEHIW", "PWHILEHSW",
		"PWHILELEW", "PWHILELOW", "PWHILELSW", "PWHILELTW",
		"PWHILERW", "PWHILEWR",
		"PDECP", "PINCP", "PSQDECP", "PSQDECPW", "PSQINCP", "PSQINCPW",
		"PUQDECP", "PUQDECPW", "PUQINCP", "PUQINCPW",
		"PLDR", "PSTR", "PPRFB", "PPRFH", "PPRFW", "PPRFD",
		"ZLDR", "ZSTR",
		"ZPRFB", "ZPRFH", "ZPRFW", "ZPRFD",
		"ZLDNT1B", "ZLDNT1H", "ZLDNT1W", "ZLDNT1D", "ZLDNT1SB", "ZLDNT1SH", "ZLDNT1SW",
		"ZSTNT1B", "ZSTNT1H", "ZSTNT1W", "ZSTNT1D",
		"ZLDFF1B", "ZLDFF1H", "ZLDFF1W", "ZLDFF1D", "ZLDFF1SB", "ZLDFF1SH", "ZLDFF1SW",
		"ZLDNF1B", "ZLDNF1H", "ZLDNF1W", "ZLDNF1D", "ZLDNF1SB", "ZLDNF1SH", "ZLDNF1SW",
		"ZLD1RB", "ZLD1RH", "ZLD1RW", "ZLD1RD", "ZLD1RSB", "ZLD1RSH", "ZLD1RSW",
		"ZLD1ROB", "ZLD1ROH", "ZLD1ROW", "ZLD1ROD", "ZLD1RQB", "ZLD1RQH", "ZLD1RQW", "ZLD1RQD",
		"CTERMEQ", "CTERMEQW", "CTERMNE", "CTERMNEW",
		"ZLD1B", "ZLD1H", "ZLD1W", "ZLD1D", "ZLD1Q", "ZLD1SB", "ZLD1SH", "ZLD1SW",
		"ZST1B", "ZST1H", "ZST1W", "ZST1D", "ZST1Q",
		"ZLD2B", "ZLD2H", "ZLD2W", "ZLD2D", "ZLD2Q",
		"ZLD3B", "ZLD3H", "ZLD3W", "ZLD3D", "ZLD3Q",
		"ZLD4B", "ZLD4H", "ZLD4W", "ZLD4D", "ZLD4Q",
		"ZST2B", "ZST2H", "ZST2W", "ZST2D", "ZST2Q",
		"ZST3B", "ZST3H", "ZST3W", "ZST3D", "ZST3Q",
		"ZST4B", "ZST4H", "ZST4W", "ZST4D", "ZST4Q",
		"ZPMOV",
		"ZINDEX", "ZINDEXW",
		"ZINSR", "ZINSRW", "ZINSRB", "ZINSRH", "ZINSRS", "ZINSRD",
		"ZLASTA", "ZLASTAW", "ZLASTAB", "ZLASTAH", "ZLASTAS", "ZLASTAD",
		"ZLASTB", "ZLASTBW", "ZLASTBB", "ZLASTBH", "ZLASTBS", "ZLASTBD",
		"ZCLASTA", "ZCLASTAW", "ZCLASTAB", "ZCLASTAH", "ZCLASTAS", "ZCLASTAD",
		"ZCLASTB", "ZCLASTBW", "ZCLASTBB", "ZCLASTBH", "ZCLASTBS", "ZCLASTBD",
		"ZCOMPACT",
		"ZMOVPRFX",
		"ZEXT", "ZEXTQ", "ZSPLICE",
		"ZCPY", "ZCPYW", "ZCPYB", "ZCPYH", "ZCPYS", "ZCPYD",
		"ZFCVT", "ZFCVTZS", "ZFCVTZU", "ZSCVTF", "ZUCVTF",
		"ZFCVTLT", "ZFCVTX", "ZFCVTXNT",
		"ZSQABS", "ZSQNEG", "ZSXTB", "ZSXTH", "ZSXTW",
		"ZUXTB", "ZUXTH", "ZUXTW", "ZURECPE", "ZURSQRTE",
		"ZSMULH", "ZUMULH",
		"ZSDOT", "ZUDOT", "ZSUDOT", "ZUSDOT",
		"ZSQSHL", "ZUQSHL",
		"ZFMUL", "ZFMULX", "ZFTMAD", "ZFTSMUL", "ZFTSSEL", "ZFCMLA", "ZFMLA", "ZFMLS", "ZFMAD", "ZFMSB",
		"ZFNMLA", "ZFNMLS", "ZFNMAD", "ZFNMSB", "ZMLA", "ZMLS",
		"ZSQDMULH", "ZSQRDMULH",
		"ZPMUL", "ZPMULL", "ZPMULLB", "ZPMULLT", "ZPMLAL",
		"ZSMULLB", "ZSMULLT", "ZUMULLB", "ZUMULLT", "ZSQDMULLB", "ZSQDMULLT",
		"ZSQDMLALB", "ZSQDMLALT", "ZSQDMLALBT", "ZSQDMLSLB", "ZSQDMLSLT", "ZSQDMLSLBT",
		"ZSMMLA", "ZUMMLA", "ZUSMMLA", "ZBFMMLA", "ZFMMLA",
		"ZADDP", "ZADDPT", "ZSUBPT",
		"ZDECP", "ZINCP", "ZSQDECP", "ZSQINCP", "ZUQDECP", "ZUQINCP",
		"ZSSHLLB", "ZSSHLLT", "ZUSHLLB", "ZUSHLLT",
		"ZFRECPS", "ZFRSQRTS",
		"ZFABD", "ZFADDP", "ZFAMAX", "ZFAMIN",
		"ZMATCH", "ZNMATCH",
		"ZHISTCNT", "ZHISTSEG",
		"ZMADPT", "ZMLAPT",
		"ZCADD", "ZSQCADD",
		"ZXAR",
		"ZEXPAND",
		"ZFEXPA", "ZFLOGB",
		"ZFCPY", "ZFDUP",
		"ZFDIV", "ZFDIVR", "ZFSCALE",
		"ZSUQADD", "ZUSQADD",
		"ZFCADD",
		"ZDUPW",
		"ZDUPQ",
		"ZDUPM",
		"ZFDOT",
		"ZCDOT",
		"ZLUTI2", "ZLUTI4",
		"ZFMLALB", "ZFMLALT", "ZFMLSLB", "ZFMLSLT",
		"ZFMLALLBB", "ZFMLALLBT", "ZFMLALLTB", "ZFMLALLTT",
		"ZSQCVTN", "ZSQCVTUN", "ZUQCVTN",
		"ZSQRSHRN", "ZSQRSHRUN", "ZUQRSHRN",
		"ZBF1CVT", "ZBF1CVTLT", "ZBF2CVT", "ZBF2CVTLT",
		"ZF1CVT", "ZF1CVTLT", "ZF2CVT", "ZF2CVTLT",
		"ZBFCVT", "ZBFCVTN", "ZBFCVTNT", "ZFCVTN", "ZFCVTNB", "ZFCVTNT",
		"ZBFADD", "ZBFSUB", "ZBFMUL", "ZBFMAX", "ZBFMAXNM", "ZBFMIN", "ZBFMINNM", "ZBFSCALE",
		"ZBFMLA", "ZBFMLS", "ZBFMLALB", "ZBFMLALT", "ZBFMLSLB", "ZBFMLSLT",
		"ZAESD", "ZAESDIMC", "ZAESE", "ZAESEMC",
		"ZRAX1", "ZSM4E", "ZSM4EKEY",
		"ZASRD", "ZASRR", "ZLSLR", "ZLSRR", "ZSLI", "ZSRI", "ZSRSHR", "ZSRSRA", "ZSSRA", "ZURSHR", "ZURSRA", "ZUSRA", "ZSQSHLU",
		"ZCMLA", "ZSQRDCMLAH",
		"ZSQRDMLAH", "ZSQRDMLSH",
		"ZADR",
		"RBIT", "RBITW", "CLZ", "CLZW", "CLS", "CLSW",
		"BIC", "BICW", "BICS", "BICSW", "ADDS", "ADDSW",
		"FCMPS", "FCMPD", "FCMPES", "FCMPED",
		"FCCMPS", "FCCMPD", "FCCMPES", "FCCMPED",
		"DMB", "DSB", "ISB", "DC", "PRFM", "RPRFM", "BRK", "UNDEF", "HINT", "YIELD", "WFE", "WFI", "SEV", "SEVL", "NOP",
	} {
		if _, ok := supported[op]; !ok {
			t.Errorf("supported opcode extraction omitted %s", op)
		}
	}
	for _, suboperation := range []string{"IVAC", "CIGDVADP", "PLDL1KEEP", "PSTL3STRM"} {
		if _, ok := supported[suboperation]; ok {
			t.Errorf("supported opcode extraction advertised %s suboperation as an instruction", suboperation)
		}
	}
}

func TestExtractSupportedOpsFindsCompleteARMAddedFamilies(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	supported, err := extractSupportedOps(repoRoot, "arm")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{
		"MOVF", "MOVD",
		"NEGF", "NEGD", "ABSF", "ABSD", "SQRTF", "SQRTD", "MOVFD", "MOVDF", "CMPF", "CMPD",
		"ADDF", "ADDD", "SUBF", "SUBD", "MULF", "MULD", "NMULF", "NMULD", "DIVF", "DIVD",
		"MULAF", "MULAD", "MULSF", "MULSD", "NMULAF", "NMULAD", "NMULSF", "NMULSD",
		"FMULAF", "FMULAD", "FMULSF", "FMULSD", "FNMULAF", "FNMULAD", "FNMULSF", "FNMULSD",
		"MOVWF", "MOVWD", "MOVFW", "MOVDW", "PLD",
		"DIV", "DIVU", "MOD", "MODU",
		"SSAT", "USAT", "SSAT16", "USAT16",
	} {
		if _, ok := supported[op]; !ok {
			t.Errorf("supported opcode extraction omitted %s", op)
		}
	}
}

func TestExtractSupportedOpsFindsCompleteWasmFloatUnaryFamily(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	supported, err := extractSupportedOps(repoRoot, "wasm")
	if err != nil {
		t.Fatal(err)
	}
	for _, width := range []string{"F32", "F64"} {
		for _, operation := range []string{"ABS", "NEG", "CEIL", "FLOOR", "TRUNC", "NEAREST", "SQRT"} {
			op := width + operation
			if _, ok := supported[op]; !ok {
				t.Errorf("supported opcode extraction omitted %s", op)
			}
		}
	}
}

func TestAsmFilesOfPkgSkipsCommentOnlyAssembly(t *testing.T) {
	dir := t.TempDir()
	comments := filepath.Join(dir, "comments.s")
	code := filepath.Join(dir, "code.s")
	include := filepath.Join(dir, "include.s")
	for path, contents := range map[string]string{
		comments: "//go:build amd64\n\n/* license only */\n",
		code:     "// comment\nTEXT ·f(SB),0,$0-0\n",
		include:  "#include \"textflag.h\"\n",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	missing := filepath.Join(dir, "missing.s")
	pkg := &packages.Package{OtherFiles: []string{comments, code, include, missing}}
	want := []string{code, include, missing}
	if got := asmFilesOfPkg(pkg); !reflect.DeepEqual(got, want) {
		t.Fatalf("asmFilesOfPkg() = %#v, want %#v", got, want)
	}
}

func TestCollectAsmTasksHonorsExactModuleRelativeAllowlist(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "pkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	amd64File := filepath.Join(pkgDir, "fast.s")
	arm64File := filepath.Join(pkgDir, "portable.s")
	for _, path := range []string{amd64File, arm64File} {
		if err := os.WriteFile(path, []byte("TEXT ·f(SB),0,$0-0\nRET\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pkg := &packages.Package{
		PkgPath:    "example.com/root/pkg",
		OtherFiles: []string{amd64File, arm64File},
		Module:     &packages.Module{Path: "example.com/root", Dir: dir},
	}
	tasks, packages := collectAsmTasks([]*packages.Package{pkg}, "/out", []string{"pkg/portable.s"})
	if len(tasks) != 1 || tasks[0].AsmFile != arm64File {
		t.Fatalf("collectAsmTasks() tasks = %#v, want only %s", tasks, arm64File)
	}
	if !reflect.DeepEqual(packages, []string{"example.com/root/pkg"}) {
		t.Fatalf("collectAsmTasks() packages = %#v", packages)
	}
}

func TestFilterPackagesByModuleExcludesNestedModules(t *testing.T) {
	pkgs := []*packages.Package{
		{PkgPath: "example.com/root/pkg", Module: &packages.Module{Path: "example.com/root"}},
		{PkgPath: "example.com/root/v2", Module: &packages.Module{Path: "example.com/root/v2"}},
		{PkgPath: "example.com/root/vendorless", Module: nil},
	}
	want := []*packages.Package{pkgs[0]}
	if got := filterPackagesByModule(pkgs, "example.com/root"); !reflect.DeepEqual(got, want) {
		t.Fatalf("filterPackagesByModule() = %#v, want %#v", got, want)
	}
}

func TestDefaultMatrixTargetsCoversEveryPlan9Architecture(t *testing.T) {
	want := []targetSpec{
		{Goos: "darwin", Goarch: "amd64"},
		{Goos: "darwin", Goarch: "arm64"},
		{Goos: "linux", Goarch: "386"},
		{Goos: "linux", Goarch: "amd64"},
		{Goos: "linux", Goarch: "arm"},
		{Goos: "linux", Goarch: "arm64"},
		{Goos: "windows", Goarch: "386"},
		{Goos: "windows", Goarch: "amd64"},
		{Goos: "windows", Goarch: "arm64"},
		{Goos: "js", Goarch: "wasm"},
		{Goos: "wasip1", Goarch: "wasm"},
	}
	if got := defaultMatrixTargets(); !reflect.DeepEqual(got, want) {
		t.Fatalf("defaultMatrixTargets() = %#v, want %#v", got, want)
	}
}

func TestExternalCorpusTargetArchitectureAndTriple(t *testing.T) {
	tests := []struct {
		goos       string
		goarch     string
		wantArch   plan9asm.Arch
		wantTriple string
	}{
		{goos: "linux", goarch: "arm", wantArch: plan9asm.ArchARM, wantTriple: "armv7-unknown-linux-gnueabihf"},
		{goos: "js", goarch: "wasm", wantArch: plan9asm.ArchWASM, wantTriple: "wasm32-unknown-unknown"},
		{goos: "wasip1", goarch: "wasm", wantArch: plan9asm.ArchWASM, wantTriple: "wasm32-wasi"},
	}
	for _, test := range tests {
		t.Run(test.goos+"/"+test.goarch, func(t *testing.T) {
			arch, err := toPlan9Arch(test.goarch)
			if err != nil {
				t.Fatal(err)
			}
			if arch != test.wantArch {
				t.Fatalf("toPlan9Arch(%q) = %q, want %q", test.goarch, arch, test.wantArch)
			}
			if got := targetTriple(test.goos, test.goarch); got != test.wantTriple {
				t.Fatalf("targetTriple(%q, %q) = %q, want %q", test.goos, test.goarch, got, test.wantTriple)
			}
		})
	}
}

func TestLLVMArgsAndFrameSlotsForTupleSliceParam(t *testing.T) {
	tup := types.NewTuple(types.NewVar(token.NoPos, nil, "b", types.NewSlice(types.Typ[types.Byte])))
	sz := types.SizesFor("gc", "amd64")
	args, slots, nextOff, err := llvmArgsAndFrameSlotsForTuple(tup, "amd64", sz, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []plan9asm.LLVMType{"{ ptr, i64, i64 }"}) {
		t.Fatalf("args mismatch: %#v", args)
	}
	wantSlots := []plan9asm.FrameSlot{
		{Offset: 0, Type: plan9asm.Ptr, Index: 0, Field: 0},
		{Offset: 8, Type: plan9asm.I64, Index: 0, Field: 1},
		{Offset: 16, Type: plan9asm.I64, Index: 0, Field: 2},
	}
	if !reflect.DeepEqual(slots, wantSlots) {
		t.Fatalf("slots mismatch: got=%#v want=%#v", slots, wantSlots)
	}
	if nextOff != 24 {
		t.Fatalf("nextOff mismatch: got=%d want=24", nextOff)
	}
}

func TestLLVMArgsAndFrameSlotsForTupleSliceResultFlatten(t *testing.T) {
	tup := types.NewTuple(types.NewVar(token.NoPos, nil, "r", types.NewSlice(types.Typ[types.Byte])))
	sz := types.SizesFor("gc", "amd64")
	args, slots, nextOff, err := llvmArgsAndFrameSlotsForTuple(tup, "amd64", sz, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []plan9asm.LLVMType{plan9asm.Ptr, plan9asm.I64, plan9asm.I64}) {
		t.Fatalf("args mismatch: %#v", args)
	}
	wantSlots := []plan9asm.FrameSlot{
		{Offset: 0, Type: plan9asm.Ptr, Index: 0, Field: -1, Name: "r"},
		{Offset: 8, Type: plan9asm.I64, Index: 1, Field: -1, Name: "r"},
		{Offset: 16, Type: plan9asm.I64, Index: 2, Field: -1, Name: "r"},
	}
	if !reflect.DeepEqual(slots, wantSlots) {
		t.Fatalf("slots mismatch: got=%#v want=%#v", slots, wantSlots)
	}
	if nextOff != 24 {
		t.Fatalf("nextOff mismatch: got=%d want=24", nextOff)
	}
}

func TestLLVMArgsAndFrameSlotsForTupleInterfaceParam(t *testing.T) {
	iface := types.NewInterfaceType(nil, nil)
	iface.Complete()
	tup := types.NewTuple(types.NewVar(token.NoPos, nil, "v", iface))
	sz := types.SizesFor("gc", "amd64")
	args, slots, nextOff, err := llvmArgsAndFrameSlotsForTuple(tup, "amd64", sz, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []plan9asm.LLVMType{"{ ptr, ptr }"}) {
		t.Fatalf("args mismatch: %#v", args)
	}
	wantSlots := []plan9asm.FrameSlot{
		{Offset: 0, Type: plan9asm.Ptr, Index: 0, Field: 0},
		{Offset: 8, Type: plan9asm.Ptr, Index: 0, Field: 1},
	}
	if !reflect.DeepEqual(slots, wantSlots) {
		t.Fatalf("slots mismatch: got=%#v want=%#v", slots, wantSlots)
	}
	if nextOff != 16 {
		t.Fatalf("nextOff mismatch: got=%d want=16", nextOff)
	}
}

func TestLLVMArgsAndFrameSlotsForTupleNamedInterfaceParam(t *testing.T) {
	iface := types.NewInterfaceType(nil, nil)
	iface.Complete()
	named := types.NewNamed(types.NewTypeName(token.NoPos, nil, "Reader", nil), iface, nil)
	tup := types.NewTuple(types.NewVar(token.NoPos, nil, "v", named))
	sz := types.SizesFor("gc", "amd64")
	args, slots, _, err := llvmArgsAndFrameSlotsForTuple(tup, "amd64", sz, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []plan9asm.LLVMType{"{ ptr, ptr }"}) {
		t.Fatalf("args mismatch: %#v", args)
	}
	wantSlots := []plan9asm.FrameSlot{
		{Offset: 0, Type: plan9asm.Ptr, Index: 0, Field: 0},
		{Offset: 8, Type: plan9asm.Ptr, Index: 0, Field: 1},
	}
	if !reflect.DeepEqual(slots, wantSlots) {
		t.Fatalf("slots mismatch: got=%#v want=%#v", slots, wantSlots)
	}
}

func TestLLVMArgsAndFrameSlotsForNestedAggregateParam(t *testing.T) {
	slice := types.NewSlice(types.Typ[types.Byte])
	array := types.NewArray(slice, 2)
	tup := types.NewTuple(types.NewVar(token.NoPos, nil, "blocks", array))
	sz := types.SizesFor("gc", "amd64")
	args, slots, nextOff, err := llvmArgsAndFrameSlotsForTuple(tup, "amd64", sz, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []plan9asm.LLVMType{"[2 x { ptr, i64, i64 }]"}) {
		t.Fatalf("args mismatch: %#v", args)
	}
	wantSlots := []plan9asm.FrameSlot{
		{Offset: 0, Type: plan9asm.Ptr, Index: 0, Field: 0, Fields: []int{0, 0}},
		{Offset: 8, Type: plan9asm.I64, Index: 0, Field: 0, Fields: []int{0, 1}},
		{Offset: 16, Type: plan9asm.I64, Index: 0, Field: 0, Fields: []int{0, 2}},
		{Offset: 24, Type: plan9asm.Ptr, Index: 0, Field: 1, Fields: []int{1, 0}},
		{Offset: 32, Type: plan9asm.I64, Index: 0, Field: 1, Fields: []int{1, 1}},
		{Offset: 40, Type: plan9asm.I64, Index: 0, Field: 1, Fields: []int{1, 2}},
	}
	if !reflect.DeepEqual(slots, wantSlots) {
		t.Fatalf("slots mismatch: got=%#v want=%#v", slots, wantSlots)
	}
	if nextOff != 48 {
		t.Fatalf("nextOff mismatch: got=%d want=48", nextOff)
	}
}

func TestLLVMArgsAndFrameSlotsForStructParam(t *testing.T) {
	st := types.NewStruct([]*types.Var{
		types.NewVar(token.NoPos, nil, "A", types.NewArray(types.Typ[types.Uint16], 3)),
		types.NewVar(token.NoPos, nil, "B", types.Typ[types.Byte]),
		types.NewVar(token.NoPos, nil, "C", types.Typ[types.String]),
	}, nil)
	tup := types.NewTuple(types.NewVar(token.NoPos, nil, "v", st))
	sz := types.SizesFor("gc", "amd64")
	args, slots, nextOff, err := llvmArgsAndFrameSlotsForTuple(tup, "amd64", sz, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []plan9asm.LLVMType{"{ [3 x i16], i8, { ptr, i64 } }"}) {
		t.Fatalf("args mismatch: %#v", args)
	}
	wantSlots := []plan9asm.FrameSlot{
		{Offset: 0, Type: plan9asm.I16, Index: 0, Field: 0, Fields: []int{0, 0}},
		{Offset: 2, Type: plan9asm.I16, Index: 0, Field: 0, Fields: []int{0, 1}},
		{Offset: 4, Type: plan9asm.I16, Index: 0, Field: 0, Fields: []int{0, 2}},
		{Offset: 6, Type: plan9asm.I8, Index: 0, Field: 1},
		{Offset: 8, Type: plan9asm.Ptr, Index: 0, Field: 2, Fields: []int{2, 0}},
		{Offset: 16, Type: plan9asm.I64, Index: 0, Field: 2, Fields: []int{2, 1}},
	}
	if !reflect.DeepEqual(slots, wantSlots) {
		t.Fatalf("slots mismatch: got=%#v want=%#v", slots, wantSlots)
	}
	if nextOff != 24 {
		t.Fatalf("nextOff mismatch: got=%d want=24", nextOff)
	}
}

func TestLLVMArgsAndFrameSlotsFlattensArrayResult(t *testing.T) {
	array := types.NewArray(types.Typ[types.Byte], 7)
	tup := types.NewTuple(types.NewVar(token.NoPos, nil, "result", array))
	sz := types.SizesFor("gc", "amd64")
	args, slots, nextOff, err := llvmArgsAndFrameSlotsForTuple(tup, "amd64", sz, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []plan9asm.LLVMType{
		plan9asm.I8, plan9asm.I8, plan9asm.I8, plan9asm.I8,
		plan9asm.I8, plan9asm.I8, plan9asm.I8,
	}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("args mismatch: got=%#v want=%#v", args, wantArgs)
	}
	for i, slot := range slots {
		want := plan9asm.FrameSlot{Offset: int64(i), Type: plan9asm.I8, Index: i, Field: -1, Name: "result"}
		if !reflect.DeepEqual(slot, want) {
			t.Fatalf("slot %d = %#v, want %#v", i, slot, want)
		}
	}
	if nextOff != 7 {
		t.Fatalf("nextOff mismatch: got=%d want=7", nextOff)
	}
}

func TestLLVMArgsAndFrameSlotsForComplexParamsAndResults(t *testing.T) {
	for _, goarch := range []string{"386", "amd64", "arm", "arm64"} {
		t.Run(goarch, func(t *testing.T) {
			tup := types.NewTuple(
				types.NewVar(token.NoPos, nil, "c64", types.Typ[types.Complex64]),
				types.NewVar(token.NoPos, nil, "c128", types.Typ[types.Complex128]),
			)
			sz := types.SizesFor("gc", goarch)
			args, slots, nextOff, err := llvmArgsAndFrameSlotsForTuple(tup, goarch, sz, 0, false)
			if err != nil {
				t.Fatal(err)
			}
			wantArgs := []plan9asm.LLVMType{"{ float, float }", "{ double, double }"}
			if !reflect.DeepEqual(args, wantArgs) {
				t.Fatalf("parameter args mismatch: got=%#v want=%#v", args, wantArgs)
			}
			wantSlots := []plan9asm.FrameSlot{
				{Offset: 0, Type: plan9asm.LLVMType("float"), Index: 0, Field: 0},
				{Offset: 4, Type: plan9asm.LLVMType("float"), Index: 0, Field: 1},
				{Offset: 8, Type: plan9asm.LLVMType("double"), Index: 1, Field: 0},
				{Offset: 16, Type: plan9asm.LLVMType("double"), Index: 1, Field: 1},
			}
			if !reflect.DeepEqual(slots, wantSlots) {
				t.Fatalf("parameter slots mismatch: got=%#v want=%#v", slots, wantSlots)
			}
			if nextOff != 24 {
				t.Fatalf("parameter nextOff = %d, want 24", nextOff)
			}

			results, resultSlots, resultEnd, err := llvmArgsAndFrameSlotsForTuple(tup, goarch, sz, 0, true)
			if err != nil {
				t.Fatal(err)
			}
			wantResults := []plan9asm.LLVMType{"float", "float", "double", "double"}
			if !reflect.DeepEqual(results, wantResults) {
				t.Fatalf("flattened result args mismatch: got=%#v want=%#v", results, wantResults)
			}
			wantResultSlots := []plan9asm.FrameSlot{
				{Offset: 0, Type: plan9asm.LLVMType("float"), Index: 0, Field: -1, Name: "c64"},
				{Offset: 4, Type: plan9asm.LLVMType("float"), Index: 1, Field: -1, Name: "c64"},
				{Offset: 8, Type: plan9asm.LLVMType("double"), Index: 2, Field: -1, Name: "c128"},
				{Offset: 16, Type: plan9asm.LLVMType("double"), Index: 3, Field: -1, Name: "c128"},
			}
			if !reflect.DeepEqual(resultSlots, wantResultSlots) {
				t.Fatalf("result slots mismatch: got=%#v want=%#v", resultSlots, wantResultSlots)
			}
			if resultEnd != 24 {
				t.Fatalf("result nextOff = %d, want 24", resultEnd)
			}
		})
	}
}
