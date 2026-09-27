package main

import (
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

func TestPackageSFilesAbsFiltersNonPlan9Asm(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(t.TempDir(), "abs", "keep.s")
	pkg := goListPackage{
		Dir: dir,
		SFiles: []string{
			"foo.s",
			"bar.S",
			"baz.Sx",
			abs,
		},
	}
	got := packageSFilesAbs(pkg)
	want := []string{
		filepath.Join(dir, "foo.s"),
		abs,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packageSFilesAbs() = %#v, want %#v", got, want)
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
	sigs, err := sigsForAsmFile(pkg, file, resolveSymFunc(pkg.PkgPath), "arm64")
	if err != nil {
		t.Fatal(err)
	}
	helper := sigs[pkg.PkgPath+".HaltEl1ExceptionAndResume"]
	if len(helper.Args) != 1 || helper.Args[0] != plan9asm.I64 ||
		len(helper.Frame.Params) != 1 || helper.Frame.Params[0].Offset != 0 {
		t.Fatalf("tail helper did not borrow caller's ABI0 frame: %+v", helper)
	}
}

func TestTranslateAsmForPackageExpandsRuntimeStyleFunctionMacro(t *testing.T) {
	dir := t.TempDir()
	header := filepath.Join(dir, "abi.h")
	asm := filepath.Join(dir, "entry_arm64.s")
	if err := os.WriteFile(header, []byte("#ifdef GOOS_linux\n#define SAVE(offset) MOVD R19, offset(RSP)\n#else\n#define SAVE(offset) UNKNOWN_TARGET\n#endif\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(asm, []byte("#include \"abi.h\"\nTEXT ·entry(SB),NOSPLIT,$0-0\nSAVE(8)\nRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgTypes := types.NewPackage("example.com/m/p", "p")
	pkgTypes.Scope().Insert(types.NewFunc(token.NoPos, pkgTypes, "entry", types.NewSignature(nil, nil, nil, false)))
	pkg := &packages.Package{
		PkgPath:    pkgTypes.Path(),
		Types:      pkgTypes,
		TypesSizes: types.SizesFor("gc", "arm64"),
		Module:     &packages.Module{Path: "example.com/m", Dir: dir},
	}
	tr, ok, err := translateAsmForPackage(pkg, asm, "linux", "arm64", false)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !strings.Contains(tr.LLVMIR, "store i64") {
		t.Fatalf("included SAVE macro was not translated:\n%s", tr.LLVMIR)
	}
}

func TestTranslateAsmForPackageExpandsGeneratedGoAsmConstants(t *testing.T) {
	dir := t.TempDir()
	asm := filepath.Join(dir, "asm_amd64.s")
	if err := os.WriteFile(asm, []byte(`#include "go_asm.h"
#ifdef GOOS_windows
GLOBL zeroTLS<>(SB),RODATA,$const_tlsSize
#endif
TEXT ·entry(SB),NOSPLIT,$0-0
RET
`), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgTypes := types.NewPackage("runtime", "runtime")
	pkgTypes.Scope().Insert(types.NewConst(token.NoPos, pkgTypes, "tlsSize", types.Typ[types.Int], constant.MakeInt64(48)))
	pkgTypes.Scope().Insert(types.NewFunc(token.NoPos, pkgTypes, "entry", types.NewSignature(nil, nil, nil, false)))
	pkg := &packages.Package{
		PkgPath:    pkgTypes.Path(),
		Types:      pkgTypes,
		TypesSizes: types.SizesFor("gc", "amd64"),
		Module:     &packages.Module{Path: "runtime", Dir: dir},
	}
	tr, ok, err := translateAsmForPackage(pkg, asm, "windows", "amd64", false)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !strings.Contains(tr.LLVMIR, `@"runtime.zeroTLS$local" = internal constant [48 x i8]`) {
		t.Fatalf("generated const_tlsSize was not expanded:\n%s", tr.LLVMIR)
	}
}

func TestFallbackSigUsesTargetWordSize(t *testing.T) {
	fn := plan9asm.Func{Instrs: []plan9asm.Instr{{
		Op: "MOVW",
		Args: []plan9asm.Operand{
			{Kind: plan9asm.OpFP, FPName: "x", FPOffset: 0},
			{Kind: plan9asm.OpFP, FPName: "ret", FPOffset: 4},
		},
	}}}
	for _, tc := range []struct {
		goarch string
		want   plan9asm.LLVMType
	}{
		{goarch: "arm", want: plan9asm.I32},
		{goarch: "386", want: plan9asm.I32},
		{goarch: "arm64", want: plan9asm.I64},
		{goarch: "amd64", want: plan9asm.I64},
		{goarch: "wasm", want: plan9asm.I64},
	} {
		t.Run(tc.goarch, func(t *testing.T) {
			got := fallbackSigForAsmFunc(fn, "example.f", tc.goarch)
			if len(got.Args) != 1 || got.Args[0] != tc.want || got.Ret != tc.want {
				t.Fatalf("fallback signature = %#v, want arg and return %s", got, tc.want)
			}
		})
	}
}

func TestFallbackSigTreatsAddressedFrameWithoutResultAsVoid(t *testing.T) {
	fn := plan9asm.Func{Instrs: []plan9asm.Instr{{
		Op: "LEAL",
		Args: []plan9asm.Operand{
			{Kind: plan9asm.OpFPAddr, FPName: "arg", FPOffset: 0},
			{Kind: plan9asm.OpReg, Reg: "AX"},
		},
	}}}
	got := fallbackSigForAsmFunc(fn, "example.helper$local", "386")
	if len(got.Args) != 1 || got.Args[0] != plan9asm.I32 || got.Ret != plan9asm.Void {
		t.Fatalf("fallback signature = %#v, want (i32) -> void", got)
	}
}

func TestLikelyResultSlotUsesExplicitResultPrefix(t *testing.T) {
	if !isLikelyResultSlot("MOVW", 0, 2, "ret0") {
		t.Fatal("ret-prefixed FP slot was not classified as a result")
	}
	for _, name := range []string{"roundTripRet", "r_ret", "request"} {
		if isLikelyResultSlot("MOVW", 0, 2, name) {
			t.Errorf("parameter FP slot %q was classified as a result", name)
		}
	}
}

func TestWasmTargetConfiguration(t *testing.T) {
	if got, err := toPlan9Arch("wasm"); err != nil || got != plan9asm.ArchWASM {
		t.Fatalf("toPlan9Arch(wasm) = (%q, %v)", got, err)
	}
	if got := targetTriple("js", "wasm"); got != "wasm32-unknown-unknown" {
		t.Fatalf("targetTriple(js, wasm) = %q", got)
	}
	if got := targetTriple("wasip1", "wasm"); got != "wasm32-unknown-wasi" {
		t.Fatalf("targetTriple(wasip1, wasm) = %q", got)
	}
	if got := wordSize("wasm"); got != 8 {
		t.Fatalf("wordSize(wasm) = %d, want official Go wasm word size 8", got)
	}
}

func TestARMBaselineTargetTriples(t *testing.T) {
	for _, tc := range []struct {
		goarm string
		want  string
	}{
		{goarm: "5", want: "armv5te-unknown-linux-gnueabi"},
		{goarm: "6", want: "armv6-unknown-linux-gnueabihf"},
		{goarm: "7", want: "armv7-unknown-linux-gnueabihf"},
		{goarm: "7,softfloat", want: "armv7-unknown-linux-gnueabihf"},
	} {
		t.Run(tc.goarm, func(t *testing.T) {
			t.Setenv("GOARM", tc.goarm)
			if got := targetTriple("linux", "arm"); got != tc.want {
				t.Fatalf("targetTriple(linux, arm) with GOARM=%s = %q, want %q", tc.goarm, got, tc.want)
			}
		})
	}
}

func TestARM64V8BaselineTargetTriples(t *testing.T) {
	t.Setenv("GOARM64", "v8.0")
	for _, tc := range []struct {
		goos string
		want string
	}{
		{goos: "linux", want: "aarch64-unknown-linux-gnu"},
		{goos: "darwin", want: "arm64-apple-macosx"},
		{goos: "windows", want: "aarch64-pc-windows-msvc"},
	} {
		if got := targetTriple(tc.goos, "arm64"); got != tc.want {
			t.Fatalf("targetTriple(%s, arm64) with GOARM64=v8.0 = %q, want %q", tc.goos, got, tc.want)
		}
	}
}

func TestTailLocalHelperKeepsLocalIdentityAndCallerReturn(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchARM, `TEXT ·caller(SB),NOSPLIT,$0-1
	MOVB $1, ret+0(FP)
	B helper<>(SB)

TEXT helper<>(SB),NOSPLIT,$0-1
	MOVB R0, ret+0(FP)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	pkgTypes := types.NewPackage("example", "example")
	result := types.NewVar(token.NoPos, pkgTypes, "ret", types.Typ[types.Bool])
	caller := types.NewFunc(token.NoPos, pkgTypes, "caller", types.NewSignature(nil, nil, types.NewTuple(result), false))
	pkgTypes.Scope().Insert(caller)
	pkg := &packages.Package{Types: pkgTypes, TypesSizes: types.SizesFor("gc", "arm")}
	sigs, err := sigsForAsmFile(pkg, file, resolveSymFunc("example"), "arm")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := sigs["example.helper$local"]
	if !ok {
		t.Fatalf("local helper signature missing: %#v", sigs)
	}
	if got.Ret != plan9asm.I1 || len(got.Frame.Results) != 1 || got.Frame.Results[0].Type != plan9asm.I1 {
		t.Fatalf("local helper signature = %#v, want i1 return and result slot", got)
	}
}

func TestPackageQualifiedAsmSymbolUsesLocalDeclaration(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchARM, `TEXT runtime·pipe2(SB),NOSPLIT,$0-16
	MOVW $r+4(FP), R0
	MOVW flags+0(FP), R1
	MOVW R0, errno+12(FP)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	pkgTypes := types.NewPackage("runtime", "runtime")
	params := types.NewTuple(types.NewVar(token.NoPos, pkgTypes, "flags", types.Typ[types.Int32]))
	results := types.NewTuple(
		types.NewVar(token.NoPos, pkgTypes, "r", types.Typ[types.Int32]),
		types.NewVar(token.NoPos, pkgTypes, "w", types.Typ[types.Int32]),
		types.NewVar(token.NoPos, pkgTypes, "errno", types.Typ[types.Int32]),
	)
	pkgTypes.Scope().Insert(types.NewFunc(token.NoPos, pkgTypes, "pipe2", types.NewSignature(nil, params, results, false)))
	pkg := &packages.Package{Types: pkgTypes, TypesSizes: types.SizesFor("gc", "arm")}
	sigs, err := sigsForAsmFile(pkg, file, resolveSymFunc("runtime"), "arm")
	if err != nil {
		t.Fatal(err)
	}
	got := sigs["runtime.pipe2"]
	if len(got.Frame.Results) != 3 || got.Frame.Results[0].Offset != 4 || got.Frame.Results[2].Offset != 12 {
		t.Fatalf("pipe2 signature = %#v, want result slots at 4, 8, 12", got)
	}
}

func TestUndeclaredEntryTailCallInheritsDeclaredVoidReturn(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, `TEXT _rt0_386(SB),NOSPLIT,$8
	JMP runtime·rt0_go(SB)

TEXT runtime·rt0_go(SB),NOSPLIT,$0
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	pkgTypes := types.NewPackage("runtime", "runtime")
	pkgTypes.Scope().Insert(types.NewFunc(token.NoPos, pkgTypes, "rt0_go", types.NewSignature(nil, nil, nil, false)))
	pkg := &packages.Package{Types: pkgTypes, TypesSizes: types.SizesFor("gc", "386")}
	sigs, err := sigsForAsmFile(pkg, file, resolveSymFunc("runtime"), "386")
	if err != nil {
		t.Fatal(err)
	}
	if got := sigs["_rt0_386"].Ret; got != plan9asm.Void {
		t.Fatalf("_rt0_386 return = %s, want void from its declared tail target", got)
	}
}

func TestUndeclaredPureForwarderInheritsABI0Frame(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT forward(SB),$0-8\nJMP body(SB)\nTEXT body(SB),$0-8\nMOVQ arg+0(FP), AX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range []*packages.Package{nil, {Types: types.NewPackage("example", "example"), TypesSizes: types.SizesFor("gc", "amd64")}} {
		sigs, err := sigsForAsmFile(pkg, file, resolveSymFunc("example"), "amd64")
		if err != nil {
			t.Fatal(err)
		}
		got := sigs["forward"]
		if got.Ret != plan9asm.Void || len(got.Args) != 1 || len(got.Frame.Params) != 1 {
			t.Fatalf("forward ABI = %#v", got)
		}
	}
}

func TestSigsForAsmFileDiscoversWasmCallOpcodes(t *testing.T) {
	for _, op := range []string{"Call", "CALLNORESUME"} {
		t.Run(op, func(t *testing.T) {
			file, err := plan9asm.Parse(plan9asm.ArchWASM, "TEXT ·caller(SB),NOSPLIT,$0-0\n\t"+op+" ·target(SB)\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			pkgTypes := types.NewPackage("example", "example")
			voidSig := types.NewSignature(nil, nil, nil, false)
			pkgTypes.Scope().Insert(types.NewFunc(token.NoPos, pkgTypes, "caller", voidSig))
			pkgTypes.Scope().Insert(types.NewFunc(token.NoPos, pkgTypes, "target", voidSig))
			pkg := &packages.Package{Types: pkgTypes, TypesSizes: types.SizesFor("gc", "wasm")}
			sigs, err := sigsForAsmFile(pkg, file, resolveSymFunc("example"), "wasm")
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := sigs["example.target"]; !ok || got.Ret != plan9asm.Void {
				t.Fatalf("%s target signature = %#v, present=%v; want void", op, got, ok)
			}
		})
	}
}

func TestSigsForAsmFileUsesGoWasmNativeSignatures(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchWASM, `TEXT wasm_export_run(SB),NOSPLIT,$0
	Call wasm_pc_f_loop(SB)
	Return

TEXT gcWriteBarrier<>(SB),NOSPLIT,$0
	Get R0
	I64Const $8
	I64Add
	Return
`)
	if err != nil {
		t.Fatal(err)
	}
	pkgTypes := types.NewPackage("runtime", "runtime")
	pkg := &packages.Package{Types: pkgTypes, TypesSizes: types.SizesFor("gc", "wasm")}
	sigs, err := sigsForAsmFile(pkg, file, resolveSymFunc("runtime"), "wasm")
	if err != nil {
		t.Fatal(err)
	}
	if got := sigs["wasm_pc_f_loop"]; len(got.Args) != 0 || got.Ret != plan9asm.Void || !got.WASMNative {
		t.Fatalf("wasm_pc_f_loop signature = %#v; want native () -> void", got)
	}
	if got := sigs["runtime.gcWriteBarrier$local"]; !reflect.DeepEqual(got.Args, []plan9asm.LLVMType{plan9asm.I64}) || got.Ret != plan9asm.I64 || !got.WASMNative {
		t.Fatalf("gcWriteBarrier signature = %#v; want native (i64) -> i64", got)
	}
}

func TestLLVMTypeForGoPointerLikeValues(t *testing.T) {
	for name, typ := range map[string]types.Type{
		"func": types.NewSignature(nil, nil, nil, false),
		"map":  types.NewMap(types.Typ[types.String], types.Typ[types.Int]),
		"chan": types.NewChan(types.SendRecv, types.Typ[types.Int]),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := llvmTypeForGo(typ, "arm"); err != nil || got != plan9asm.Ptr {
				t.Fatalf("llvmTypeForGo(%s) = (%s, %v), want ptr", typ, got, err)
			}
		})
	}
}

func TestZeroSizedTupleValueHasNoFrameSlot(t *testing.T) {
	empty := types.NewStruct(nil, nil)
	tuple := types.NewTuple(types.NewVar(token.NoPos, nil, "marker", empty))
	args, slots, next, err := llvmArgsAndFrameSlotsForTuple(tuple, "arm", types.SizesFor("gc", "arm"), 0, false)
	if err != nil || len(args) != 0 || len(slots) != 0 || next != 0 {
		t.Fatalf("zero-sized tuple = (%v, %v, %d, %v), want empty layout", args, slots, next, err)
	}
}

func TestInterfaceTupleUsesTwoPhysicalFrameSlots(t *testing.T) {
	iface := types.NewInterfaceType(nil, nil).Complete()
	tuple := types.NewTuple(types.NewVar(token.NoPos, nil, "value", iface))
	args, slots, next, err := llvmArgsAndFrameSlotsForTuple(tuple, "386", types.SizesFor("gc", "386"), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 1 || args[0] != plan9asm.LLVMType("{ ptr, ptr }") || len(slots) != 2 || next != 8 {
		t.Fatalf("interface tuple = (%v, %#v, %d), want one aggregate and two pointer slots", args, slots, next)
	}
	if slots[0].Offset != 0 || slots[0].Field != 0 || slots[1].Offset != 4 || slots[1].Field != 1 {
		t.Fatalf("interface frame slots = %#v, want offsets 0/4 and fields 0/1", slots)
	}
}

func TestGoListPackagesDisablesCgo(t *testing.T) {
	dir := t.TempDir()
	name := "go"
	script := "#!/bin/sh\nprintf '%s\\n' \"{\\\"ImportPath\\\":\\\"$CGO_ENABLED\\\"}\"\n"
	if runtime.GOOS == "windows" {
		name = "go.cmd"
		script = "@echo off\r\necho {\"ImportPath\":\"%CGO_ENABLED%\"}\r\n"
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	pkgs, err := goListPackages("std", "linux", "amd64")
	if err != nil {
		t.Fatalf("goListPackages() error = %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].ImportPath != "0" {
		t.Fatalf("goListPackages() = %#v, want one package with CGO disabled", pkgs)
	}
}
