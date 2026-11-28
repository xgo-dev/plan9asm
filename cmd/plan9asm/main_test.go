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

func TestTranslateX86AssemblyBindsGoConstant(t *testing.T) {
	decls := types.NewPackage("example", "example")
	decls.Scope().Insert(types.NewConst(token.NoPos, decls, "Guard", types.Typ[types.Int], constant.MakeInt64(731)))
	result := types.NewVar(token.NoPos, decls, "ret", types.Typ[types.Int32])
	decls.Scope().Insert(types.NewFunc(token.NoPos, decls, "read", types.NewSignature(nil, nil, types.NewTuple(result), false)))
	path := filepath.Join(t.TempDir(), "read.s")
	if err := os.WriteFile(path, []byte("TEXT ·read(SB),4,$0-4\nMOVL $const_Guard,AX\nMOVL AX,ret+0(FP)\nRET\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		pkg := &packages.Package{PkgPath: "example", Types: decls, TypesSizes: types.SizesFor("gc", arch)}
		tr, err := translateAsmForPackage(pkg, path, "linux", arch, false)
		if err != nil || !strings.Contains(tr.LLVMIR, "731") {
			t.Fatalf("%s: translate = %v, IR = %s", arch, err, tr.LLVMIR)
		}
	}
}

func TestTranslatePackageDataAndStub(t *testing.T) {
	dir := t.TempDir()
	const data = "DATA ·table+0(SB)/4, $0x71426354\nGLOBL ·table(SB),8,$4\n"
	if err := os.WriteFile(filepath.Join(dir, "payload.h"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.h"), []byte("DATA ·table+0(SB)/4, $UNKNOWN_DATA_VALUE\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p := types.NewPackage("example", "example")
	pkg := &packages.Package{PkgPath: p.Path(), Types: p, TypesSizes: types.SizesFor("gc", "amd64")}
	for _, tc := range []struct {
		name, src string
		hasData   bool
		fails     bool
	}{
		{"data", data, true, false},
		{"text_and_include", "#include \"payload.h\"\nTEXT ·present(SB),4,$0-0\nRET\n", true, false}, {"include", "#include \"payload.h\"\n", true, false},
		{"broken", "#include \"broken.h\"\n", false, true},
		{"stub", "#include \"textflag.h\"\n", false, false}, {"missing", "#include \"not_here.h\"\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".s")
			if err := os.WriteFile(path, []byte(tc.src), 0600); err != nil {
				t.Fatal(err)
			}
			tr, err := translateAsmForPackage(pkg, path, "linux", "amd64", false)
			if tc.fails {
				if err == nil {
					t.Fatal("accepted unresolved assembly header")
				}
				return
			}
			if err != nil || tr.LLVMIR == "" || strings.Contains(tr.LLVMIR, "example.table") != tc.hasData {
				t.Fatalf("translation err=%v IR=%s", err, tr.LLVMIR)
			}
		})
	}
}

func TestTranslateSelectsTargetOperatingSystem(t *testing.T) {
	p := types.NewPackage("example", "example")
	pkg := &packages.Package{PkgPath: p.Path(), Types: p, TypesSizes: types.SizesFor("gc", "amd64")}
	path := filepath.Join(t.TempDir(), "os.s")
	src := "#ifdef GOOS_windows\nTEXT ·onWindows(SB),4,$0-0\n#else\nTEXT ·onOther(SB),4,$0-0\n#endif\nRET\n"
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ os, sym string }{{"windows", "example.onWindows"}, {"linux", "example.onOther"}} {
		tr, err := translateAsmForPackage(pkg, path, tc.os, "amd64", false)
		if err != nil || len(tr.Functions) != 1 || tr.Functions[0].Resolved != tc.sym {
			t.Errorf("%s: functions=%v err=%v", tc.os, tr.Functions, err)
		}
	}
}

func Test386AddressedABISuffixedDeclaration(t *testing.T) {
	p := types.NewPackage("pkg", "pkg")
	result := types.NewTuple(types.NewVar(token.NoPos, p, "", types.Typ[types.Int32]))
	p.Scope().Insert(types.NewFunc(token.NoPos, p, "callee", types.NewSignature(nil, nil, result, false)))
	pkg := &packages.Package{PkgPath: p.Path(), Types: p, TypesSizes: types.SizesFor("gc", "386")}
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT ·f(SB),4,$0\n MOVL $·callee<ABI0>(SB),AX\n RET")
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := sigsForAsmFile(pkg, file, func(s string) string { return strings.ReplaceAll(s, "·", "pkg.") }, "386")
	if err != nil || sigs["pkg.callee"].Ret != plan9asm.I32 {
		t.Fatalf("callee signature: %v, %v", sigs, err)
	}
}
