package main

import (
	"bytes"
	"debug/elf"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

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
		{Offset: 0, Type: plan9asm.Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: plan9asm.I64, Index: 1, Field: -1},
		{Offset: 16, Type: plan9asm.I64, Index: 2, Field: -1},
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

func TestCompileOneAssemblyExpandsGoConstant(t *testing.T) {
	dir := t.TempDir()
	file, out := filepath.Join(dir, "const.s"), filepath.Join(dir, "const.ll")
	if err := os.WriteFile(file, []byte("TEXT ·value(SB),4,$0-4\nMOVL $const_minMatch,AX\nMOVL AX,ret+0(FP)\nRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pkg := types.NewPackage("example.com/lz4", "lz4")
	pkg.Scope().Insert(types.NewConst(token.NoPos, pkg, "minMatch", types.Typ[types.Int], constant.MakeInt64(731)))
	sig := types.NewSignature(nil, nil, types.NewTuple(types.NewVar(token.NoPos, pkg, "", types.Typ[types.Int32])), false)
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "value", sig))
	p := &packages.Package{PkgPath: pkg.Path(), Types: pkg, TypesSizes: types.SizesFor("gc", "amd64")}
	if err := compileOne(p, "linux", "amd64", "x86_64-unknown-linux-gnu", asmTask{AsmFile: file, OutLL: out}, false, compileConfig{}); err != nil {
		t.Fatal(err)
	}
	ir, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(ir), "731") {
		t.Fatalf("missing Go constant in IR: %v: %s", err, ir)
	}
}

func TestCompileOneDataAndStubEmitObjects(t *testing.T) {
	dir := t.TempDir()
	const data = "DATA ·table+0(SB)/4, $0x71426354\nGLOBL ·table(SB),8,$4\n"
	if err := os.WriteFile(filepath.Join(dir, "data.h"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	decls := types.NewPackage("example", "example")
	pkg := &packages.Package{PkgPath: decls.Path(), Types: decls, TypesSizes: types.SizesFor("gc", "amd64")}
	cfg, err := resolveCompileConfig(true, "", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, src string
		want      bool
	}{
		{"data", data, true}, {"include", "#include \"data.h\"\n", true}, {"empty", "", false}, {"stub", "#include \"textflag.h\"\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := filepath.Join(dir, tc.name)
			if err := os.WriteFile(base+".s", []byte(tc.src), 0600); err != nil {
				t.Fatal(err)
			}
			if err := compileOne(pkg, "linux", "amd64", "x86_64-unknown-linux-gnu", asmTask{AsmFile: base + ".s", OutLL: base + ".ll"}, false, cfg); err != nil {
				t.Fatal(err)
			}
			f, err := elf.Open(base + ".o")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			syms, err := f.Symbols()
			if err != nil && err != elf.ErrNoSymbols {
				t.Fatal(err)
			}
			found := false
			for _, s := range syms {
				if s.Name == "example.table" {
					section := f.Sections[s.Section]
					buf, err := section.Data()
					if err != nil {
						t.Fatal(err)
					}
					if s.Size != 4 || !bytes.Equal(buf[s.Value-section.Addr:][:4], []byte{0x54, 0x63, 0x42, 0x71}) {
						t.Fatalf("bad DATA symbol %+v: %x", s, buf)
					}
					found = true
				}
			}
			if found != tc.want {
				t.Errorf("DATA symbol found=%t, want %t", found, tc.want)
			}
		})
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
