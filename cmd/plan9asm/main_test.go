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
	"github.com/xgo-dev/plan9asm/cmd/internal/asmfile"
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

func TestWasmTargetConfiguration(t *testing.T) {
	if got, err := asmfile.Architecture("wasm"); err != nil || got != plan9asm.ArchWASM {
		t.Fatalf("asmfile.Architecture(wasm) = (%q, %v)", got, err)
	}
	if got := targetTriple("js", "wasm"); got != "wasm32-unknown-unknown" {
		t.Fatalf("targetTriple(js, wasm) = %q", got)
	}
	if got := targetTriple("wasip1", "wasm"); got != "wasm32-unknown-wasi" {
		t.Fatalf("targetTriple(wasip1, wasm) = %q", got)
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
