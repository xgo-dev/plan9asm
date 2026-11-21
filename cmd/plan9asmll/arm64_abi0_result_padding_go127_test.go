//go:build go1.27

package main

import (
	"debug/elf"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCompileOneSelectedSDKARM64AtomicsTrailingResult(t *testing.T) {
	const packagePath = "internal/runtime/atomic"
	setX86SDKNumericalCLIProfile(t, "explicit")
	t.Setenv("GOROOT", runtime.GOROOT())
	t.Chdir(filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(packagePath)))
	packages, environment, err := loadPkgsInEnvironment("linux", "arm64", []string{"."}, nil, "", true, false, nil)
	if err != nil || len(packages) != 1 || packages[0].PkgPath != packagePath {
		t.Fatal("could not load the original ARM64 SDK atomic package", err)
	}
	pkg := packages[0]
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = arm64PrivateCLIContext(t)
	config.x86CallerSelections = captureX86CallerSelectionsInEnvironment(packages, "linux/arm64", environment)
	dir := t.TempDir()
	task := asmTask{PkgPath: pkg.PkgPath, AsmFile: filepath.Join(pkg.Dir, "atomic_arm64.s"), OutLL: filepath.Join(dir, "atomic.ll")}
	if err := compileOne(pkg, plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu", task, false, config); err != nil {
		t.Fatal(err)
	}
	object, err := elf.Open(filepath.Join(dir, "atomic.o"))
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	if object.Machine != elf.EM_AARCH64 {
		t.Fatal("expected AArch64 object", object.Machine)
	}
	symbols, err := object.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	defined := make(map[string]bool)
	for _, symbol := range symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC && symbol.Section != elf.SHN_UNDEF && symbol.Size != 0 {
			defined[symbol.Name] = true
		}
	}
	for _, name := range []string{"Or32", "And32"} {
		if !defined[packagePath+"."+name] {
			t.Error("compiled SDK member is missing", name)
		}
	}
}
