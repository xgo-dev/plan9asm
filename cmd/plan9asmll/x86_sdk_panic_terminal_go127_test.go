//go:build go1.27

package main

import (
	"debug/elf"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCompileOneSelectedSDK386AtomicWholeFile(t *testing.T) {
	setX86SDKNumericalCLIProfile(t, "explicit")
	t.Setenv("GOROOT", runtime.GOROOT())
	t.Chdir(filepath.Join(runtime.GOROOT(), "src", "internal", "runtime", "atomic"))
	packages, environment, err := loadPkgsInEnvironment("linux", "386", []string{"."}, nil, "", true, false, nil)
	if err != nil || len(packages) != 1 || packages[0].PkgPath != "internal/runtime/atomic" {
		t.Fatal("could not load the selected SDK package", err)
	}
	pkg := packages[0]
	input := filepath.Join(pkg.Dir, "atomic_386.s")
	source, err := plan9asm.ReadGoAssemblySourceAtGOROOT(input, pkg.Dir, runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := plan9asm.ParseWithDefines(plan9asm.ArchAMD64, string(source), plan9asm.GoAssemblerDefines("linux", "386"))
	if err != nil || len(parsed.Funcs) != 42 {
		t.Fatal("complete original SDK TEXT inventory changed", err)
	}
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = arm64PrivateCLIContext(t)
	config.x86CallerSelections = captureX86CallerSelectionsInEnvironment(packages, "linux/386", environment)
	output := filepath.Join(t.TempDir(), "atomic.ll")
	if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "386", "i386-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
		t.Fatal(err)
	}
	ir, err := os.ReadFile(output)
	if err != nil || strings.Count(string(ir), "fence seq_cst") != 1 {
		t.Fatal("the original complete member lost its physical fence", err)
	}
	object, err := elf.Open(strings.TrimSuffix(output, ".ll") + ".o")
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	symbols, err := object.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	definitions := make(map[string]bool)
	for _, symbol := range symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC && symbol.Section != elf.SHN_UNDEF {
			definitions[symbol.Name] = true
		}
	}
	if object.Machine != elf.EM_386 {
		t.Fatal("object does not target 386", object.Machine)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	for _, function := range parsed.Funcs {
		if !definitions[resolve(function.Sym)] {
			t.Fatal("the LLVM object omitted an original function", function.Sym)
		}
	}
}
