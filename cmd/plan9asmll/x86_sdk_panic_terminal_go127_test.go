//go:build go1.27

package main

import (
	"debug/elf"
	"debug/pe"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCompileOneSelectedSDK386AtomicWholeFile(t *testing.T) {
	for _, target := range []struct{ goos, triple string }{
		{"linux", "i386-unknown-linux-gnu"},
		{"windows", "i686-pc-windows-msvc"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			testCompileOneSelectedSDK386Atomic(t, target.goos, target.triple)
		})
	}
}

func testCompileOneSelectedSDK386Atomic(t *testing.T, goos, triple string) {
	t.Helper()
	setX86SDKNumericalCLIProfile(t, "explicit")
	t.Setenv("GOROOT", runtime.GOROOT())
	t.Chdir(filepath.Join(runtime.GOROOT(), "src", "internal", "runtime", "atomic"))
	packages, environment, err := loadPkgsInEnvironment(goos, "386", []string{"."}, nil, "", true, false, nil)
	if err != nil || len(packages) != 1 || packages[0].PkgPath != "internal/runtime/atomic" {
		t.Fatal("could not load the selected SDK package", err)
	}
	pkg := packages[0]
	input := filepath.Join(pkg.Dir, "atomic_386.s")
	source, err := plan9asm.ReadGoAssemblySourceAtGOROOT(input, pkg.Dir, runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := plan9asm.ParseWithDefines(plan9asm.ArchAMD64, string(source), plan9asm.GoAssemblerDefines(goos, "386"))
	if err != nil || len(parsed.Funcs) != 42 {
		t.Fatal("complete original SDK TEXT inventory changed", err)
	}
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = arm64PrivateCLIContext(t)
	config.x86CallerSelections = captureX86CallerSelectionsInEnvironment(packages, goos+"/386", environment)
	output := filepath.Join(t.TempDir(), "atomic.ll")
	if err := compileOne(pkg, plan9asm.ArchAMD64, goos, "386", triple,
		asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
		t.Fatal(err)
	}
	ir, err := os.ReadFile(output)
	body := string(ir)
	if err != nil || strings.Count(body, "fence seq_cst") != 1 ||
		strings.Count(body, `call void @"internal/runtime/atomic.panicUnaligned"()`) != 5 ||
		strings.Count(body, "unreachable") != 5 || !strings.Contains(body, "noreturn") {
		t.Fatal("the original complete member lost its physical fence or exact terminal calls", err)
	}
	definitions := sdk386AtomicObjectFunctions(t, goos, strings.TrimSuffix(output, ".ll")+".o")
	resolve := resolveSymFunc(pkg.PkgPath)
	for _, function := range parsed.Funcs {
		if !definitions[resolve(function.Sym)] {
			t.Fatal("the LLVM object omitted an original function", function.Sym)
		}
	}
}

func sdk386AtomicObjectFunctions(t *testing.T, goos, path string) map[string]bool {
	t.Helper()
	definitions := make(map[string]bool)
	if goos == "windows" {
		object, err := pe.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer object.Close()
		if object.Machine != pe.IMAGE_FILE_MACHINE_I386 {
			t.Fatal("object does not target 386", object.Machine)
		}
		for _, symbol := range object.Symbols {
			section := int(symbol.SectionNumber)
			if section > 0 && section <= len(object.Sections) &&
				object.Sections[section-1].Characteristics&pe.IMAGE_SCN_CNT_CODE != 0 {
				definitions[strings.TrimPrefix(symbol.Name, "_")] = true
			}
		}
		panicCalls := 0
		for _, section := range object.Sections {
			if section.Characteristics&pe.IMAGE_SCN_CNT_CODE == 0 {
				continue
			}
			for _, relocation := range section.Relocs {
				if uint64(relocation.SymbolTableIndex) >= uint64(len(object.COFFSymbols)) {
					t.Fatal("invalid object relocation symbol index", relocation)
				}
				symbol := object.COFFSymbols[relocation.SymbolTableIndex]
				name, err := symbol.FullName(object.StringTable)
				if err != nil {
					t.Fatal(err)
				}
				if strings.TrimPrefix(name, "_") == "internal/runtime/atomic.panicUnaligned" {
					const i386Relative32 = 0x0014
					if relocation.Type != i386Relative32 || symbol.SectionNumber != 0 {
						t.Fatal("panic CALL lost its external COFF relocation", relocation)
					}
					panicCalls++
				}
			}
		}
		if panicCalls != 5 {
			t.Fatal("the complete object lost original panic CALLs", panicCalls)
		}
		return definitions
	}
	object, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	symbols, err := object.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	for _, symbol := range symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC && symbol.Section != elf.SHN_UNDEF {
			definitions[symbol.Name] = true
		}
	}
	if object.Machine != elf.EM_386 {
		t.Fatal("object does not target 386", object.Machine)
	}
	return definitions
}

func TestCompileOneSelectedSDK386ABI0TailPreservesGlobalEntry(t *testing.T) {
	testCompileOneSelectedSDKABI0Tail(t, "386", plan9asm.ArchAMD64, "i386-unknown-linux-gnu", elf.EM_386)
}

func TestCompileOneSelectedSDKARM64ABI0TailPreservesGlobalEntry(t *testing.T) {
	testCompileOneSelectedSDKABI0Tail(t, "arm64", plan9asm.ArchARM64, "aarch64-unknown-linux-gnu", elf.EM_AARCH64)
}

func TestCompileOneSelectedSDKARMABI0TailPreservesGlobalEntry(t *testing.T) {
	testCompileOneSelectedSDKABI0Tail(t, "arm", plan9asm.ArchARM, "armv7-unknown-linux-gnueabihf", elf.EM_ARM)
}

func testCompileOneSelectedSDKABI0Tail(t *testing.T, goarch string, arch plan9asm.Arch, triple string, machine elf.Machine) {
	t.Helper()
	const packagePath = "crypto/internal/fips140/bigmod"
	setX86SDKNumericalCLIProfile(t, "explicit")
	t.Setenv("GOROOT", runtime.GOROOT())
	t.Chdir(filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(packagePath)))
	packages, environment, err := loadPkgsInEnvironment("linux", goarch, []string{"."}, nil, "", true, false, nil)
	if err != nil || len(packages) != 1 || packages[0].PkgPath != packagePath {
		t.Fatal("could not load the original SDK package", err)
	}
	pkg := packages[0]
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = arm64PrivateCLIContext(t)
	config.x86CallerSelections = captureX86CallerSelectionsInEnvironment(packages, "linux/"+goarch, environment)
	output := filepath.Join(t.TempDir(), "nat.ll")
	task := asmTask{PkgPath: pkg.PkgPath, AsmFile: filepath.Join(pkg.Dir, "nat_"+goarch+".s"), OutLL: output}
	if err := compileOne(pkg, arch, "linux", goarch, triple, task, false, config); err != nil {
		t.Fatal(err)
	}
	ir, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ir), " = alloca ") {
		t.Fatal("typed wrappers retained virtual-register or logical frame spills")
	}
	object, err := elf.Open(strings.TrimSuffix(output, ".ll") + ".o")
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	if object.Machine != machine {
		t.Fatalf("expected %v native object, got %v", machine, object.Machine)
	}
	symbols, err := object.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	definitions := make(map[string]bool)
	for _, symbol := range symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC && elf.ST_BIND(symbol.Info) == elf.STB_GLOBAL &&
			symbol.Section != elf.SHN_UNDEF && symbol.Size != 0 {
			definitions[symbol.Name] = true
		}
	}
	for _, name := range []string{"addMulVVWx", packagePath + ".addMulVVW1024", packagePath + ".addMulVVW1536", packagePath + ".addMulVVW2048"} {
		if !definitions[name] {
			t.Errorf("the LLVM object omitted global function %s", name)
		}
	}
}
