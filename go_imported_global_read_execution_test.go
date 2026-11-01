package plan9asm

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const importedCompareOwner = "example.com/globalconsumer/state"

type importedCompareCase struct {
	bits int
	form string
}

func importedCompareCases(arch string) []importedCompareCase {
	var rows []importedCompareCase
	for _, bits := range []int{8, 16, 32, 64} {
		if arch == "386" && bits == 64 {
			continue
		}
		for _, form := range []string{"memory-register", "register-memory", "memory-immediate"} {
			rows = append(rows, importedCompareCase{bits: bits, form: form})
		}
	}
	return rows
}

// Exercise every scalar comparison width and memory operand position. The
// unaligned address is an actual imported declaration, not emitted DATA or an
// SDK capability. Existing scalar-family tests separately observe every flag.
func importedCompareSource(arch string) (assembly, declarations string) {
	var source, decls strings.Builder
	for index, row := range importedCompareCases(arch) {
		name := fmt.Sprintf("compare%d", index)
		fmt.Fprintf(&decls, "func %s() uint32\n", name)
		address := importedGlobalOperand(importedCompareOwner, "Words", 1)
		args := address + ",AX"
		switch row.form {
		case "register-memory":
			args = "AX," + address
		case "memory-immediate":
			args = address + ",$42"
		}
		op := map[int]string{8: "CMPB", 16: "CMPW", 32: "CMPL", 64: "CMPQ"}[row.bits]
		body := ordinaryGlobalReadAssembly("MOVL $42,AX\n", op+" "+args+"\n")
		source.WriteString(strings.Replace(string(body), "·view", "·"+name, 1))
	}
	return source.String(), decls.String()
}

func importedComparePackage(t *testing.T, arch, declarations string) GoPackage {
	t.Helper()
	owner := importedGlobalPackage(t, importedCompareOwner, arch,
		[]string{"package state\nvar Words [40]byte\n"}, nil)
	pkg := importedGlobalPackage(t, "example.com/globalconsumer", arch,
		[]string{"package globalconsumer\nimport state " + fmt.Sprintf("%q", owner.Path) +
			"\nvar _ = state.Words\n" + declarations},
		map[string]*types.Package{owner.Path: owner.Types})
	pkg.ImportSyntax = map[string][]*ast.File{owner.Path: owner.Syntax}
	pkg.Path = "main"
	return pkg
}

func TestGoModuleImportedGlobalReadCompleteComparisonObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := importedCompareSource(target.arch)
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"public", "owned-context"} {
				t.Run(api, func(t *testing.T) {
					pkg := importedComparePackage(t, target.arch, declarations)
					ir, err := importedGlobalReadRequest(t, pkg, []byte(source), target.arch, target.triple, api, true, nil)
					if err != nil {
						t.Fatal(err)
					}
					if got := strings.Count(ir, "load volatile "); got != len(importedCompareCases(target.arch)) {
						t.Fatalf("imported reads disappeared or multiplied: got %d", got)
					}
					for _, input := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "imported-compare.ll", "imported-compare.o", input)
					}
				})
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixGoModuleImportedGlobalComparisons(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	source, declarations := importedCompareSource("amd64")
	rows := importedCompareCases("amd64")
	// The bytes beyond each narrower view distinguish an exact-width read
	// from a wider load. Reassign between calls to catch folded initializers.
	patterns := []uint64{0, 42 << 8, 43 << 8, 42<<8 | 1<<16, 42<<8 | 1<<24,
		42<<8 | 1<<40, 1 << 63, ^uint64(0), 0x0123456789abcdef}
	var goChecks, cChecks, cDeclarations strings.Builder
	prefix := ""
	if runtime.GOOS == "darwin" {
		prefix = "_"
	}
	for index := range rows {
		fmt.Fprintf(&cDeclarations, "extern uint32_t compare%d(void) __asm__(\"%smain.compare%d\");\n", index, prefix, index)
	}
	for pattern, seed := range patterns {
		fmt.Fprintf(&goChecks, "for i:=range state.Words { state.Words[i]=byte(uint64(%d)>>uint(8*(i%%8))) }\n", seed)
		fmt.Fprintf(&cChecks, "for(unsigned i=0;i<40;++i) words[i]=(uint8_t)(UINT64_C(%d)>>(8*(i%%8)));\n", seed)
		for index, row := range rows {
			// The unaligned 64-bit view wraps around to the seed's first byte.
			value := seed>>8 | seed<<56
			if row.bits < 64 {
				value &= uint64(1)<<uint(row.bits) - 1
			}
			want := 7
			if value == 42 {
				want = 0
			}
			fmt.Fprintf(&goChecks, "if got:=compare%d(); got!=%d { panic(fmt.Sprintf(\"pattern=%d case=%d got=%%d\",got)) }\n", index, want, pattern, index)
			fmt.Fprintf(&cChecks, "if(compare%d()!=%d) { fprintf(stderr,\"pattern=%d case=%d mismatch\\n\");return 1; }\n", index, want, pattern, index)
		}
	}
	want := fmt.Sprintf("%d imported comparisons x %d mutable patterns\n", len(rows), len(patterns))
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "state"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"go.mod":           "module example.com/globalconsumer\n\ngo 1.20\n",
		"state/state.go":   "package state\nvar Words [40]byte\n",
		"original_amd64.s": source,
		"main.go": "package main\nimport (\"fmt\"; state " + fmt.Sprintf("%q", importedCompareOwner) + ")\n" +
			declarations + "func main(){\n" + goChecks.String() + fmt.Sprintf("fmt.Print(%q)\n}\n", want),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, "original")
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	command := exec.Command("go", "build", "-p=2", "-o", executable, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH=amd64", "CGO_ENABLED=0",
		"GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local")
	x86FloatCompareCaptureCommand(t, command)
	if output := execution.run(t, executable); string(output) != want {
		t.Fatalf("original Go imported-storage oracle: %q", output)
	}
	cSource := "#include <stdint.h>\n#include <stdio.h>\n" + cDeclarations.String() +
		fmt.Sprintf("uint8_t words[40] __asm__(\"%s%s.Words\");\n", prefix, importedCompareOwner) +
		"int main(void){\n" + cChecks.String() + fmt.Sprintf("printf(%q);return 0;\n}\n", want)
	for _, api := range []string{"public", "owned-context"} {
		t.Run(api, func(t *testing.T) {
			pkg := importedComparePackage(t, "amd64", declarations)
			ir, err := importedGlobalReadRequest(t, pkg, []byte(source), "amd64", execution.triple, api, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, pipeline := range []struct{ name, ir, level string }{
				{"backend_O0", ir, "-O0"},
				{"IR_O2/backend_O2", x86MulDivRoundOptimize(t, ir), "-O2"},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					output := execution.compileAndRunLLVM(t, "imported-compare", pipeline.ir, cSource, pipeline.level)
					if string(output) != want {
						t.Fatalf("imported mutable comparison execution: %q", output)
					}
					t.Log(strings.TrimSpace(want))
				})
			}
		})
	}
}
