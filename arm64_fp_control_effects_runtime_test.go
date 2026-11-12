package plan9asm

import (
	"fmt"
	"go/types"
	"runtime"
	"strings"
	"testing"
)

// Retain all three translation entry points and the separate typed-Go
// consumer. Public TranslateModule uses the global LLVM context; its module
// is disposed immediately, while the shared helper owns its private context.
func arm64FPControlIRs(t *testing.T, source, declarations, triple string) []string {
	t.Helper()
	irs := arm64CompareMatrixIRs(t, source, declarations, triple)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "compare", declarations)
	sizes := types.SizesFor("gc", "arm64")
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
	if err != nil {
		t.Fatal(err)
	}
	module, err := TranslateModule(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve})
	if err != nil {
		t.Fatal(err)
	}
	irs = append(irs, module.String())
	module.Dispose()
	return irs
}

// Go asm7 case35/36 and Arm's MRS/MSR register encodings. The instruction
// under test transfers FPCR/FPSR, not NZCV; the preceding integer comparison
// must remain observable by CSET. Both original named and WORD forms execute.
func arm64FPControlFlagFixture() (source, declarations, original, driver string) {
	var assembly, goDecl, goMain, cMain strings.Builder
	goDecl.WriteString("package compare\n")
	goMain.WriteString("package main\nimport \"fmt\"\n")
	cMain.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	var names []string
	for _, register := range []struct {
		name     string
		encoding uint32
		saved    int
	}{
		{"FPCR", 0x5a20, 10},
		{"FPSR", 0x5a21, 11},
	} {
		for _, read := range []bool{true, false} {
			for _, raw := range []bool{false, true} {
				name := fmt.Sprintf("compareFPControl%d", len(names))
				names = append(names, name)
				fmt.Fprintf(&goDecl, "func %s(*uint64, *uint64)\n", name)
				fmt.Fprintf(&goMain, "func %s(*uint64, *uint64)\n", name)
				fmt.Fprintf(&cMain, "extern void %s(uint64_t*, uint64_t*);\n", name)
				fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-16\n", name)
				assembly.WriteString(`MOVD in+0(FP),R0
MOVD out+8(FP),R1
MRS FPCR,R10
MRS FPSR,R11
MOVD (R0),R2
CMP R2,R2
`)
				instruction := fmt.Sprintf("MSR R%d,%s", register.saved, register.name)
				word := uint32(0xd5100000) | register.encoding<<5 | uint32(register.saved)
				if read {
					instruction = fmt.Sprintf("MRS %s,R3", register.name)
					word = 0xd5300000 | register.encoding<<5 | 3
				}
				if raw {
					instruction = fmt.Sprintf("WORD $%#08x", word)
				}
				fmt.Fprintln(&assembly, instruction)
				assembly.WriteString(`CSET EQ,R4
MOVD R4,(R1)
MSR R10,FPCR
MSR R11,FPSR
RET
`)
			}
		}
	}
	goMain.WriteString("func main() {\n")
	cMain.WriteString("int main(void) {\n")
	for _, name := range names {
		fmt.Fprintf(&goMain, `{
    input, output := uint64(0x8000000000000001), uint64(0)
    %s(&input, &output)
    if output != 1 { panic(fmt.Sprintf("%s flags: %%x", output)) }
}
`, name, name)
		fmt.Fprintf(&cMain, `{
    uint64_t input = UINT64_C(0x8000000000000001), output = 0;
    %s(&input, &output);
    if (output != 1) {
        fprintf(stderr, "%s flags: %%llx\n", (unsigned long long)output);
        return 1;
    }
}
`, name, name)
	}
	goMain.WriteString("fmt.Println(\"ARM64_COMPARE_ORIGINAL_PASS FPCR/FPSR preserve NZCV 8\")\n}\n")
	cMain.WriteString("return 0;\n}\n")
	return assembly.String(), goDecl.String(), goMain.String(), cMain.String()
}

func arm64FPControlFlagsRuntime(t *testing.T, triple, goos string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	source, declarations, original, driver := arm64FPControlFlagFixture()
	arm64ScalarCompareActualGo(t, source, original, goos, runner)
	irs := arm64FPControlIRs(t, source, declarations, triple)
	for api, ir := range irs {
		for _, variant := range []struct{ name, ir string }{
			{"none", ir}, {"O2", armFloatEffectOptimizedIR(t, ir)},
		} {
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("api%d/IR_%s/backend_O%d", api, variant.name, level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler,
						"fp_control_flags", triple, variant.ir, driver, runner, level)
				})
			}
		}
	}
}

func TestARM64FPControlFlagsNativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("Darwin counterpart; the required Linux/QEMU owner executes the same original Go oracle")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	arm64FPControlFlagsRuntime(t, "aarch64-apple-darwin", "darwin", []string{clang}, nil)
}
