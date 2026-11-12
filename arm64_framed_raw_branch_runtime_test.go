package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64FramedRawBranchFixture() (string, string) {
	var source, declarations strings.Builder
	for _, branch := range arm64FramedRawBranches() {
		name := "raw" + branch.name
		source.WriteString(arm64FramedRawBranchSource(name, fmt.Sprintf("WORD $%#08x", branch.word)))
		fmt.Fprintf(&declarations, "func %s(*uint64,*uint64)\n", name)
	}
	return source.String(), declarations.String()
}

// This is independent of NZCV lowering: these boolean identities follow a
// native subtraction by zero. CBZ's W truncation and TBZ's high bits are separate.
func arm64FramedRawBranchCondition(branch arm64FramedRawBranchCase) string {
	conditions := map[string]string{
		"B": "true", "BEQ": "input == 0", "BNE": "input != 0",
		"BCS": "true", "BHS": "true", "BCC": "false", "BLO": "false",
		"BMI": "int64(input) < 0", "BPL": "int64(input) >= 0",
		"BVS": "false", "BVC": "true", "BHI": "input != 0", "BLS": "input == 0",
		"BGE": "int64(input) >= 0", "BLT": "int64(input) < 0",
		"BGT": "int64(input) > 0", "BLE": "int64(input) <= 0",
		"CBZ": "input == 0", "CBNZ": "input != 0",
		"CBZW": "uint32(input) == 0", "CBNZW": "uint32(input) != 0",
	}
	if branch.op == "TBZ" || branch.op == "TBNZ" {
		comparison := "=="
		if branch.op == "TBNZ" {
			comparison = "!="
		}
		return fmt.Sprintf("((input >> %d) & 1) %s 0", branch.bit, comparison)
	}
	return conditions[branch.op]
}

func arm64FramedRawBranchGoCaller(name string) string {
	return fmt.Sprintf(`
TEXT ·check_%s(SB),4,$80-24
MOVD input+0(FP),R0
MOVD R0,8(RSP)
MOVD output+8(FP),R0
MOVD R0,16(RSP)
MOVD $0x123456789abcdef0,R12
MOVD R12,24(RSP)
MOVD R12,32(RSP)
MOVD g,R12
MOVD R12,40(RSP)
WORD $0xaa1203ec // read x18, without changing the reserved register.
MOVD R12,48(RSP)
MOVD 0(RSP),R12
MOVD R12,56(RSP)
MOVD RSP,R12
MOVD R12,64(RSP)
CALL ·%s(SB)
MOVD $0x123456789abcdef0,R12
MOVD 24(RSP),R13
CMP R12,R13
BNE bad_%s
MOVD 32(RSP),R13
CMP R12,R13
BNE bad_%s
MOVD 40(RSP),R12
CMP g,R12
BNE bad_%s
MOVD 48(RSP),R13
WORD $0xaa1203ec
CMP R12,R13
BNE bad_%s
MOVD 0(RSP),R12
MOVD 56(RSP),R13
CMP R12,R13
BNE bad_%s
MOVD RSP,R12
MOVD 64(RSP),R13
CMP R12,R13
BNE bad_%s
MOVD $1,R0
MOVD R0,ret+16(FP)
RET
bad_%s:
MOVD $0,R0
MOVD R0,ret+16(FP)
RET
`, name, name, name, name, name, name, name, name, name)
}

func arm64FramedRawBranchPrograms() (source, goProgram, cProgram string) {
	source, declarations := arm64FramedRawBranchFixture()
	var goMain, cMain strings.Builder
	goMain.WriteString("package main\nimport \"fmt\"\n" + declarations)
	cMain.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for _, branch := range arm64FramedRawBranches() {
		name := "raw" + branch.name
		fmt.Fprintf(&goMain, "func check_%s(*uint64,*uint64) uint64\n", name)
		source += arm64FramedRawBranchGoCaller(name)
		symbol := "largeframe." + name
		if runtime.GOOS == "darwin" {
			symbol = "_" + symbol
		}
		fmt.Fprintf(&cMain, "extern void %s(uint64_t*,uint64_t*) __asm__(%q);\n", name, symbol)
	}
	goMain.WriteString(`
func main() {
    inputs := []uint64{0, 1, 0xffffffff, 0x100000000, 0x80000000,
        0x8000000000000000, 0x7fffffffffffffff, ^uint64(0)}
    for _, input := range inputs {
`)
	cMain.WriteString(`
int main(void) {
    const uint64_t inputs[] = {0, 1, UINT64_C(0xffffffff), UINT64_C(0x100000000),
        UINT64_C(0x80000000), UINT64_C(0x8000000000000000),
        UINT64_C(0x7fffffffffffffff), UINT64_MAX};
    for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        uint64_t input = inputs[i];
`)
	for _, branch := range arm64FramedRawBranches() {
		name := "raw" + branch.name
		condition := arm64FramedRawBranchCondition(branch)
		fmt.Fprintf(&goMain, `
        {
            want := uint64(7)
            if %s {
                want = 5
            }
            data := [3]uint64{0x1234, input, 0x5678}
            result := [3]uint64{0x9abc, 0, 0xdef0}
            if check_%s(&data[1], &result[1]) != 1 || result[1] != want ||
                    data != [3]uint64{0x1234, input, 0x5678} ||
                    result[0] != 0x9abc || result[2] != 0xdef0 {
                panic(fmt.Sprintf("%s input=%%x result=%%x want=%%x", input, result[1], want))
            }
        }
`, condition, name, name)
		condition = strings.NewReplacer("true", "1", "false", "0", "int64(input)", "(int64_t)input", "uint32(input)", "(uint32_t)input").Replace(condition)
		fmt.Fprintf(&cMain, `
        {
            uint64_t data[] = {0x1234, input, 0x5678};
            uint64_t result[] = {0x9abc, 0, 0xdef0};
            uint64_t want = (%s) ? 5 : 7;
            %s(&data[1], &result[1]);
            if (result[1] != want || data[0] != 0x1234 || data[1] != input ||
                    data[2] != 0x5678 || result[0] != 0x9abc || result[2] != 0xdef0) {
                fprintf(stderr, "%s input=%%llx result=%%llx want=%%llx\n",
                    (unsigned long long)input, (unsigned long long)result[1], (unsigned long long)want);
                return 1;
            }
        }
`, condition, name, name)
	}
	goMain.WriteString("    }\n}\n")
	cMain.WriteString("    }\n    return 0;\n}\n")
	return source, goMain.String(), cMain.String()
}

func TestARM64FramedRawBranchAPIsAndLLVM22Objects(t *testing.T) {
	source, declarations := arm64FramedRawBranchFixture()
	pkg := mustGoPackage(t, "largeframe", "package largeframe\n"+declarations)
	arm64LargeFrameCheckAPIs(t, source, pkg, nil, false, true)
	t.Logf("%d raw branch forms through three APIs and five target objects", len(arm64FramedRawBranches()))
}

func TestCrossLinuxRuntimeMatrixARM64FramedRawBranchFamily(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source, goMain, cMain := arm64FramedRawBranchPrograms()
	runARM64LocalRegisterGoOracle(t, source, goMain, len(runner) != 0, "1.20")
	source, declarations := arm64FramedRawBranchFixture()
	pkg := mustGoPackage(t, "largeframe", "package largeframe\n"+declarations)
	translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple, ResolveSym: testResolveSym(pkg.Path),
	})
	if err != nil {
		t.Fatal(err)
	}
	ir := translated.Module.String()
	translated.Module.Dispose()
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "framed_raw_branch", triple, ir, cMain, runner)
	t.Logf("%d original Go/LLVM cases; complete input/output and native Go g/OS18/LR/SP/stack canaries", len(arm64FramedRawBranches())*8)
}
