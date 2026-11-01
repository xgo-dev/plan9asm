package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64NamedPCFamilyRuntime(t *testing.T, triple string) (string, string) {
	t.Helper()
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	conditions := map[string]string{
		"B": "1", "JMP": "1", "BEQ": "a == b", "BNE": "a != b",
		"BLO": "a < b", "BCC": "a < b", "BHS": "a >= b", "BCS": "a >= b",
		"BHI": "a > b", "BLS": "a <= b", "BLT": "(int64_t)a < (int64_t)b",
		"BGE": "(int64_t)a >= (int64_t)b", "BLE": "(int64_t)a <= (int64_t)b",
		"BGT": "(int64_t)a > (int64_t)b", "BMI": "(a - b) >> 63",
		"BPL": "!((a - b) >> 63)", "BVS": "((a ^ b) & (a ^ (a - b))) >> 63",
		"BVC": "!(((a ^ b) & (a ^ (a - b))) >> 63)",
		"CBZ": "a == 0", "CBNZ": "a != 0", "CBZW": "(uint32_t)a == 0", "CBNZW": "(uint32_t)a != 0",
	}
	for _, op := range arm64NamedPCBranchOps {
		if op == "BL" || op == "CALL" {
			continue
		}
		bits := []int{3}
		if op == "TBZ" || op == "TBNZ" {
			bits = []int{0, 31, 32, 63}
		}
		for _, bit := range bits {
			name := fmt.Sprintf("named_%s_%d", strings.ToLower(op), bit)
			instruction := arm64NamedPCBranchInstruction(op, "3(PC)")
			condition := conditions[op]
			if op == "TBZ" || op == "TBNZ" {
				instruction = fmt.Sprintf("%s $%d, R0, 3(PC)", op, bit)
				condition = fmt.Sprintf("((a >> %d) & 1) %s 0", bit, map[string]string{"TBZ": "==", "TBNZ": "!="}[op])
			}
			fmt.Fprintf(&source, "TEXT %s(SB),$0-24\nMOVD a+0(FP), R0\nMOVD b+8(FP), R1\nMOVD $0, R2\nCMP R1, R0\n%s\nADD $1, R2\nADD $2, R2\nMOVD R2, ret+16(FP)\nRET\n", name, instruction)
			sigs[name] = arm64NamedPCBranchSig(name)
			fmt.Fprintf(&declarations, "extern uint64_t %s(uint64_t, uint64_t);\n", name)
			fmt.Fprintf(&checks, "    if (%s(a, b) != ((%s) ? 0 : 3)) { fprintf(stderr, \"%s a=%%llx b=%%llx failed\\n\", (unsigned long long)a, (unsigned long long)b); return 1; }\n", name, condition, name)
		}
	}
	source.WriteString(`TEXT named_backward(SB),$0-24
	MOVD a+0(FP), R0
	MOVD $0, R2
again:
	ADD $1, R2
	SUBS $1, R0
	BNE -2(PC)
	MOVD R2, ret+16(FP)
	RET
`)
	sigs["named_backward"] = arm64NamedPCBranchSig("named_backward")
	for _, op := range []string{"BL", "CALL"} {
		name := "named_" + strings.ToLower(op)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-24\nMOVD a+0(FP), R0\n%s 4(PC)\n%s_resume:\nADD $2, R0\nMOVD R0, ret+16(FP)\nRET\nADD $5, R0\nB %s_resume\n", name, op, name, name)
		sigs[name] = arm64NamedPCBranchSig(name)
		fmt.Fprintf(&declarations, "extern uint64_t %s(uint64_t, uint64_t);\n", name)
		fmt.Fprintf(&checks, "    if (%s(a, b) != a + 7) { fprintf(stderr, \"%s local continuation failed\\n\"); return 2; }\n", name, name)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := `#include <stdint.h>
#include <stdio.h>
` + declarations.String() + `extern uint64_t named_backward(uint64_t, uint64_t);
int main(void) {
	const uint64_t values[] = {0, 1, UINT64_MAX, UINT64_C(0x80000000), UINT64_C(0x100000000),
		UINT64_C(0x8000000000000000), UINT64_C(0x7fffffffffffffff), UINT64_C(0x0123456789abcdef)};
	for (unsigned i = 0; i < sizeof values / sizeof values[0]; i++) {
		for (unsigned j = 0; j < sizeof values / sizeof values[0]; j++) {
			uint64_t a = values[i], b = values[j];
` + checks.String() + `		}
	}
	for (uint64_t n = 1; n < 10; n++) if (named_backward(n, 0) != n) return 3;
	return 0;
}
`
	return ir, main
}

func TestCrossLinuxRuntimeMatrixARM64NamedPCBranchFamily(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	ir, main := arm64NamedPCFamilyRuntime(t, triple)
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "named_pc_family", triple, ir, main, runner)
}
