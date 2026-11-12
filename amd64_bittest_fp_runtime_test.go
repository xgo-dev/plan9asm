package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86BitTestFPPartialWriteback(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, prototypes, checks, goChecks strings.Builder
	declarations.WriteString("package oracle\n")
	count := 0
	for _, op := range x86BitTestOracleNames("amd64") {
		width := map[byte]int{'W': 2, 'L': 4, 'Q': 8}[op[len(op)-1]]
		for offset := 0; offset+width <= 8; offset++ {
			name := fmt.Sprintf("Partial%d", count)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\n%s $-1,x+%d(FP)\nMOVQ x+0(FP),AX\nMOVQ AX,ret+8(FP)\nRET\n", name, op, offset)
			fmt.Fprintf(&declarations, "func %s(x uint64) uint64\n", name)
			fmt.Fprintf(&prototypes, "extern uint64_t %s(uint64_t);\n", name)
			mask := uint64(1) << uint(8*(offset+width)-1)
			cWant, goWant := "x", "x"
			switch op[:len(op)-1] {
			case "BTC":
				cWant, goWant = fmt.Sprintf("(x^UINT64_C(0x%x))", mask), fmt.Sprintf("x^uint64(0x%x)", mask)
			case "BTR":
				cWant, goWant = fmt.Sprintf("(x&~UINT64_C(0x%x))", mask), fmt.Sprintf("x&^uint64(0x%x)", mask)
			case "BTS":
				cWant, goWant = fmt.Sprintf("(x|UINT64_C(0x%x))", mask), fmt.Sprintf("x|uint64(0x%x)", mask)
			}
			fmt.Fprintf(&checks, "if(%s(x)!=%s) {fprintf(stderr,\"FP partial %d mismatch\\n\");return 1;}\n", name, cWant, count)
			fmt.Fprintf(&goChecks, "if got,want:=%s(x),%s;got!=want {t.Fatalf(\"FP partial %d got=%%x want=%%x\",got,want)}\n", name, goWant, count)
			count++
		}
	}
	if count != 52 {
		t.Fatalf("partial FP byte-span denominator changed: %d", count)
	}
	const patterns = "0,1,0x8000000000000000,0xffffffffffffffff,0x55aa0123cdef9876,0x7ff8000000000001"
	original := "package oracle\nimport \"testing\"\nfunc TestOriginal(t *testing.T) { for _,x:=range []uint64{" + patterns + "} {\n" + goChecks.String() + "}}\n"
	x86WordMultiplyRunOriginalGo(t, execution, declarations.String(), source.String(), original)
	main := "#include <stdint.h>\n#include <stdio.h>\n" + prototypes.String() +
		"int main(void) {const uint64_t patterns[]={" + patterns + "};\nfor(unsigned i=0;i<6;++i) {uint64_t x=patterns[i];\n" + checks.String() +
		"}\nputs(\"52 partial FP programs x 6 complete values\");return 0;}\n"
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), strings.TrimPrefix(declarations.String(), "package oracle\n"), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, pipeline := range []struct{ level, ir string }{{"-O0", ir}, {"-O2", x86MulDivRoundOptimize(t, ir)}} {
				output := execution.compileAndRunLLVM(t, "bit-test-fp-partial", pipeline.ir, main, pipeline.level)
				if string(output) != "52 partial FP programs x 6 complete values\n" {
					t.Fatalf("missing complete original/LLVM FP value oracle: %s", output)
				}
			}
		})
	}
}
