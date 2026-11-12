//go:build unix && go1.27

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalReadonlyData(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	operations := []string{
		"MOVOU literal<>(SB),X0\nPADDQ 16(SP),X0",
		"PADDQ literal<>(SB),X0",
		"MOVQ literal<>+8(SB),DX\nMOVQ DX,48(SP)\nMOVOU 48(SP),X0",
		"MOVOU literal<>+16(SB),X0\nPADDQ 16(SP),X0",
		"MOVQ literal<>+3(SB),DX\nMOVQ DX,48(SP)\nMOVOU 48(SP),X0",
		"MOVB literal<>+1(SB),DX\nMOVQ DX,48(SP)\nMOVOU 48(SP),X0",
		"MOVW literal<>+1(SB),DX\nMOVQ DX,48(SP)\nMOVOU 48(SP),X0",
		"MOVL literal<>+1(SB),DX\nMOVQ DX,48(SP)\nMOVOU 48(SP),X0",
	}
	var assembly, declarations, calls, cDeclarations, cCalls strings.Builder
	assembly.WriteString(fixedLocalLiteralData)
	prefix := ""
	if runtime.GOOS == "darwin" {
		prefix = "_"
	}
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		body, _, _ := x86PrivateAlignedFrameAuditFixture(t, operation)
		assembly.WriteString(strings.Replace(body, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(a,b,c,d uint64) uint64\n", name)
		fmt.Fprintf(&calls, `
		if got := %s(a, b, c, d); got != expected(%d, a, c) {
			t.Fatalf("case %d seed=%%d got=%%x", seed, got)
		}
`, name, index, index)
		fmt.Fprintf(&cDeclarations, "extern uint64_t value%d(uint64_t,uint64_t,uint64_t,uint64_t) __asm__(\"%sexample.invalid/framefixture.%s\");\n", index, prefix, name)
		fmt.Fprintf(&cCalls, `
		if (value%d(a, b, c, d) != expected(%d, a, c)) {
			fprintf(stderr, "case %d seed=%%u\n", seed);
			return 1;
		}
`, index, index, index)
	}
	goOracle := `package framefixture
import "testing"
func expected(op int, a, c uint64) uint64 {
	const lo = uint64(0x0102030405060708)
	const hi = uint64(0x1112131415161718)
	switch op {
	case 0:
		return lo+a
	case 1:
		return lo+c
	case 2:
		return hi
	case 3:
		return a
	case 4:
		return lo>>24 | (hi&0xffffff)<<40
	case 5:
		return c&^255 | 7
	case 6:
		return c&^65535 | 0x0607
	case 7:
		return 0x04050607
	}
	panic("unknown case")
}
func TestOriginal(t *testing.T) {
	for seed := uint64(0); seed < 256; seed++ {
		a := seed*0x102030405060708
		b, c, d := ^a, a^0xfedcba9876543210, a+0x1234
` + calls.String() + `
	}
}
`
	cOracle := `#include <stdint.h>
#include <stdio.h>
` + cDeclarations.String() + `
static uint64_t expected(unsigned op, uint64_t a, uint64_t c) {
	const uint64_t lo = UINT64_C(0x0102030405060708);
	const uint64_t hi = UINT64_C(0x1112131415161718);
	switch (op) {
	case 0:
		return lo+a;
	case 1:
		return lo+c;
	case 2:
		return hi;
	case 3:
		return a;
	case 4:
		return lo>>24 | (hi&0xffffff)<<40;
	case 5:
		return (c&~UINT64_C(255)) | 7;
	case 6:
		return (c&~UINT64_C(65535)) | 0x0607;
	case 7:
		return 0x04050607;
	}
	return 0;
}
int main(void) {
	for (unsigned seed=0; seed<256; seed++) {
		uint64_t a = seed*UINT64_C(0x102030405060708);
		uint64_t b = ~a, c = a^UINT64_C(0xfedcba9876543210), d = a+0x1234;
` + cCalls.String() + `
	}
	return 0;
}
`
	pkg, request, _, options := x86CMOVFixedLocalFixture(t, assembly.String(), declarations.String(), runtime.GOOS+"/amd64", execution.triple)
	fixedLocalPackedRunOriginal(t, execution, assembly.String(), declarations.String(), goOracle, true)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
		if err != nil {
			t.Fatal(err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			input := ir
			if level == "-O2" {
				input = x86MulDivRoundOptimize(t, ir)
			}
			execution.compileAndRunLLVM(t, "readonly-frame", input, cOracle, level)
		}
	})
	t.Log("2048 independent numeric outcomes: original Go and three LLVM APIs at O0/O2; includes sparse zero tails and unaligned/partial scalar reads")
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		t.Log("Rosetta legacy SSE diagnostic, not native Linux or AVX/AVX512 execution")
	}
}
