package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// This executes the pure integer lowering on the actual host. Native x86
// opcode/FLAGS execution remains owned by the original conformance suite.
func TestX86AccumulatorSignExtendPortableValues(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc/clang required")
	}
	var source, declarations, prototypes, rows strings.Builder
	for _, row := range x86AccumulatorSignExtendOracle {
		for _, raw := range []bool{false, true} {
			name := fmt.Sprintf("Value%s%t", row.op, raw)
			fmt.Fprintf(&declarations, "func %s(value, old uint64) uint64\n", name)
			fmt.Fprintf(&prototypes, "extern uint64_t %s(uint64_t, uint64_t);\n", name)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVQ value+0(FP),AX\nMOVQ old+8(FP),DX\n%s\nMOVQ %s,ret+16(FP)\nRET\n",
				name, x86AccumulatorSignExtendSource(t, row.op, "amd64", raw), row.destination)
			high := 0
			if row.destination == DX {
				high = 1
			}
			fmt.Fprintf(&rows, "{%s, %q, %d, %d, %d},\n", name, name, row.read*8, row.write*8, high)
		}
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	main := "#include <stdint.h>\n#include <stdio.h>\n" + prototypes.String() + `
static uint64_t reference(uint64_t value, uint64_t old,
                          int source, int result, int high) {
    uint64_t inputMask = source == 64 ? UINT64_MAX : (UINT64_C(1) << source) - 1;
    uint64_t outputMask = result == 64 ? UINT64_MAX : (UINT64_C(1) << result) - 1;
    int negative = (value & (UINT64_C(1) << (source - 1))) != 0;
    uint64_t low = high ? (negative ? UINT64_MAX : 0) :
        (value & inputMask) | (negative ? ~inputMask : 0);
    if (result == 32) return low & UINT32_MAX;
    return ((high ? old : value) & ~outputMask) | (low & outputMask);
}
static const struct {
    uint64_t (*run)(uint64_t, uint64_t);
    const char *name;
    int source, result, high;
} cases[] = {
` + rows.String() + `};
int main(void) {
    const uint64_t old[] = {0, UINT64_MAX, UINT64_C(0x1122334455667788)};
    for (unsigned row = 0; row < sizeof(cases) / sizeof(cases[0]); row++) {
        for (unsigned bit = 0; bit < 64; bit++) {
            for (unsigned inverted = 0; inverted < 2; inverted++) {
                uint64_t value = UINT64_C(1) << bit;
                if (inverted) value = ~value;
                for (unsigned seed = 0; seed < sizeof(old) / sizeof(old[0]); seed++) {
                    uint64_t want = reference(value, old[seed], cases[row].source,
                                              cases[row].result, cases[row].high);
                    uint64_t got = cases[row].run(value, old[seed]);
                    if (got != want) {
                        fprintf(stderr, "%s bit=%u inverted=%u seed=%u got=%llx want=%llx\n",
                                cases[row].name, bit, inverted, seed,
                                (unsigned long long)got, (unsigned long long)want);
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil {
				t.Fatal("initialized complete integer source rejected", err)
			}
			for index, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					compileAndRunRuntimeTestForTarget(t, llc, clang,
						fmt.Sprintf("accumulator-%s-ir%d-%s", api, index, level[1:]), triple, text, main, nil)
				}
			}
		})
	}
}
