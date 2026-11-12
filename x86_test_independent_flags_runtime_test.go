package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86TESTIndependentCarryFlags(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	source, declaration := x86TESTIndependentFlagSource("amd64")
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	var prototypes, originals, pairs strings.Builder
	for index, body := range x86TESTIndependentFlagCases("amd64") {
		name, original := fmt.Sprintf("testFlags%d", index), fmt.Sprintf("original%d", index)
		// The test-only SysV wrapper initializes actual physical scratch to
		// diverse values. The translated function has no such numerical input.
		// Only CF/OF are independent of these otherwise unavailable bits.
		actual := x86PackedShiftActualGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\n"+
			"PUSHQ BX\nMOVQ DI,AX\nMOVQ DI,DX\nNOTQ DX\n"+body+"\n"+
			x86TESTIndependentFlagPack+"MOVL DI,CX\nSHLQ $32,CX\nORQ CX,AX\nPOPQ BX\nRET\n")
		if len(actual) == 0 || actual[len(actual)-1] != 0xc3 {
			t.Fatal("incomplete original Go program", body, actual)
		}
		var bytes []string
		for _, b := range actual {
			bytes = append(bytes, fmt.Sprintf("0x%02x", b))
		}
		symbol := original
		if strings.Contains(execution.triple, "apple") {
			symbol = "_" + symbol
		}
		fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
		fmt.Fprintf(&prototypes, "extern uint64_t %s(uint64_t);\n", name)
		prototypes.WriteString(x86OriginalSysVDeclaration("uint64_t", original, "uint64_t"))
		fmt.Fprintf(&pairs, "{%s,%s},\n", name, original)
	}
	main := `#include <stdint.h>
#include <stdio.h>
` + prototypes.String() + originals.String() +
		x86OriginalSysVPointer("uint64_t", "original_program", "uint64_t") + `
typedef uint64_t (*program)(uint64_t);
struct pair { program translated; original_program original; };
static const struct pair pairs[]={
` + pairs.String() + `};
int main(void) {
    const uint64_t seeds[]={0,1,127,128,255,256,32767,32768,65535,65536,
        UINT64_C(0xffffffff),UINT64_C(0x100000000),UINT64_MAX,
        UINT64_C(0x0123456789abcdef),UINT64_C(0x8000000000000000)};
    for(unsigned i=0;i<sizeof(pairs)/sizeof(*pairs);++i) {
        for(unsigned s=0;s<sizeof(seeds)/sizeof(*seeds);++s) {
            uint64_t want=((uint64_t)(uint32_t)seeds[s]<<32)|UINT32_C(0x01010000);
            uint64_t original=pairs[i].original(seeds[s]);
            uint64_t translated=pairs[i].translated(seeds[s]);
            if(original!=want || translated!=want) {
                fprintf(stderr,"TEST=%u seed=%u Go=%llx LLVM=%llx want=%llx\n",
                    i,s,(unsigned long long)original,(unsigned long long)translated,
                    (unsigned long long)want);
                return 1;
            }
        }
    }
    printf("%zu TEST programs x 15 scratch values: CF=OF=0\n",sizeof(pairs)/sizeof(*pairs));
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, pipeline := range []struct{ name, level, ir string }{
				{"backend_O0", "-O0", ir},
				{"IR_O2/backend_O2", "-O2", x86MulDivRoundOptimize(t, ir)},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					out := execution.compileAndRunLLVM(t, "test-independent-flags", pipeline.ir, main, pipeline.level)
					want := fmt.Sprintf("%d TEST programs x 15 scratch values: CF=OF=0\n", len(x86TESTIndependentFlagCases("amd64")))
					if string(out) != want {
						t.Fatalf("unexpected original-Go/LLVM receipt: %q", out)
					}
					t.Log(strings.TrimSpace(string(out)))
				})
			}
		})
	}
}
