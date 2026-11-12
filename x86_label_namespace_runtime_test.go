package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86RegisterShapedLabelsPortableResults(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			result, extent, originalTriple := 8, 12, "x86_64-unknown-linux-gnu"
			if arch == "386" {
				result, extent, originalTriple = 4, 8, "i386-unknown-linux-gnu"
			}
			source := fmt.Sprintf(`TEXT ·Value(SB),4,$0-%d
MOVL input+0(FP),AX
TESTL AX,AX
JEQ x1
INCL AX
JMP t1
x1:
MOVL $17,AX
JMP t1
t1:
JMP reg_AX
reg_AX:
JMP bb_foo
bb_foo:
MOVL AX,result+%d(FP)
RET
`, extent, result)
			x86LEAActualTargetGoObject(t, arch, originalTriple, source)
			const driver = `#include <stdint.h>
#include <stdio.h>
extern uint32_t Value(uint32_t);
int main(void) {
    const uint32_t edges[] = {0,1,2,0x7fffffffU,0x80000000U,0xfffffffeU,0xffffffffU};
    for (unsigned row=0;row<sizeof(edges)/sizeof(edges[0]);++row) {
        uint32_t input=edges[row], expected=input ? input+1 : 17;
        uint32_t actual=Value(input);
        if (actual!=expected) {
            fprintf(stderr,"label row=%u input=%u got=%u want=%u\n",row,input,actual,expected);
            return 1;
        }
    }
    return 0;
}
`
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(input uint32) uint32", arch, execution.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized register-shaped labels lost their source CFG", err)
					}
					for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							execution.compileAndRunLLVM(t, "branch-label-namespace", text, driver, level)
						}
					}
				})
			}
		})
	}
}
