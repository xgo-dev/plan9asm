package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86Mode32PrivateFlagsCancellationPortableValues(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	var source, declarations, driver strings.Builder
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	var checks strings.Builder
	index := 0
	for _, carrier := range []struct {
		width, typ, ctyp string
		bytes            int
		masks            []uint32
	}{
		{"W", "uint16", "uint16_t", 2, []uint32{0, 1, 0x40, 0x400, 0x8d5}},
		{"L", "uint32", "uint32_t", 4, []uint32{0, 1, 0x400, 0x200000, 0x200cd5}},
	} {
		for _, register := range []string{"AX", "BX", "CX", "DX", "BP", "SI", "DI"} {
			for _, mask := range carrier.masks {
				name := fmt.Sprintf("cancelFlags%d", index)
				index++
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%sMOV%s %s,ret+0(FP)\nRET\n",
					name, carrier.bytes, x86StackFlagsCorrelationBody(carrier.width, register, mask), carrier.width, register)
				fmt.Fprintf(&declarations, "func %s() %s\n", name, carrier.typ)
				fmt.Fprintf(&driver, "extern %s %s(void);\n", carrier.ctyp, name)
				fmt.Fprintf(&checks, "if (%s()!=UINT32_C(%d)) {fprintf(stderr,\"%s\\n\"); return 1;}\n", name, mask, name)
			}
		}
	}
	fmt.Fprintf(&driver, "int main(void) {for(unsigned row=0;row<257;++row) {%s} return 0;}\n", checks.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "386", execution.triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete portable private FLAGS source", err)
			}
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					execution.compileAndRunLLVM(t, "private-flags-values", text, driver.String(), level)
				}
			}
		})
	}
}
