package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86ScalarSqrtNativeReadSurvivesOptimization(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		word, move := goWordSize(target.arch), "MOVQ"
		if target.arch == "386" {
			move = "MOVL"
		}
		for _, row := range []struct {
			operation string
			bits      int
		}{
			{"SQRTSS (AX),X1", 32},
			{"SQRTSD (AX),X1", 64},
			{"VSQRTSS (AX),X0,X1", 32},
			{"VSQRTSD (AX),X0,X1", 64},
		} {
			for _, address := range []struct{ name, input string }{
				{"null", "MOVL $0,AX"},
				{"runtime", move + " p+0(FP),AX"},
			} {
				t.Run(target.triple+"/"+row.operation+"/"+address.name, func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s\nPXOR X0,X0\nPXOR X1,X1\n%s\nRET\n",
						word, address.input, row.operation)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p uintptr)", target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("complete numerical source did not reach its native scalar opcode", err)
							}
							x86RequireNumericNativeSourceContext(t, source, "func Value(p uintptr)", target.arch)
							for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
								body := x86StringMemoryFunction(t, text, "Value")
								// Even a dead numerical result must retain the source
								// access and fault, without a pointer-validity assumption.
								if x86FMA3PortableVolatileBytes(t, body) != row.bits/8 ||
									!strings.Contains(body, "asm sideeffect") || strings.Contains(body, "dereferenceable") {
									t.Errorf("native m%d read/fault was lost or given invented backing:\n%s", row.bits, body)
									continue
								}
								x86PackedStringCompileObject(t, llc, target.triple, text, "-O2")
							}
						})
					}
				})
			}
		}
	}
}
