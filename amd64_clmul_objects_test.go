package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86CLMULThreeAPIFiveTargetResultObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			for _, vector := range []bool{false, true} {
				if target.arch == "386" && vector {
					continue // Source mode, independently checked against Go.
				}
				for _, selector := range []int{0, 1, 16, 17} {
					var body strings.Builder
					body.WriteString("MOVL a+0(FP),AX\nMOVL b+4(FP),BX\n")
					for half := 0; half < 2; half++ {
						fmt.Fprintf(&body, "PINSRD $%d,AX,X0\nPINSRD $%d,BX,X1\n", (selector>>4&1)*2+half, (selector&1)*2+half)
					}
					if vector {
						fmt.Fprintf(&body, "VPCLMULQDQ $%d,X0,X1,X2\nPEXTRD $0,X2,AX\n", selector)
					} else {
						fmt.Fprintf(&body, "PCLMULQDQ $%d,X0,X1\nPEXTRD $0,X1,AX\n", selector)
					}
					source := "TEXT ·view(SB),4,$0-12\n" + body.String() + "MOVL AX,ret+8(FP)\nRET\n"
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view(a,b uint32) uint32\n", target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal(api, vector, selector, err)
						}
						compileLLVMToObject(t, llc, target.triple, "clmul-result.ll", "clmul-result.o", ir)
					}
				}
			}
		})
	}
}
