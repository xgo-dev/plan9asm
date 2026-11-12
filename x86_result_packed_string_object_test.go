package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86PackedStringResultObjectFixture(arch string) (string, string) {
	move, word := "MOVQ", 8
	if arch == "386" {
		move, word = "MOVL", 4
	}
	var source, declarations strings.Builder
	for _, row := range go127PackedStringCompareSpecs() {
		for _, role := range []string{"register", "native", "dead-native"} {
			name := strings.ToLower(row.op) + strings.ReplaceAll(role, "-", "")
			fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nPXOR X0,X0\nPXOR X1,X1\nMOVL $0,AX\nMOVL $0,DX\n", name, word+4)
			operand := "X0"
			if role != "register" {
				fmt.Fprintf(&source, "%s p+0(FP),DI\n", move)
				operand = "1(DI)"
			}
			fmt.Fprintf(&source, "%s $12,%s,X1\n", row.op, operand)
			if role == "dead-native" {
				source.WriteString("MOVL $7,AX\n")
			} else if row.mask {
				source.WriteString("MOVL X0,AX\n")
			} else {
				source.WriteString("MOVL CX,AX\n")
			}
			fmt.Fprintf(&source, "MOVL AX,ret+%d(FP)\nRET\n", word)
		}
	}
	return source.String(), declarations.String()
}

func TestX86PackedStringNumericalCompleteFiveTargetGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete packed-string numerical objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86PackedStringResultObjectFixture(target.arch)
			if strings.Count(source, "TEXT ·") != 24 {
				t.Fatal("complete eight-name/three-role source inventory changed")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || strings.Count(ir, "load volatile <16 x i8>") != 16 {
						t.Fatal("complete original numerical/read inventory changed", err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86UndefinedTrapOptimizedIR(t, input)
						}
						if strings.Count(input, "load volatile <16 x i8>") != 16 {
							t.Fatal("full native dead/zero-length source reads lost before objects")
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimized, level), func(t *testing.T) { x86PackedStringCompileObject(t, llc, target.triple, input, level) })
						}
					}
				})
			}
		})
	}
}
