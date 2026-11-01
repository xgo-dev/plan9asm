package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86ResultMode32BPOriginalAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	var source, declarations strings.Builder
	for index, operation := range []string{
		"NOP", "ADDL $9,BP", "XORL BP,BP", "MOVW $7,BP",
		"MOVL $9,DI\nXCHGB BP,DI", "MOVL $9,DI\nXCHGW BP,DI", "MOVL $9,DI\nXCHGL BP,DI",
		"LEAW 3(BP)(BP*2),BP", "LEAL 3(BP)(BP*2),BP", "CMPL BP,$0\nSETEQ BP\nMOVBLZX BP,BP",
	} {
		name := fmt.Sprintf("BPScalar%d", index)
		fmt.Fprintf(&declarations, "func %s(n uint32) uint32\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nMOVL n+0(FP),BP\n%s\nMOVL BP,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+4(FP)\nRET\n", name, operation)
	}
	for _, width := range []string{"B", "W", "L"} {
		name := "BPPointerTest" + width
		fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nMOVL p+0(FP),BP\nTEST%s $7,BP\nSETEQ AX\nMOVBLZX AX,AX\nMOVL AX,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+4(FP)\nRET\n", name, width)
	}
	for index, op := range []string{"CMPXCHGB", "CMPXCHGW", "CMPXCHGL", "CMPXCHG8B"} {
		name := fmt.Sprintf("BPCAS%d", index)
		fmt.Fprintf(&declarations, "func %s(p *uint64,a,b,c,d uint32) uint32\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVL p+0(FP),BP\nMOVL a+4(FP),AX\nMOVL b+8(FP),DX\nMOVL c+12(FP),BX\nMOVL d+16(FP),CX\nLOCK\n%s ", name, op)
		if op != "CMPXCHG8B" {
			source.WriteString("CX,")
		}
		source.WriteString("(BP)\nSETEQ AX\nMOVBLZX AX,AX\nMOVL AX,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+20(FP)\nRET\n")
	}
	declarations.WriteString("func BPLogicalResult(n uint32) uint32\n")
	source.WriteString("TEXT ·BPLogicalResult(SB),4,$0-8\nLEAL ret+4(FP),BP\nMOVL n+0(FP),SI\nMOVL SI,(BP)\nRET\n")
	if strings.Count(source.String(), "TEXT ") != 18 {
		t.Fatal("complete mode32 BP fixture inventory changed")
	}
	// Both affected targets retain original stock-Go objects and all three
	// translation APIs. IR-prepass and backend optimization are separate axes;
	// neither compilation nor this logical transport fixture executes native Go.
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "386", triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "386", triple, api)
					if err != nil || ir == "" {
						t.Fatal("original mode32 BP class did not translate", err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86MulDivRoundOptimize(t, input)
						}
						for _, backend := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR-O2-%t/backend%s", optimized, backend), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, triple, input, backend)
							})
						}
					}
				})
			}
		})
	}
}
