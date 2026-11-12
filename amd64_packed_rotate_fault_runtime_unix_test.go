//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// The output is deliberately dead. Active native reads must still fault,
// while inactive E4 elements and broadcasts must not read their address.
func TestX86PackedRotateDeadE4MemoryFaults(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	var source, declarations, prototypes, rows strings.Builder
	count := 0
	for _, family := range x86PackedRotateTestFamilies {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, broadcast := range []bool{false, true} {
				for _, zeroing := range []bool{false, true} {
					name := fmt.Sprint("RotateFault", count)
					count++
					width := amd64VectorByteWidth(Reg(bank + "0"))
					extent, suffix := width, ""
					if broadcast {
						extent, suffix = family.bits/8, ".BCST"
					}
					if zeroing {
						suffix += ".Z"
					}
					operands := fmt.Sprintf("$255,(AX),K1,%s2", bank)
					if family.variable {
						operands = fmt.Sprintf("(AX),%s1,K1,%s2", bank, bank)
					}
					fmt.Fprintf(&declarations, "func %s(p *[64]byte,mask uint64)\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),AX\n"+
						"KMOVQ mask+8(FP),K1\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n%s%s %s\nRET\n",
						name, family.op, suffix, operands)
					fmt.Fprintf(&prototypes, "extern void %s(const uint8_t *,uint64_t);\n", name)
					fmt.Fprintf(&rows, "{%s,%d,%d,%d},\n", name, extent, family.bits/8, width*8/family.bits)
				}
			}
		}
	}
	if count != 96 {
		t.Fatal("incomplete rotate width/broadcast/merge memory inventory", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	driver := x86E4DeadReadFaultOracle(prototypes.String(), rows.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal("complete dead rotate source rejected", err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					input := ir
					if level == "-O2" {
						input = x86MulDivRoundOptimize(t, ir)
					}
					execution.compileAndRunLLVM(t, "rotate-e4-faults", input, driver, level)
				})
			}
		})
	}
}
