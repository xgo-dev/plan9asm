package plan9asm

import "testing"

func TestX86WordMultiplyAddLegacyVirtualMemoryCannotProveAlignment(t *testing.T) {
	for _, operand := range []string{"source+0(FP)", "(SP)", "(BP)"} {
		for _, target := range x86RawReturnTargets {
			source := "TEXT ·f(SB),4,$0-64\nPXOR X1,X1\nPMADDWL " + operand + ",X1\nRET\n"
			declaration := "func f(source [64]byte)"
			if operand != "source+0(FP)" {
				source = x86OrdinaryBPNativeSource(target.arch, "f", "PMADDWL "+operand+",X1", operand, 0)
				declaration = "func f(p *byte)"
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+operand+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					x86RequireOrdinaryBPNativeOutcome(t, target.arch, operand, ir, err)
				})
			}
		}
	}
}
