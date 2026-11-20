//go:build go1.27

package plan9asm

import (
	"fmt"
	"testing"
)

// PCALIGNMAX was added after the oldest supported SDK. Current Go checks its
// real encoding; untagged tests still check every consumer on historical Go.
func TestX86DirectiveCurrentGoCompleteFormats(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86DirectiveValidForms() {
			t.Run(arch+"/"+row, func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT value(SB),4,$0-0\n"+row+"\nRET\n", "", true)
			})
		}
		for _, row := range []string{
			"PCALIGN", "PCALIGN $16,$1", "PCALIGN AX", "PCALIGN $16.0",
			"PCDATA $0", "PCDATA AX,$1", "PCDATA $0,$1.0",
			"FUNCDATA $0", "FUNCDATA AX,metadata(SB)", "FUNCDATA $0,$1",
			"FUNCDATA $0,metadata(SB)(AX)", "FUNCDATA $0,metadata(SB)(AX*1)",
		} {
			t.Run(arch+"/invalid/"+row, func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT value(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			})
		}
	}
}

func TestX86DirectiveCurrentGoFiveTargetObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []string{"PCALIGN $16", "PCALIGNMAX $16,$7", "PCDATA $0,$-1", "FUNCDATA $0,metadata(SB)"} {
			t.Run(target.triple+"/"+row, func(t *testing.T) {
				source := fmt.Sprintf("TEXT value(SB),4,$0-4\nMOVL $1,AX\n%s\nMOVL AX,ret+0(FP)\nRET\n", row)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			})
		}
	}
}
