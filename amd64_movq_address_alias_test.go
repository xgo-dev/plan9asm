package plan9asm

import (
	"bytes"
	"testing"
)

func TestX86MOVQAliasesRetainCompleteGoAddressRewrite(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, operand := range []string{
			"$·value(SB)", "$value<>+3(SB)", "$value<>-1(SB)",
			"$slot+0(FP)", "$slot-8(SP)", "$8(BX)", "$8(BX)(CX*4)",
		} {
			for _, alias := range x86OriginalMOVQAliases(t) {
				t.Run(arch+"/"+alias+"/"+operand, func(t *testing.T) {
					source := "TEXT address(SB),4,$0-16\n" + alias + " " + operand + ",AX\nRET\n"
					accepted := arch == "amd64"
					goAssemblerOracleOutput(t, arch, source, "", accepted)
					context := amd64Ctx{goarch: arch}
					instruction := x86PureGPUnknownInstruction(t, alias+" "+operand+",AX")
					if err := context.validateMOVDAliasForm(instruction); (err == nil) != accepted {
						t.Fatal("source alias lost AMOVQ TYPE_ADDR progedit", err)
					}
					if accepted {
						canonical := "TEXT address(SB),4,$0-16\nMOVQ " + operand + ",AX\nRET\n"
						if !bytes.Equal(x86OrderingHintGoBytes(t, arch, source), x86OrderingHintGoBytes(t, arch, canonical)) {
							t.Fatal("alias address bytes differ from original MOVQ")
						}
					}
				})
			}
		}
	}
}

func TestX86MOVQAliasAddressClassDoesNotGrantAnotherDestination(t *testing.T) {
	for _, alias := range x86OriginalMOVQAliases(t) {
		for _, destination := range []string{"X0", "M0", "8(BX)"} {
			t.Run(alias+"/"+destination, func(t *testing.T) {
				instruction := x86PureGPUnknownInstruction(t, alias+" $value<>(SB),"+destination)
				context := amd64Ctx{goarch: "amd64"}
				if err := context.validateMOVDAliasForm(instruction); err == nil {
					t.Fatal("address source became a memory, MMX or X immediate")
				}
			})
		}
	}
}
