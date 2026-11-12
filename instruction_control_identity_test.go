package plan9asm

import (
	"strings"
	"testing"
)

func TestDescribeInstructionRetainsFullControlIdentity(t *testing.T) {
	for _, control := range []string{
		"", ".Z", ".BCST", ".BCST.Z", ".SAE", ".SAE.Z",
		".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE", ".RN_SAE.Z",
		".Z.BCST", ".UNKNOWN",
	} {
		t.Run("VADDPD"+control, func(t *testing.T) {
			// Identity preserves even invalid controls; it grants no grammar
			// acceptance, initialized inputs or executable evidence.
			ins := Instr{Op: Op(" vaddpd" + strings.ToLower(control) + " "), Args: []Operand{
				{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X2"},
			}}
			for _, arch := range []string{"386", "amd64"} {
				descriptor := DescribeInstruction(ArchAMD64, arch, ins)
				if descriptor.Opcode != "VADDPD" || descriptor.Family != "avx" ||
					descriptor.Form != "VADDPD"+control+" xmm,xmm,xmm" {
					t.Fatalf("%s: source controls collapsed or changed the opcode family: %+v", arch, descriptor)
				}
			}
		})
	}
}
