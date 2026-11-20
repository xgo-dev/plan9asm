package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestPackedAddSubCoverageRequiresNativeInputContext(t *testing.T) {
	// Independent complete legacy/V inventory, including Go's PADDD alias.
	names := strings.Fields("PADDB PADDW PADDL PADDD PADDQ PADDSB PADDSW PADDUSB PADDUSW " +
		"PSUBB PSUBW PSUBL PSUBQ PSUBSB PSUBSW PSUBUSB PSUBUSW " +
		"VPADDB VPADDW VPADDD VPADDQ VPADDSB VPADDSW VPADDUSB VPADDUSW " +
		"VPSUBB VPSUBW VPSUBD VPSUBQ VPSUBSB VPSUBSW VPSUBUSB VPSUBUSW")
	if len(names) != 33 {
		t.Fatal("complete independent add-sub inventory changed", len(names))
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range names {
			t.Run(arch+"/"+op, func(t *testing.T) {
				memory, registers := op+" 3(AX)(DX*2),X1", op+" X0,X1"
				if strings.HasPrefix(op, "V") {
					memory, registers = op+" 3(AX)(DX*2),X1,X2", op+" X0,X1,X2"
				}
				valueProbeNeedsContext(t, arch, memory)
				prefix := "VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n"
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, prefix+registers)); err != nil {
					t.Fatal("initialized registers became unsupported while checking native context", err)
				}
			})
		}
	}
}
