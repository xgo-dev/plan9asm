package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestX86ScalarReciprocalMode32FrontendAddressHasNoPhysicalPermission(t *testing.T) {
	for _, op := range []string{"VRCPSS", "VRSQRTSS"} {
		for _, base := range []string{"R8", "R9", "R10", "R11", "R13", "R14", "R15"} {
			memory := fmt.Sprintf("16(%s)", base)
			t.Run(op+"/"+memory, func(t *testing.T) {
				source := "TEXT f(SB),4,$0-0\n" + op + " " + memory + ",X1,X2\nRET\n"
				goAssemblerOracleOutput(t, "386", source, "", true)
				ins := x86ScalarLaneInstruction(t, op+" "+memory+",X1,X2")
				if _, known, err := x86ScalarReciprocalProperties(ins.Op, ins, "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("Go-accepted VEX address was misclassified as rejected syntax or granted a physical mode32 binding", known, err)
				}
				state := x86ResultState{}
				state.xmm[1], state.xmm[2] = 0xffff, 0xffff
				for index := range state.gp {
					state.gp[index], state.pointerGP[index] = 0xff, true
				}
				if accepted, known := x86ResultScalarReciprocalStep(ins, &state, nil, "386", true); !known || accepted {
					t.Fatal("frontend extended address acquired numerical or native permission", accepted, known)
				}
			})
		}
		for _, memory := range []string{"16(AX)(R9*2)", "16(R9)(CX*2)", "16(R12)"} {
			t.Run(op+"/rejected-SIB/"+memory, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, op+" "+memory+",X1,X2")
				if _, known, err := x86ScalarReciprocalProperties(ins.Op, ins, "386"); !known || err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("simple VEX base compatibility was incorrectly extended to SIB syntax", known, err)
				}
				if memory == "16(R9)(CX*2)" {
					x86ReciprocalSIBOriginalGoRejection(t, "386", "TEXT f(SB),4,$0-0\n"+ins.Raw+"\nRET\n")
				} else if memory == "16(AX)(R9*2)" {
					// Actual Go 1.27 emitted this positionless stderr in the
					// original RED, but the independent diagnostic join did not
					// bind it to the complete source. Retain the observation,
					// not a fabricated source-rejection certificate.
					t.Log("prior actual Go stderr: asm: asmidx: bad address 2/R9/AX; asm: assembly failed; unbound diagnostic, no source-rejection claim")
				} else {
					// Even without an explicit index, R12 requires SIB. Go's
					// asmidx source rejects its extended mode32 base; do not
					// invent a concrete tool diagnostic that was not observed.
					t.Log("R12 uses the independently inspected asmidx SIB source route, not the non-SIB frontend compatibility class")
				}
			})
		}
	}
}
