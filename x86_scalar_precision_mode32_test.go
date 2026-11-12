package plan9asm

import (
	"errors"
	"reflect"
	"testing"
)

func TestX86ScalarPrecisionMode32FrontendDoesNotGrantPhysicalInputs(t *testing.T) {
	for _, op := range []string{"VCVTSS2SD", "VCVTSD2SS"} {
		for _, operands := range []string{"X31,X30,X29", "16(R9),X1,X2"} {
			t.Run(op+"/"+operands, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, op+" "+operands)
				goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+ins.Raw+"\nRET\n", "", true)
				if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("Go's accepted spelling acquired a physical mode32 register/address or became rejected syntax", known, err)
				}
				state := x86ResultState{flags: x86ByteFlagsAll}
				for index := range state.xmm {
					state.writeVector(index, 64, ^uint64(0), true)
				}
				for index := range state.gp {
					state.gp[index], state.pointerGP[index] = 0xff, true
				}
				before := state.clone()
				if x86ResultTransfer(ins, &state, nil, 0, "386") || !reflect.DeepEqual(state, before) {
					t.Fatal("frontend spelling borrowed an AMD64 numerical/native input", state)
				}
			})
		}
	}
}
