package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86FourSourceRejectsMalformedSuffixesBeforeEffects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, member := range x86FourSourceOracle {
			row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, dot: member.dot, first: 2, dest: 6, mode: "plain"}
			original := x86ScalarLaneInstruction(t, row.instruction())
			for _, suffix := range []string{".", "..", ".Z.", ".Z.Z", ".BCST", ".SAE", ".RN_SAE", ".Z.BCST"} {
				t.Run(arch+"/"+member.op+suffix, func(t *testing.T) {
					ins := original
					ins.Op = Op(member.op + suffix)
					ins.Raw = strings.Replace(ins.Raw, member.op, string(ins.Op), 1)
					before := fmt.Sprintf("%#v", ins)
					if _, known, err := x86FourSourceProperties(ins.Op, ins, arch); !known || err == nil {
						t.Fatal("trailing or unsupported suffix entered the complete typed grammar", known, err)
					}
					if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); !known || err == nil {
						t.Fatal("malformed suffix acquired numerical read/write roles", known, err)
					}
					if features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}}); features != "" {
						t.Fatal("malformed suffix acquired native ISA attributes", features)
					}
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
					for register := 0; register < 8; register++ {
						state.writeVector(register, 64, ^uint64(0), false)
					}
					pointer, _, _ := x86ResultGP(BX, x86ResultPointerWord(arch), arch)
					state.pointerGP[pointer] = true
					state.masks[1] = true
					old := state.clone()
					if accepted, known := x86ResultFourSourceStep(ins, &state, nil, arch, true); accepted || !known || !reflect.DeepEqual(old, state) {
						t.Fatal("malformed suffix mutated fully initialized native state", accepted, known)
					}
					if before != fmt.Sprintf("%#v", ins) {
						t.Fatal("malformed-source observation changed the original instruction")
					}
				})
			}
		}
	}
}
