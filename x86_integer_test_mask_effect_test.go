package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86IntegerTestMaskResultKeepsFlagsVectorsAndInputMaskRoles(t *testing.T) {
	for _, op := range strings.Fields("VPTESTMB VPTESTMW VPTESTMD VPTESTMQ VPTESTNMB VPTESTNMW VPTESTNMD VPTESTNMQ") {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, destination := range []int{0, 2, 1} {
				row := fmt.Sprintf("%s %s0,%s1,K1,K%d", op, bank, bank, destination)
				ins := x86ScalarLaneInstruction(t, row)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
				if !known || err != nil || !effect.requiresResultProof {
					t.Fatal("complete original mask-result row lost its typed byte effect", row, err)
				}
				result := effect.operands[2]
				if result.index != 3 || result.width != 8 || result.read || !result.write {
					t.Fatal("output K acquired an old-result read or vector carrier", row, result)
				}
				for _, maskKnown := range []bool{false, true} {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
					state.writeVector(0, 64, ^uint64(0), false)
					state.writeVector(1, 64, ^uint64(0), false)
					state.masks[1] = maskKnown
					before := state.clone()
					accepted := x86ResultTransfer(ins, &state, nil, 0, "amd64")
					if maskKnown {
						before.masks[destination] = true
					}
					if accepted != maskKnown || !reflect.DeepEqual(state, before) {
						t.Fatal("K0 output, mask/output alias, FLAGS/DF or source vectors changed", row, maskKnown, accepted)
					}
				}
			}
		}
	}
}
