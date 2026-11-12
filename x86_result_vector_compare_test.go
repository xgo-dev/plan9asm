package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86ResultVectorCompareCompleteDestinationRoles(t *testing.T) {
	for _, op := range []string{"PCMPEQB", "PCMPEQW", "PCMPEQL", "PCMPEQQ", "PCMPGTB", "PCMPGTW", "PCMPGTL", "PCMPGTQ"} {
		vector := "V" + strings.ReplaceAll(op, "L", "D")
		rows := []string{op + " X0,X2", vector + " X0,X1,X2", vector + " Y0,Y1,Y2"}
		for _, bank := range []string{"X", "Y", "Z"} {
			rows = append(rows, fmt.Sprintf("%s %s0,%s1,K0", vector, bank, bank), fmt.Sprintf("%s %s0,%s1,K1,K0", vector, bank, bank))
		}
		for _, row := range rows {
			t.Run(row, func(t *testing.T) {
				goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
				state := x86ResultState{flags: x86ByteFlagsAll, masks: [8]bool{1: true}}
				state.writeVector(0, 64, ^uint64(0), false)
				state.writeVector(1, 64, ^uint64(0), false)
				state.xmm[2] = 0xffff
				state.vectorUpper[2] = 1 << 60
				if !x86ResultTransfer(x86ScalarLaneInstruction(t, row), &state, nil, 0, "amd64") {
					t.Fatal("typed compare destination has no closed numerical effect")
				}
				want := uint64(0xffff | 1<<60)
				if strings.HasSuffix(row, "K0") {
					if !state.masks[0] {
						t.Fatal("complete EVEX compare failed to define its K destination")
					}
				} else if strings.HasPrefix(row, "V") {
					want = ^uint64(0)
				}
				if state.vectorBytes(2) != want || state.flags != x86ByteFlagsAll {
					t.Fatal("packed compare changed the wrong vector aliases or flags")
				}
			})
		}
	}
}

func TestX86ResultVectorCompareRequiresEveryReadByte(t *testing.T) {
	for _, bank := range []string{"X", "Y", "Z"} {
		width := map[string]int{"X": 16, "Y": 32, "Z": 64}[bank]
		for _, op := range []string{"VPCMPEQB", "VPCMPEQW", "VPCMPEQD", "VPCMPEQQ", "VPCMPGTB", "VPCMPGTW", "VPCMPGTD", "VPCMPGTQ"} {
			row := fmt.Sprintf("%s %s0,%s1,K1,K0", op, bank, bank)
			for _, maskDefined := range []bool{false, true} {
				for missing := -1; missing < 64; missing++ {
					for input := 0; input < 2; input++ {
						state := x86ResultState{masks: [8]bool{1: maskDefined}}
						state.writeVector(0, 64, ^uint64(0), false)
						state.writeVector(1, 64, ^uint64(0), false)
						if missing >= 0 {
							state.writeVector(input, 64, ^(uint64(1) << uint(missing)), false)
						}
						before := state.clone()
						accepted := x86ResultTransfer(x86ScalarLaneInstruction(t, row), &state, nil, 0, "amd64")
						want := maskDefined && (missing < 0 || missing >= width)
						if accepted != want || accepted && !state.masks[0] || !accepted && !reflect.DeepEqual(before, state) {
							t.Fatal("wide comparison laundered missing input or mask bytes", row, input, missing, maskDefined)
						}
					}
				}
			}
		}
	}
}
