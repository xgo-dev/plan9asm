package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86LowWordSparseProjectionKeepsWholeSourceInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		var original strings.Builder
		original.WriteString("TEXT f(SB),4,$0-0\n")
		for _, row := range x86WordMultiplyValueRows(arch) {
			if row.op != "PMULLW" && row.op != "VPMULLW" {
				continue
			}
			instruction := row.op + " X0,X1"
			if row.op == "VPMULLW" {
				mask, suffix := "", ""
				if row.mode != "plain" {
					mask = "K1,"
				}
				if row.mode == "zero" {
					suffix = ".Z"
				}
				instruction = fmt.Sprintf("%s%s %s0,%s1,%s%s2", row.op, suffix, row.bank, row.bank, mask, row.bank)
			}
			original.WriteString(instruction + "\n")
			ins := x86ScalarLaneInstruction(t, instruction)
			width := map[string]int{"X": 16, "Y": 32, "Z": 64}[row.bank]
			full := x86CallerVectorByteMask(int64(width))
			for input := 0; input < 2; input++ {
				for missing := -1; missing < width; missing++ {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
					state.masks[1] = true
					for index := 0; index < 3; index++ {
						state.xmm[index] = 0xffff
						state.vectorUpper[index] = (full | 0xa55aa55aa55aa55a) &^ 0xffff
					}
					want := full
					if missing >= 0 {
						known := state.vectorBytes(input) &^ (uint64(1) << uint(missing))
						state.xmm[input], state.vectorUpper[input] = uint16(known), known&^0xffff
						want &^= uint64(3) << uint(missing/2*2)
					}
					before := state.clone()
					if !x86ResultTransfer(ins, &state, nil, 0, arch) {
						t.Fatal("low-word NUM projection lost a valid sparse lane", arch, instruction, input, missing)
					}
					destination := 2
					if row.op == "PMULLW" {
						destination = 1
						want |= before.vectorBytes(destination) &^ full
					} else {
						want |= ^full
					}
					if state.vectorBytes(destination) != want || state.flags != before.flags || state.direction != before.direction {
						t.Fatal("sparse low product invented bytes or changed aliases/flags", arch, instruction, input, missing)
					}
					private := before.clone()
					accepted := x86ScalarFPResultTransfer(ins, &private, nil, 0, arch)
					if accepted != (missing == -1) || !accepted && !reflect.DeepEqual(private, before) {
						t.Fatal("NUM projection bypassed complete source inputs", arch, instruction, input, missing)
					}
				}
			}
		}
		original.WriteString("RET\n")
		goAssemblerOracleOutput(t, arch, original.String(), "", true)
	}
}

func TestX86WordMultiplySourceGuardRetainsMarkedLiteralValidation(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86WordMultiplyNames {
			row := op + " X0,X1"
			if strings.HasPrefix(op, "V") {
				row = op + " X0,X1,X2"
			}
			ins := x86ScalarLaneInstruction(t, row)
			ins.x86SDKLiteral = &x86SDKLiteralCertificate{}
			state := x86ResultState{flags: x86ByteFlagsAll}
			state.xmm[0], state.xmm[1], state.xmm[2] = 0xffff, 0xffff, 0xffff
			before := state.clone()
			if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
				t.Fatal("word source guard bypassed a marked literal's independent validation", arch, op)
			}
		}
	}
}
