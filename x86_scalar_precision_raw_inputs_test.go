package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func TestX86ScalarPrecisionRawPairedInputsAndIndependentState(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for index, row := range x86ScalarPrecisionRawCases() {
			if arch == "386" && (row.row.mode == "merge" || row.row.mode == "zero") {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d/%s", arch, index, row.row.instruction()), func(t *testing.T) {
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t,
					"TEXT ·RawInputs(SB),4,$0-0\n"+x86RawDisplacementDirectives(row.code)+"RET\n"), arch)
				if err != nil {
					t.Fatal(err)
				}
				instruction := file.Funcs[0].Instrs[1]
				if !x86RawScalarPrecisionSource(instruction, arch) {
					t.Fatal("physical conversion lost its exact typed source identity")
				}
				for _, missing := range []string{"none", "input", "upper", "old", "mask", "pointer"} {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
						masks: [8]bool{1: true}}
					for register := 0; register < 3; register++ {
						state.writeVector(register, 64, ^uint64(0), true)
					}
					state.pointerGP[0], state.callerAddressGP[0] = true, true
					source, upper, destination := row.row.registers()
					valid := true
					switch missing {
					case "input":
						state.writeVector(source, 64, ^x86CallerVectorByteMask(int64(row.row.input)), true)
						valid = row.row.source == "native"
					case "upper":
						state.writeVector(upper, 64, x86CallerVectorByteMask(int64(row.row.output)), true)
					case "old":
						state.writeVector(destination, 64, ^x86CallerVectorByteMask(int64(row.row.output)), true)
						valid = row.row.mode != "merge"
					case "mask":
						state.masks[1] = false
						valid = row.row.mode != "merge" && row.row.mode != "zero"
					case "pointer":
						state.pointerGP[0] = false
						valid = row.row.source != "native"
					}
					before, expected := state.clone(), state.clone()
					if valid {
						output := x86CallerVectorByteMask(int64(row.row.output))
						expected.writeVector(destination, 16, output|state.vectorBytes(upper)&(0xffff&^output), !row.row.vector)
					}
					standalone := state.clone()
					if accepted, known := x86ResultScalarPrecisionStep(instruction, &standalone, nil, arch, false); accepted || !known || !reflect.DeepEqual(standalone, before) {
						t.Fatal("raw source identity granted standalone numerical authority", missing)
					}
					accepted, known := x86ResultScalarPrecisionStep(instruction, &state, nil, arch, true)
					if !known || accepted != valid || !reflect.DeepEqual(state, expected) {
						t.Fatal("paired raw conversion lost active/merge/K/native inputs or fabricated copied upper bytes", missing, accepted, valid)
					}
					if x86ResultCallerAddressesAfter(instruction, before.callerAddressGP, nil, arch) != before.callerAddressGP ||
						x86ResultDirectionAfterSource(instruction, before.direction, arch) != before.direction ||
						!x86ResultPreservesPrivateStorage(instruction, arch) {
						t.Fatal("exact conversion discarded unrelated GP/DF/private state")
					}
				}
			})
		}
	}
}
