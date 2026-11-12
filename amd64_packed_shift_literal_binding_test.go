package plan9asm

import (
	"strings"
	"testing"
)

func TestX86PackedShiftLiteralBindingAndStateLifetime(t *testing.T) {
	for _, mutation := range []string{"control", "missing-global", "mutable", "duplicate-global",
		"relocation", "overlap", "payload-too-long", "code-collision", "resolved-alias"} {
		t.Run(mutation, func(t *testing.T) {
			file, err := Parse(ArchAMD64, x86ShiftLiteralMaskSource(x86ShiftLiteralMaskCases()[0], "PAND", 4, 0x0f, 0))
			if err != nil {
				t.Fatal(err)
			}
			resolve := func(symbol string) string {
				symbol = strings.TrimPrefix(symbol, "·")
				if symbol == "alias" {
					return "mask<>"
				}
				return symbol
			}
			switch mutation {
			case "missing-global":
				file.Globl = nil
			case "mutable":
				file.Globl[0].Flags = "0"
			case "duplicate-global":
				file.Globl = append(file.Globl, file.Globl[0])
			case "relocation":
				file.Data[0].Addr = "·other"
			case "overlap":
				file.Data = append(file.Data, file.Data[0])
			case "payload-too-long":
				file.Data[0].Payload = make([]byte, 9)
			case "code-collision":
				file.Funcs = append(file.Funcs, Func{Sym: "mask<>"})
			case "resolved-alias":
				file.Data[1].Sym = "alias"
			}
			values := x86LoweredStaticAddressValues(file, resolve, nil, "amd64")
			literals := x86LoweredShiftLiterals(file, resolve, values, "amd64")
			if mutation != "control" {
				if len(literals) != 0 {
					t.Fatal("unbound, mutable or aliased object supplied literal bits", literals)
				}
				return
			}
			literal := literals[x86StaticSBAddress{symbol: "mask<>"}]
			if len(literals) != 1 || literal.width != 16 {
				t.Fatal("complete actual readonly tuple was lost", literals)
			}
			for _, value := range literal.bytes[:literal.width] {
				if value != 0x0f {
					t.Fatal("literal bits disagree with actual emitted DATA", literal)
				}
			}
		})
	}
	pending := x86ResultShiftBits{input: 1, register: 3, width: 64, lane: 16, count: 4}
	state := x86ResultState{shiftBits: pending}
	if state.clone().shiftBits != pending || state.intersect(state).shiftBits != pending {
		t.Fatal("identical adjacent dependency was not value-copied")
	}
	other := state.clone()
	other.shiftBits.input = 3
	if state.intersect(other).shiftBits.width != 0 || state.intersect(x86ResultState{}).shiftBits.width != 0 {
		t.Fatal("different predecessor shifts were joined as one fact")
	}
}

func TestX86PackedShiftRawKeepsNamedBitDependenciesSeparate(t *testing.T) {
	pending := x86ResultShiftBits{input: 1, register: 3, width: 64, lane: 16, count: 4}
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86PackedShiftRawCases() {
			t.Run(arch+"/"+row.name(), func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, row.code(false))
				for _, knownBytes := range []uint64{1, ^uint64(0)} {
					state := x86ResultState{shiftBits: pending}
					for index := 0; index < 3; index++ {
						state.writeVector(index, 64, knownBytes, false)
					}
					state.pointerGP[3], state.masks[1] = true, true
					accepted, known := x86LoweredRawPackedShiftStep(ins, &state, nil, arch)
					if !known || !accepted || state.shiftBits != pending {
						t.Fatal("raw projection created or replaced a named-only bit dependency", accepted, known)
					}
				}
			})
		}
	}

	state := x86ResultState{}
	state.writeVector(1, 16, 1, true)
	ins := x86ScalarLaneInstruction(t, "VPSRLW $4,X1,X0")
	accepted, known := x86ResultPackedShiftStepWithRead(ins, &state, nil, "amd64", true)
	want := x86ResultShiftBits{input: 1, register: 0, width: 16, lane: 16, count: 4}
	if !accepted || !known || state.shiftBits != want {
		t.Fatal("genuine named input lost its adjacent bit dependency", accepted, known, state.shiftBits)
	}
}
