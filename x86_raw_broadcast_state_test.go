package plan9asm

import (
	"reflect"
	"testing"
)

func x86RawBroadcastInitializedState() x86ResultState {
	state := x86RawMoveInitializedState()
	state.pointerGP[6], state.callerAddressGP[6] = true, true // The independent ordinary source is SI.
	return state
}

func TestX86RawBroadcastEveryInputByteAndIndependentState(t *testing.T) {
	rows := x86RawBroadcastOriginCases()
	code := x86RawBroadcastOriginBytes(t, rows)
	for _, arch := range []string{"386", "amd64"} {
		for ordinal, row := range rows {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, code[ordinal])
				width, inputBytes := map[string]int{"X": 16, "Y": 32, "Z": 64}[row.bank], row.bytes
				if arch == "386" && row.source == "AX" && row.bytes == 8 {
					inputBytes = 4 // The original opcode 7C/W1 has a physical r32 input here.
				}
				for input := 0; input < 3; input++ {
					for missing := -1; missing < 64; missing++ {
						state := x86RawBroadcastInitializedState()
						if missing >= 0 {
							state.writeVector(input, 64, ^(uint64(1) << uint(missing)), false)
						}
						before, expected := state.clone(), state.clone()
						wanted := !(missing >= 0 && (input == 1 && row.source == "X1" && missing < inputBytes ||
							input == 2 && row.masked && !row.zero && missing < 16))
						if wanted {
							defined := ^uint64(0)
							if row.masked && !row.zero {
								// Existing typed effects retain unknown inactive upper
								// bytes, rather than initializing an unobserved alias.
								defined &= state.vectorBytes(2)
							}
							expected.writeVector(2, width, defined, false)
						}
						accepted, known := x86LoweredRawBroadcastStep(ins, &state, nil, arch)
						if !known || accepted != wanted || wanted && !reflect.DeepEqual(state, expected) ||
							!wanted && !reflect.DeepEqual(state, before) {
							t.Fatal("raw broadcast invented a scalar/block/old byte, changed independent state or partially committed rejection", input, missing, accepted, wanted)
						}
					}
				}
				if row.source == "AX" {
					for missing := -1; missing < 8; missing++ {
						state := x86RawBroadcastInitializedState()
						if missing >= 0 {
							state.gp[0] &^= uint8(1) << uint(missing)
						}
						before, expected := state.clone(), state.clone()
						wanted := missing < 0 || missing >= inputBytes
						if wanted {
							expected.writeVector(2, width, ^uint64(0), false)
						}
						accepted, known := x86LoweredRawBroadcastStep(ins, &state, nil, arch)
						if !known || accepted != wanted || wanted && !reflect.DeepEqual(state, expected) ||
							!wanted && !reflect.DeepEqual(state, before) {
							t.Fatal("raw broadcast consumed the wrong physical GP bytes or changed independent state", missing, accepted, wanted)
						}
					}
				}
				for _, control := range []string{"mask", "K data", "native address", "GP pointer"} {
					if control == "mask" && !row.masked || control == "K data" && row.source != "K1" ||
						control == "native address" && row.source != "(SI)" || control == "GP pointer" && row.source != "AX" {
						continue
					}
					state := x86RawBroadcastInitializedState()
					switch control {
					case "mask":
						state.masks[3] = false
					case "K data":
						state.masks[1] = false
					case "native address":
						state.pointerGP[6] = false // Numeric SI is not a native pointer.
					case "GP pointer":
						state.pointerGP[0] = true // Opaque pointer AX is not numerical scalar input.
					}
					before := state.clone()
					if accepted, known := x86LoweredRawBroadcastStep(ins, &state, nil, arch); !known || accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("raw broadcast borrowed an independent input role", control)
					}
				}
			})
		}
	}
}

func TestX86RawBroadcastEditedOriginRejectsAtomically(t *testing.T) {
	rows := x86RawBroadcastOriginCases()
	code := x86RawBroadcastOriginBytes(t, rows)
	for _, arch := range []string{"386", "amd64"} {
		for ordinal, row := range rows {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				original := x86RawMoveObservedInstruction(t, arch, code[ordinal])
				for _, control := range []struct {
					name string
					edit func(*Instr)
				}{
					{"origin", func(ins *Instr) { ins.x86SourceRaw = nil }},
					{"opcode", func(ins *Instr) { ins.Op = "VPBROADCASTB" }},
					{"operand", func(ins *Instr) {
						if row.source == "(SI)" {
							ins.Args[0].Mem.Off++
						} else {
							ins.Args[0].Reg = "DX"
						}
					}},
					{"destination", func(ins *Instr) { ins.Args[len(ins.Args)-1].Reg = Reg(row.bank + "4") }},
					{"source opcode", func(ins *Instr) { ins.x86SourceRaw.op = "MOVL" }},
					{"source operand", func(ins *Instr) { ins.x86SourceRaw.args[0] = Operand{} }},
					{"vector width", func(ins *Instr) { ins.x86VectorBytes += 16 }},
					{"source width", func(ins *Instr) { ins.x86SourceRaw.vectorBytes += 16 }},
					{"address width", func(ins *Instr) { ins.x86AddressBits = 16 }},
					{"address override", func(ins *Instr) { ins.x86UnboundAddressOverride = true }},
					{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
					{"literal", func(ins *Instr) { ins.x86RIPLiteral = true }},
					{"raw return", func(ins *Instr) { ins.x86RawNearReturn = new(x86RawNearReturnForm) }},
					{"numerical certificate", func(ins *Instr) { ins.x86NumericalRead = new(x86NumericalReadCertificate) }},
				} {
					changed := cloneX86ReplayInstrs([]Instr{original})[0]
					control.edit(&changed)
					// Make the opcode mutation real for the B member as well.
					if control.name == "opcode" && original.Op == changed.Op {
						changed.Op = "VPBROADCASTW"
					}
					state := x86RawBroadcastInitializedState()
					before := state.clone()
					if accepted, _ := x86LoweredRawBroadcastStep(changed, &state, nil, arch); accepted ||
						x86RawBroadcastSource(changed, arch) || !reflect.DeepEqual(state, before) {
						t.Fatal("edited raw broadcast acquired or partially committed a typed/native effect", control.name)
					}
				}
			})
		}
	}
}
