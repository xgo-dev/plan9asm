package plan9asm

import (
	"reflect"
	"testing"
)

func TestX86CLMULNativeEverySelectedByteAndWholeMemoryRole(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86CLMULNativeOriginCases() {
			t.Run(arch+"/"+row.name(), func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, row.code())
				destination := 2
				if row.encoding == "legacy" {
					destination = 1
				}
				for input := 0; input < 3; input++ {
					for missing := -1; missing < 64; missing++ {
						state := x86RawMoveInitializedState()
						if missing >= 0 {
							state.writeVector(input, 64, ^(uint64(1) << uint(missing)), false)
						}
						expected := state.clone()
						defined := x86CallerVectorByteMask(int64(row.width))
						if missing >= 0 && missing < row.width {
							// Independent SDM selectors: bit4 chooses source0,
							// bit0 source1; other immediate bits are ignored.
							selected := int(row.immediate & 1)
							if input == 0 {
								selected = int(row.immediate >> 4 & 1)
							}
							if (input == 1 || input == 0 && !row.memory) && missing%16/8 == selected {
								defined &^= uint64(65535) << uint(missing/16*16)
							}
						}
						expected.writeVector(destination, row.width, defined, row.encoding == "legacy")
						if accepted, known := x86LoweredCLMULStep(ins, &state, nil, arch); !known || !accepted || !reflect.DeepEqual(state, expected) {
							t.Fatal("CLMUL invented a selected qword, consumed an ignored one or changed independent state", input, missing, accepted, known)
						}
					}
				}
				if row.memory {
					state := x86RawMoveInitializedState()
					before := state.clone()
					if accepted, known := x86ResultCLMULStep(ins, &state, nil, arch); !known || accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("standalone result observer acquired paired native memory")
					}
					state.pointerGP[3] = false // Defined numerical BX cannot replace the original native address.
					before = state.clone()
					if accepted, known := x86LoweredCLMULStep(ins, &state, nil, arch); !known || accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("CLMUL discarded its complete native address obligation or partially committed its result")
					}
				}
			})
		}
	}
}

func TestX86CLMULNativeEditedSelectorAndOriginRejectAtomically(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86CLMULNativeOriginCases() {
			t.Run(arch+"/"+row.name(), func(t *testing.T) {
				original := x86RawMoveObservedInstruction(t, arch, row.code())
				for _, control := range []struct {
					name string
					edit func(*Instr)
				}{
					{"origin", func(ins *Instr) { ins.x86SourceRaw = nil }},
					{"selector", func(ins *Instr) { ins.Args[0].Imm ^= 1 }},
					{"ignored selector bit", func(ins *Instr) { ins.Args[0].Imm ^= 2 }},
					{"source selector", func(ins *Instr) { ins.x86SourceRaw.args[0].Imm ^= 1 }},
					{"opcode", func(ins *Instr) { ins.Op = "VPXOR" }},
					{"source opcode", func(ins *Instr) { ins.x86SourceRaw.op = "MOVL" }},
					{"data", func(ins *Instr) {
						if row.memory {
							ins.Args[1].Mem.Off++
						} else {
							ins.Args[1].Reg = "X4"
						}
					}},
					{"source data", func(ins *Instr) { ins.x86SourceRaw.args[1] = Operand{} }},
					{"destination", func(ins *Instr) { ins.Args[len(ins.Args)-1].Reg = "X4" }},
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
					state := x86RawMoveInitializedState()
					before := state.clone()
					if accepted, _ := x86LoweredCLMULStep(changed, &state, nil, arch); accepted ||
						x86RawCLMULSource(changed, arch) || !reflect.DeepEqual(state, before) {
						t.Fatal("edited selector, tuple or source acquired a CLMUL native result or partially changed state", control.name)
					}
				}
			})
		}
	}
}
