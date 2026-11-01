package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestX86RawIntegerCompareEveryInputByteAndIndependentState(t *testing.T) {
	rows := x86RawIntegerCompareOriginCases()
	code := x86RawIntegerCompareOriginBytes(t, rows)
	for _, arch := range []string{"386", "amd64"} {
		for ordinal, row := range rows {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, code[ordinal])
				width := map[string]int{"X": 16, "Y": 32, "Z": 64}[row.bank]
				second := 0
				if row.legacy {
					second = 2
				}
				for input := 0; input < 3; input++ {
					for missing := -1; missing < 64; missing++ {
						state := x86RawMoveInitializedState()
						state.masks[2] = false // K destinations are write-only, including masked compares.
						if missing >= 0 {
							state.writeVector(input, 64, ^(uint64(1) << uint(missing)), false)
						}
						before, expected := state.clone(), state.clone()
						wanted := missing < 0 || missing >= width || input != second && (row.memory || input != 1)
						if wanted {
							if row.destination == "K2" {
								expected.masks[2] = true
							} else {
								expected.writeVector(2, width, x86CallerVectorByteMask(int64(width)), row.legacy)
							}
						}
						accepted, known := x86LoweredPackedIntegerCompareStep(ins, &state, nil, arch)
						if !known || accepted != wanted || wanted && !reflect.DeepEqual(state, expected) ||
							!wanted && !reflect.DeepEqual(state, before) {
							t.Fatal("raw compare invented input, merged K output, erased an alias or changed independent FLAGS/DF/storage", input, missing, accepted, wanted)
						}
					}
				}
				for _, control := range []string{"mask", "native address"} {
					if control == "mask" && !row.mask || control == "native address" && !row.memory {
						continue
					}
					state := x86RawMoveInitializedState()
					if control == "mask" {
						state.masks[1] = false
					} else {
						state.pointerGP[3] = false // Numerically defined BX still does not supply a native pointer.
					}
					before := state.clone()
					if accepted, known := x86LoweredPackedIntegerCompareStep(ins, &state, nil, arch); !known || accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("raw compare borrowed an unknown mask or native address", control)
					}
				}
			})
		}
	}
}

func TestX86RawIntegerCompareEditedOriginRejectsAtomically(t *testing.T) {
	rows := x86RawIntegerCompareOriginCases()
	code := x86RawIntegerCompareOriginBytes(t, rows)
	for _, arch := range []string{"386", "amd64"} {
		for ordinal, row := range rows {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				original := x86RawMoveObservedInstruction(t, arch, code[ordinal])
				for _, control := range []struct {
					name string
					edit func(*Instr)
				}{
					{"origin", func(ins *Instr) { ins.x86SourceRaw = nil }},
					{"opcode", func(ins *Instr) {
						if strings.Contains(string(ins.Op), "EQ") {
							ins.Op = Op(strings.Replace(string(ins.Op), "EQ", "GT", 1))
						} else {
							ins.Op = Op(strings.Replace(string(ins.Op), "GT", "EQ", 1))
						}
					}},
					{"operand", func(ins *Instr) {
						if row.memory {
							ins.Args[0].Mem.Off++
						} else {
							ins.Args[0].Reg = Reg(row.bank + "4")
						}
					}},
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
					state := x86RawMoveInitializedState()
					before := state.clone()
					if accepted, _ := x86LoweredPackedIntegerCompareStep(changed, &state, nil, arch); accepted ||
						x86RawPackedIntegerCompareSource(changed, arch) || !reflect.DeepEqual(state, before) {
						t.Fatal("edited raw compare borrowed or partially committed a paired typed/native effect", control.name)
					}
				}
			})
		}
	}
}
