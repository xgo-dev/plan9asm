package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func TestX86RawPackedMovePhysicalGenerationSealRejectsAtomically(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86PackedMovePhysicalCases() {
			t.Run(fmt.Sprintf("%s/%s/%s/%s/EVEX%t", arch, row.name, row.bank, row.role, row.evex), func(t *testing.T) {
				original := x86RawMoveObservedInstruction(t, arch, row.code)
				state := x86RawMoveInitializedState()
				state.pointerGP[6] = true // The actual SI address, not an inferred pointee.
				before := state.clone()
				if accepted, known := x86LoweredRawVectorMoveStep(original, &state, nil, 0, arch); !known || !accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("complete original move lost its existing paired effect or changed independent state")
				}
				for _, control := range []struct {
					name string
					edit func(*Instr)
				}{
					{"absent snapshot", func(ins *Instr) { ins.x86SourceRaw.packedMove = x86RawPackedMoveIdentity{} }},
					{"foreign snapshot", func(ins *Instr) {
						ins.x86SourceRaw.packedMove.arch = map[string]string{"386": "amd64", "amd64": "386"}[arch]
					}},
					{"physical generation", func(ins *Instr) { ins.x86PackedVectorMoveEVEX = !ins.x86PackedVectorMoveEVEX }},
					{"physical grammar", func(ins *Instr) { ins.x86Encoded = !ins.x86Encoded }},
					{"snapshot generation", func(ins *Instr) { ins.x86SourceRaw.packedMove.evex = !ins.x86SourceRaw.packedMove.evex }},
					{"snapshot grammar", func(ins *Instr) { ins.x86SourceRaw.packedMove.encoded = !ins.x86SourceRaw.packedMove.encoded }},
				} {
					changed := cloneX86ReplayInstrs([]Instr{original})[0]
					control.edit(&changed)
					state = before.clone()
					if accepted, _ := x86LoweredRawVectorMoveStep(changed, &state, nil, 0, arch); accepted ||
						x86RawVectorMoveSource(changed, arch) || !reflect.DeepEqual(state, before) {
						t.Fatal("edited physical identity borrowed or partially committed a move effect", control.name)
					}
					if !x86RawVectorMoveSource(original, arch) {
						t.Fatal("editing a replay clone mutated the original generation snapshot", control.name)
					}
				}
			})
		}
	}
}

func TestX86RawPackedMovePhysicalGenerationCannotBroadenVEXOnlyMembers(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{"VMOVDQA", "VMOVDQU"} {
			for _, bank := range []string{"X", "Y"} {
				t.Run(arch+"/"+name+"/"+bank, func(t *testing.T) {
					file, err := Parse(ArchAMD64, fmt.Sprintf("TEXT f(SB),4,$0-0\n%s %s0,%s2\nRET\n", name, bank, bank))
					if err != nil {
						t.Fatal(err)
					}
					ins := file.Funcs[0].Instrs[1]
					if _, known, err := amd64PackedVectorMoveProperties(ins, arch); !known || err != nil {
						t.Fatal("the complete original VEX-only member lost its grammar", err)
					}
					ins.x86PackedVectorMoveEVEX = true
					if _, known, err := amd64PackedVectorMoveProperties(ins, arch); !known || err == nil {
						t.Fatal("physical generation metadata invented an EVEX spelling for a VEX-only member")
					}
				})
			}
		}
	}
}
