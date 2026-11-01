package plan9asm

import (
	"reflect"
	"testing"
)

func TestX86XLATPairedByteInputsAliasesAndUnrelatedState(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		instruction := x86ScalarLaneInstruction(t, "XLAT")
		for _, knownAX := range []uint8{0, 1, 3, 0x55, 0xfe, 0xff} {
			for _, pointer := range []bool{false, true} {
				for _, flags := range []uint8{0, x86ByteFlagCF, x86ByteFlagsAll} {
					state := x86ResultState{flags: flags, direction: x86ResultDirectionBackward}
					state.gp[0], state.gp[3], state.gp[7] = knownAX, 0xff, 0xa5
					state.pointerGP[0], state.callerAddressGP[0], state.pointerGP[3] = true, true, pointer
					state.canonicalGP[0], state.callerAddressOrigin[0] = 0xff, 17
					state.resultAddressGP[0] = x86ResultSlotAddress{start: 8, end: 16, valid: true}
					before, expected := state.clone(), state.clone()
					valid := knownAX&1 != 0 && pointer
					if valid {
						expected.gp[0] |= 1
						expected.canonicalGP[0] &^= 1
						expected.pointerGP[0], expected.callerAddressGP[0], expected.callerAddressOrigin[0] = false, false, 0
						expected.resultAddressGP[0] = x86ResultSlotAddress{}
					}
					accepted, known := x86ResultXLATStep(instruction, &state, nil, arch, true)
					if !known || accepted != valid || !reflect.DeepEqual(state, expected) {
						t.Fatal("XLAT invented AL/BX input, defined AX high bytes or lost FLAGS/DF/unrelated facts", arch, knownAX, pointer, flags, accepted, valid)
					}
					if !valid && !reflect.DeepEqual(state, before) {
						t.Fatal("rejected XLAT partially changed its source state")
					}
				}
			}
		}
		for _, edit := range []func(*Instr){
			func(ins *Instr) { ins.x86Encoded = true },
			func(ins *Instr) { ins.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op} },
			func(ins *Instr) { ins.x86AddressBits = 32 },
			func(ins *Instr) { ins.x86SegmentPrefix = 0x64 },
		} {
			changed := instruction
			edit(&changed)
			state := x86ResultState{gp: [16]uint8{0: 0xff}, pointerGP: [16]bool{3: true}}
			before := state.clone()
			if accepted, known := x86ResultXLATStep(changed, &state, nil, arch, true); accepted || !known || !reflect.DeepEqual(state, before) {
				t.Fatal("paired XLAT accepted an unbound physical mode, origin or segment", arch)
			}
		}
	}
}
