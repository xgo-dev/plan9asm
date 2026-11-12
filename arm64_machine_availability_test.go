package plan9asm

import (
	"errors"
	"testing"
)

func TestARM64GoRegisterMachineLowBitsAndMerge(t *testing.T) {
	for _, tc := range []struct {
		name       string
		read       int
		leftWidth  int
		rightWidth int
		context    bool
	}{
		{"narrow_copy", 8, 8, 8, false},
		{"copy_does_not_widen", 9, 8, 8, true},
		{"mixed_paths_low_bits", 8, 64, 8, false},
		{"mixed_paths_high_bits", 64, 64, 8, true},
		{"all_paths_redefined", 64, 64, 64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := func(reg Reg, typ LLVMType) ARM64GoRegisterValue {
				return ARM64GoRegisterValue{Register: reg, Type: typ}
			}
			flow := &arm64MachineAvailability{
				used: true, entry: &ARM64GoRegisterABI{Params: []ARM64GoRegisterValue{leaf("R0", I8)}},
				blocks: []arm64MachineBlock{
					{name: "entry", successors: []string{"left", "right"}},
					{name: "left", successors: []string{"merge"}},
					{name: "right", successors: []string{"merge"}},
					{name: "merge", effects: []arm64MachineEffect{{register: "R9", width: tc.read}}},
				},
			}
			for i, width := range []int{tc.leftWidth, tc.rightWidth} {
				if width == 64 {
					flow.blocks[i+1].effects = []arm64MachineEffect{{register: "R9", width: 64, write: true}}
				} else {
					flow.blocks[i+1].effects = []arm64MachineEffect{{register: "R9", copyFrom: "R0", width: 64}}
				}
			}
			if err := flow.validate(); errors.Is(err, ErrProbeNeedsContext) != tc.context || (!tc.context && err != nil) {
				t.Fatalf("width intersection context=%t: %v", tc.context, err)
			}
		})
	}
	for _, tc := range []struct {
		typ  LLVMType
		bits int
	}{
		{I1, 1}, {I8, 8}, {I16, 16}, {I32, 32}, {I64, 64}, {Ptr, 64}, {"float", 32}, {"double", 64}, {"unknown", 0},
	} {
		if got := arm64MachineScalarWidth(tc.typ); got != tc.bits {
			t.Errorf("%s: bits=%d, want %d", tc.typ, got, tc.bits)
		}
	}
}
