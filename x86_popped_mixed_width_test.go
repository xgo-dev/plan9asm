package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestX86StackRefinementCloneJoinAndReuse(t *testing.T) {
	flags := x86ResultState{valueStack: &x86ResultValueStack{
		bytes: []uint8{0xff, 0xff}, refinable: []uint8{0, 1},
	}}
	numeric := x86ResultState{valueStack: &x86ResultValueStack{bytes: []uint8{0xff, 0xff}}}
	copy := flags.clone()
	copy.valueStack.refinable[1] = 0
	if flags.valueStack.refinable[1] != 1 {
		t.Fatal("refinement masks alias a predecessor")
	}
	for _, pair := range [][2]x86ResultState{{flags, numeric}, {numeric, flags}} {
		joined := pair[0].intersect(pair[1])
		if !reflect.DeepEqual(joined.valueStack.refinable, []uint8{0, 1}) {
			t.Fatal("a numeric edge laundered FLAGS-origin control bits", joined.valueStack)
		}
		joined.valueStack.refinable[1] = 0
		if flags.valueStack.refinable[1] != 1 {
			t.Fatal("joined refinement masks alias a predecessor")
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		storage := 2
		if arch == "amd64" {
			storage = 8
		}
		state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward,
			valueStack: &x86ResultValueStack{id: true}}
		count := x86ResultValueStackLimit(arch) / storage
		for index := 0; index < count; index++ {
			instruction := "PUSHW $7"
			if index%2 == 0 {
				instruction = "PUSHFW"
			}
			ins := x86ScalarLaneInstruction(t, instruction)
			if accepted, known := x86ResultValueStackStep(ins, &state, nil, 0, arch); !accepted || !known {
				t.Fatal("bounded complete stack slot rejected", arch, index)
			}
		}
		for index := count - 1; index >= 0; index-- {
			ins := x86ScalarLaneInstruction(t, "POPW AX")
			want := uint64(0xffff)
			if index%2 == 0 {
				want = 0xcff
			}
			if accepted, known := x86ResultValueStackStep(ins, &state, nil, 0, arch); !accepted || !known || state.valueStack.popped.bits&0xffff != want {
				t.Fatal("source-bit eligibility changed at a stack position", arch, index, state.valueStack.popped)
			}
		}
		if len(state.valueStack.bytes) != 0 || state.valueStack.refinable != nil {
			t.Fatal("consumed source masks survived an empty stack", arch)
		}
		for _, text := range []string{"PUSHW $7", "POPW AX"} {
			ins := x86ScalarLaneInstruction(t, text)
			if accepted, known := x86ResultValueStackStep(ins, &state, nil, 0, arch); !accepted || !known {
				t.Fatal("numeric storage could not reuse a former FLAGS slot", arch, text)
			}
		}
		if state.valueStack.popped.bits&0xffff != 0xffff {
			t.Fatal("a stale FLAGS mask contaminated reused numeric storage", arch)
		}
	}
}

func TestX86PoppedMixedWidthsRetainOriginalFlagBitPositions(t *testing.T) {
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		for _, row := range []struct {
			name   string
			mask   int
			accept bool
		}{{"unmodeled-AC", 4, false}, {"modeled-ID", 32, true}} {
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-4\nPUSHL $0\nPOPFL\nMOVL $3,AX\nMULL AX\nCLD\nPUSHFL\nPOPW BX\nPOPW AX\nANDW $%d,AX\nMOVW AX,ret+0(FP)\nMOVW $0,ret+2(FP)\nRET\n", row.mask)
			goAssemblerOracleOutput(t, "386", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", "386", triple, api)
					if row.accept && (err != nil || ir == "") || !row.accept && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
						t.Fatal("mixed-width flags transport changed an original bit role", row.accept, err)
					}
				})
			}
		}
	}
}
