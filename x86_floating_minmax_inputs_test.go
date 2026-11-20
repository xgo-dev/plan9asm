package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestX86FloatingMinMaxEveryInputByteAndUpperAlias(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86FloatingMinMaxFormats(arch) {
			if strings.Contains(row, "(AX)") {
				continue // Native tuples have separate paired-read and literal owners.
			}
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				f, known, err := x86FloatMinMaxProperties(ins, arch)
				if !known || err != nil {
					t.Fatal(row, err)
				}
				active := f.byteWidth
				if f.scalar {
					active = f.bits / 8
				}
				for missing := -1; missing < 193; missing++ {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
					state.gp[5], state.pointerGP[7], state.callerAddressGP[7], state.masks[1] = 0x53, true, true, true
					for register := 0; register < 3; register++ {
						state.writeVector(register, 64, ^uint64(0), false)
					}
					want := true
					if missing == 192 {
						state.masks[1], want = false, f.mask < 0
					} else if missing >= 0 {
						register, bit := missing/64, uint(missing%64)
						state.writeVector(register, 64, state.vectorBytes(register)&^(uint64(1)<<bit), false)
						want = int(bit) >= active || register != 0 && register != 1 &&
							(f.mask < 0 || f.zeroing)
					}
					before := state.clone()
					accepted := x86ScalarFPResultTransfer(ins, &state, nil, 0, arch)
					if accepted != want {
						t.Fatal("missing numerical/mask input", row, missing, accepted, want)
					}
					if want {
						index, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
						value := x86CallerVectorByteMask(int64(f.byteWidth))
						required := x86CallerVectorByteMask(int64(active))
						if f.legacy {
							value = before.vectorBytes(index) | required
						} else if f.scalar {
							value = required | before.vectorBytes(1)&^required
						}
						before.writeVector(index, f.byteWidth, value, f.legacy)
					}
					if !reflect.DeepEqual(state, before) {
						t.Fatal("MIN/MAX invented passthrough bytes or changed unrelated state", row, missing)
					}
				}
			})
		}
	}
}

func TestX86FloatingMinMaxCallerConsumesSameTypedInputs(t *testing.T) {
	for _, row := range x86FloatingMinMaxFormats("amd64") {
		if strings.Contains(row, "(AX)") {
			continue
		}
		ins := x86ScalarLaneInstruction(t, row)
		f, known, err := x86FloatMinMaxProperties(ins, "amd64")
		if !known || err != nil || !x86CallerVectorMoveKnown(ins) {
			t.Fatal("caller lacks the complete MIN/MAX registration", row, err)
		}
		for _, missing := range []int{-1, f.first, f.second, f.destination, 4} {
			state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": ^uint64(0)},
				masks: map[Reg]bool{"K1": true}}
			if missing >= 0 && missing < len(ins.Args) {
				state.vectors[x86CallerVectorRoot(ins.Args[missing].Reg)] &^= 1
			}
			if missing == 4 {
				state.masks["K1"] = false
			}
			before, masks := x86CloneCallerVectorState(state.vectors, state.masks)
			accepted := x86CallerVectorMoveStep(&ins, &state, nil)
			want := missing == -1 || missing == f.destination && !f.legacy &&
				(f.mask < 0 || f.zeroing) || missing == 4 && f.mask < 0
			if accepted != want || !reflect.DeepEqual(state.masks, masks) || !accepted && !reflect.DeepEqual(state.vectors, before) {
				t.Fatal("caller invented source, merge or mask bytes", row, missing, accepted, want)
			}
		}
	}
}
