package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86FloatingCompareResultEveryByteMaskAndAlias(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86FloatCompareGoForms(arch) {
			ins := x86ScalarLaneInstruction(t, row)
			form, known, err := x86FloatCompareProperties(ins, arch)
			if !known || err != nil {
				t.Fatal("independent original-Go comparison row lost its grammar", row, err)
			}
			width := form.byteWidth
			if strings.HasSuffix(string(ins.Op), "SS") || strings.HasSuffix(string(ins.Op), "SD") || form.scalar {
				width = form.bits / 8
			}
			required := x86CallerVectorByteMask(int64(width))
			state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
			state.pointerGP[0], state.gp[1], state.masks[1] = true, 0xff, true
			for index := 0; index < 32; index++ {
				pattern := uint64(0xaaaaaaaaaaaaaaaa)
				if index&1 != 0 {
					pattern = ^pattern
				}
				state.writeVector(index, 64, pattern|required, false)
			}
			before := state.clone()
			if accepted, owned := x86ResultFloatCompareStep(ins, &state, nil, arch, true); !owned || !accepted {
				t.Fatal("initialized complete comparison failed numerical continuation", arch, row)
			}
			expected := before.clone()
			if form.maskResult {
				index, _ := amd64ParseKReg(ins.Args[form.destination].Reg)
				expected.masks[index] = true
			} else {
				destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
				second, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
				bytes := ^uint64(0)
				if form.legacy {
					bytes = before.vectorBytes(destination) | required
				} else if form.scalar {
					bytes = ^uint64(0xffff) | required | before.vectorBytes(second)&(0xffff&^required)
				}
				expected.writeVector(destination, 64, bytes, false)
			}
			if !reflect.DeepEqual(state, expected) {
				t.Fatal("comparison changed FLAGS, DF, inputs or inactive aliases", arch, row)
			}
			for _, ordinal := range []int{form.first, form.second, form.mask} {
				if ordinal < 0 || ordinal == form.memory {
					continue
				}
				limit := width
				if ordinal == form.mask {
					limit = 1
				}
				for missing := 0; missing < limit; missing++ {
					current := before.clone()
					if ordinal == form.mask {
						index, _ := amd64ParseKReg(ins.Args[ordinal].Reg)
						current.masks[index] = false
					} else {
						index, _ := amd64VectorRegisterIndex(ins.Args[ordinal].Reg, form.byteWidth)
						current.writeVector(index, 64, current.vectorBytes(index)&^(uint64(1)<<uint(missing)), false)
					}
					initial := current.clone()
					if accepted, _ := x86ResultFloatCompareStep(ins, &current, nil, arch, true); accepted || !reflect.DeepEqual(current, initial) {
						t.Fatal("missing comparison byte/mask invented a result or partially changed state", arch, row, ordinal, missing)
					}
				}
			}
		}
	}
}

func TestX86FloatingCompareNativeContinuationRetainsSourceBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86FloatCompareGoForms(arch) {
			ins := x86ScalarLaneInstruction(t, row)
			form, _, err := x86FloatCompareProperties(ins, arch)
			if err != nil || form.memory < 0 {
				continue
			}
			state := x86ResultState{flags: x86ByteFlagsAll}
			state.pointerGP[0], state.gp[1], state.masks[1] = true, 0xff, true
			for index := 0; index < 32; index++ {
				state.writeVector(index, 64, ^uint64(0), false)
			}
			for _, change := range []string{"standalone", "pointer", "numeric base", "index", "raw", "address size"} {
				current, changed := state.clone(), ins
				changed.Args = append([]Operand(nil), ins.Args...)
				native := true
				switch change {
				case "standalone":
					native = false
				case "pointer", "numeric base":
					current.pointerGP[0] = false
					if change == "numeric base" {
						current.gp[0] = 0xff
					}
				case "index":
					changed.Args[form.memory].Mem.Index, changed.Args[form.memory].Mem.Scale = DX, 2
				case "raw":
					changed.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op, args: ins.Args}
				case "address size":
					changed.x86AddressBits = 16
				}
				before := current.clone()
				if accepted, _ := x86ResultFloatCompareStep(changed, &current, nil, arch, native); accepted || !reflect.DeepEqual(current, before) {
					t.Fatal("unproved comparison supplied native bytes or changed state", arch, row, change)
				}
			}
		}
	}
}

func TestX86FloatingCompareMaskDestinationDoesNotBorrowOldInput(t *testing.T) {
	for _, row := range []string{"VCMPPS $0,Z0,Z1,K1,K1", "VCMPSS $255,X0,X1,K1,K1"} {
		for _, mask := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/known-%t", row, mask), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				state := x86ResultState{}
				state.writeVector(0, 64, ^uint64(0), false)
				state.writeVector(1, 64, ^uint64(0), false)
				state.masks[1] = mask
				before := state.clone()
				accepted, _ := x86ResultFloatCompareStep(ins, &state, nil, "amd64", true)
				if accepted != mask || !reflect.DeepEqual(state, before) {
					t.Fatal("K destination initialized its own missing writemask input")
				}
			})
		}
	}
}
