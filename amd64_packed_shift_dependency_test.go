package plan9asm

import (
	"fmt"
	"testing"
)

// An independent bit-by-bit relation, not the production interval arithmetic.
// Every possible in-range dynamic count is enumerated; all other counts emit
// zero. Operand bytes are known only when every possible selected bit is known.
func x86ShiftIndependentBitInputs(bits, width, count int, left, byteShift, dynamic, perLane bool) [][2]uint64 {
	if byteShift {
		bits = 128
	}
	masks := make([][2]uint64, width)
	for output := 0; output < width*8; output++ {
		first, end := int(uint8(count)), int(uint8(count))+1
		if byteShift {
			first, end = first*8, first*8+1
		}
		if dynamic {
			first, end = 0, bits
		}
		for shift := first; shift < end; shift++ {
			input := output%bits + shift
			if left {
				input = output%bits - shift
			}
			if input >= 0 && input < bits {
				input += output / bits * bits
				masks[output/8][0] |= uint64(1) << uint(input/8)
			}
		}
		if dynamic {
			start, end := 0, 8
			if perLane {
				start, end = output/bits*(bits/8), (output/bits+1)*(bits/8)
			}
			for at := start; at < end; at++ {
				masks[output/8][1] |= uint64(1) << uint(at)
			}
		}
	}
	return masks
}

func TestX86PackedShiftResultEveryByteDependency(t *testing.T) {
	for _, bank := range []struct {
		name  string
		width int
	}{{"X", 16}, {"Y", 32}, {"Z", 64}} {
		for _, bits := range []int{16, 32, 64, 128} {
			for _, left := range []bool{false, true} {
				for mode := 0; mode < 3; mode++ {
					byteShift, dynamic, perLane := bits == 128, mode != 0, mode == 2
					if byteShift && dynamic {
						continue
					}
					name := "VPSRL"
					if left {
						name = "VPSLL"
					}
					if perLane {
						name += "V"
					}
					name += map[int]string{16: "W", 32: "D", 64: "Q", 128: "DQ"}[bits]
					last := 255
					if dynamic {
						last = 0
					}
					for immediate := 0; immediate <= last; immediate++ {
						count := fmt.Sprintf("$%d", immediate)
						if dynamic {
							count = "X0"
							if perLane {
								count = bank.name + "0"
							}
						}
						row := fmt.Sprintf("%s %s,%s1,%s2", name, count, bank.name, bank.name)
						ins := x86ScalarLaneInstruction(t, row)
						form, known, err := x86PackedShiftProperties(ins.Op, ins, "amd64")
						if !known || err != nil {
							t.Fatal(row, err)
						}
						want := x86ShiftIndependentBitInputs(bits, bank.width, immediate, left, byteShift, dynamic, perLane)
						for output, masks := range want {
							data, counts := x86PackedShiftByteInputs(form, output)
							if data != masks[0] || counts != masks[1] {
								t.Fatalf("%s byte=%d data=%x/%x counts=%x/%x", row, output, data, masks[0], counts, masks[1])
							}
						}
						for missing := -1; missing < bank.width; missing++ {
							for operand := 0; operand < 2; operand++ {
								inputs := [2]uint64{^uint64(0), ^uint64(0)}
								if missing >= 0 {
									inputs[operand] &^= uint64(1) << uint(missing)
								}
								var expected uint64
								for output, masks := range want {
									if inputs[0]&masks[0] == masks[0] && inputs[1]&masks[1] == masks[1] {
										expected |= uint64(1) << uint(output)
									}
								}
								if got := x86PackedShiftDefinedBytes(form, inputs[0], inputs[1], 0); got != expected {
									t.Fatal(row, missing, operand, got, expected)
								}
								state := x86ResultState{flags: x86ByteFlagsAll}
								state.writeVector(0, 64, inputs[1], false)
								state.writeVector(1, 64, inputs[0], false)
								physical := expected | ^x86CallerVectorByteMask(int64(bank.width))
								if !x86ResultTransfer(ins, &state, nil, 0, "amd64") || state.vectorBytes(2) != physical || state.flags != x86ByteFlagsAll {
									t.Fatal("complete result byte state differs", row, missing, operand)
								}
							}
						}
					}
				}
			}
		}
	}
}
